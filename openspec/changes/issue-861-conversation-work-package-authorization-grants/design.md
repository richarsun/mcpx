# Design: Conversation Work-Package Authorization Grants

## 1. Data Model

`authorization_grants` 持久化以下不可缺失的绑定：

- `principal_id`
- `authorization_context_id`
- `remote_session_id`
- `workspace_name`
- `work_package_id` 与 `goal`
- 规范化 scope：`purpose_patterns`、`action_classes`、精确 repository identities、target patterns、write paths、`risk_ceiling`
- `scope_digest`、`grant_digest`
- `status`：active / revoked / superseded / expired
- source request/command digests、创建/更新/过期/撤销时间和 supersedes 关系

同一 principal/context/session/workspace/work-package/goal/scope 只允许一个 active grant。稳定 digest 使用规范化字段生成，不包含 transport request ID。

## 2. Activation Protocol

`execute(action=run)` 增加三个可选字段：

- `authorization_context_id`
- `authorization_grant_id`
- `authorization_request`

客户端首次提出 `authorization_request` 时，Runtime 对当前命令完成策略分析和 scope 匹配，但仍要求原 exact-command confirmation。确认重试时，Runtime 校验同一个服务端 pending digest，再原子创建或恢复 grant。后续命令只携带 context + grant ID。

新对话必须使用新的 context ID；session open 只有在调用方显式提供 context 时才返回对应 grant，不自动把旧 conversation grant 注入新对话。

## 3. Policy and Matching Order

每个动作按以下顺序处理：

1. 运行现有安全策略。
2. Deny 立即终止，grant 无权覆盖。
3. 保守分类命令，得到风险、动作类别、实际 repository identity、targets 和 write paths。
4. 按 principal/context/Remote Session/Workspace 读取绑定 grant。
5. 检查 active/expiry、purpose、risk、classes、repositories、targets、write paths。
6. 只有策略为 Confirm 且匹配时，grant 才跳过逐命令 confirmation；Allow 动作不需要 grant 放权，但在提供 grant 时记录匹配结果。

Repository identity 逐项精确匹配；purpose/target 使用受限 glob；write path 使用 slash-aware 的保守覆盖判定。无法证明为子集或在 Workspace 内的路径一律不匹配。

## 4. Conservative Command Classification

首版 allowlist 只覆盖可机器证明的普通 Git/GitHub 形态：

- Git read：status、受限 diff/log/show/rev-parse
- Git remote read：显式 remote + ref 的 fetch
- Git local write：受限 switch、显式 add、非交互 commit
- Git remote write：非 force、非删除、非 upstream 变更、非 hooks 绕过的 push
- GitHub PR：受限 create/view/merge，要求显式 repo/PR selector 与非交互参数
- 安全 cleanup：`git branch -d`

以下情况 grant-ineligible 并回到现有策略：未知/compound command、external diff/textconv、外部输出、hooks/submodule/filter 执行面、force/delete/reset/clean、credential/secret/auth、production/payment/system-network/service、永久删除，以及 `go test/vet/build` 等可能执行仓库代码的验证命令。

### 4.1 Grant reuse 安全不变量

第二轮独立 Review 证明，仅对已知 argv 形态逐点封堵不足以证明授权复用安全。首版 Git grant reuse 必须同时满足以下四条不变量；任一条无法证明时动作必须 grant-ineligible，并回到原逐命令策略：

1. **Remote identity invariant**：分类器规范化出的 repository identity 必须与 Git 实际执行时对 remote 字符串的 transport 解释唯一且一致。`<transport>::<address>`、除明确允许的 canonical `git@github.com:owner/repo` 外的 scp-like `host:path` / `user@host:path` 等歧义连接形式不得先按 Workspace 本地路径归一化；合法 Windows 绝对盘符路径单独识别。
2. **Execution-surface invariant**：grant 绑定的不只是顶层 executable 与 argv，还包括会改变 Git 子程序解析的关键执行环境。非空 `GIT_EXEC_PATH` 等可替换 Git child program 的环境不得参与 grant reuse；分类探测与真正 grant-backed 执行必须使用同一冻结环境语义。Grant-backed Git 的 PATH 必须由已验证 Git 安装派生，不继承任意宿主 PATH shadow；HTTPS credential helper 只能在来源与 helper binary 都能绑定到同一受信任 Git 安装时进入 grant reuse，否则 fail-closed。
3. **Target-completeness invariant**：所有 grant-eligible `git_read` 必须具有非空、规范化且可匹配的 `Action.Targets`。无法确定 branch/object target 时必须 fail-closed；`git branch --show-current` 绑定当前 attached branch，plain `git branch` 首版不进入 grant allowlist。
4. **Classification/execution equivalence**：分类阶段批准的 executable、argv、repository/target 解释和受控环境必须原样约束实际进程；不得出现分类器看到本地 repository 或可信 Git，而执行阶段因 transport/helper/environment 漂移到另一执行面。

实现与测试必须对全部 grant-eligible Git action 做 surface audit：需要 repository scope 的动作不得产生空 repository；需要 target scope 的 `git_read` 不得产生空 target；remote/helper 与 child-program 语义不得依赖分类阶段未冻结的环境。

## 5. Lifecycle

- `authorization_list`：按当前 identity/context 列出 active 或包含 inactive 历史。
- `authorization_revoke`：原子标记 revoked；重复调用返回同一终态。
- `authorization_narrow`：旧 grant 原子 supersede，新 grant 使用新 ID/digest；只允许 scope 真子集和/或更早 expiry，不允许任何维度扩张或延长。
- expiry：读取或写入时惰性转换为 expired。

所有生命周期调用都要求当前 principal、Remote Session、Workspace 和 context 与 grant 绑定一致。

## 6. Audit and Idempotency

执行响应与 command audit detail 记录：

- decision（created / reused / matched policy allow / mismatch / absent）
- grant ID/digest、source request/command digest
- 当前 action 分类
- matched、match basis 或具体 mismatch reasons
- grant 是否真正用于 confirmation bypass

授权 context、grant、request 以及授权调用的 purpose 参与幂等 fingerprint；transport confirmation metadata 不参与。已完成的 durable idempotency record 在当前 grant 被 narrow/revoke/expire 后仍可精确重放；改变 purpose、context、grant、request 或业务参数则返回 conflict。

## 7. Recovery and Compatibility

SQLite migration 创建 grant 表与唯一 active-scope/index 约束。Create/retry、narrow retry 和 revoke retry 均为幂等。旧客户端不提供任何 authorization 字段时继续使用原策略和逐命令确认，协议为向后兼容的 opt-in。

## 8. Independent Strong Protocols

`move_out` schema 不增加 authorization 字段，submit 仍必须使用 prepare 返回的服务端 confirmation UUID。普通 grant 永远不能替代或消费该强确认协议。
