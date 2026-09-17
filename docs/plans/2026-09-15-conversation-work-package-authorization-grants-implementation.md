# #861 对话／工作包级授权 Grant 实施计划

- 规格：`docs/specs/2026-09-15-conversation-work-package-authorization-grants.md`
- 分支：`feat/issue-861-conversation-authorization-grants`
- 停点：实现、验证、commit、push、Draft PR、#861 回写；不合并、不发布、不部署

## 1. 领域与持久化

- [x] 新增 `internal/authorization`：scope 规范化、digest、子集判断、命令描述匹配。
- [x] 新增 SQLite `authorization_grants` migration，状态含 active/revoked/superseded/expired。
- [x] 实现 create-or-reuse、get/list、revoke、narrow；同一等价 scope 不重复创建 active grant。
- [x] 单测状态恢复、到期、撤销和只能缩小。

## 2. 命令安全分类

- [x] 保守支持单条普通 Git read/fetch/switch/add/commit/push、GitHub PR create/view/merge 与安全 branch cleanup；grant-backed 命令固定并直接执行分类时解析的可信 executable/argv，复合命令与代码执行型验证命令继续逐条确认。
- [x] 解析 `git -C`、repo/remote identity、branch／PR target 和 `git add`／staged write paths。
- [x] force/delete/reset/clean、credential/payment/production/system-network 与未知命令均 grant-ineligible。
- [x] 单测正反分类和范围匹配。
- [x] 第二轮收敛不变量：remote identity 必须与 Git transport 唯一解释一致；grant 执行面包含影响 Git child program 的受控 environment；所有 grant-eligible `git_read` target 必须完整；classification 与 actual execution 的 executable/argv/environment/repository 语义必须等价。
- [x] 对全部 grant-eligible Git action 完成 surface audit，逐项检查 repository、target、write path、top-level executable、argv、environment 与 child/helper 执行面；额外将 Git child PATH 收敛到受信任安装/系统目录，并对白名单 HTTPS credential helper 验证配置来源与 PE binary 身份。

## 3. Runtime 协议

- [x] `execute(run)` schema 增加 `authorization_context_id`、`authorization_grant_id`、`authorization_request`。
- [x] 首次 confirmation digest 纳入规范化授权请求 digest；确认后创建／复用 grant。
- [x] Deny 先行；Allow/Confirm 均可记录 grant 匹配，只有 Confirm 且匹配时跳过 pending。
- [x] clean idempotency 将 authorization 元数据与业务效果指纹分离，同时允许有效 grant 请求进入幂等路径。
- [x] 执行响应与 command audit detail 返回／记录 created、reused 或 mismatch 证据。

## 4. 生命周期操作

- [x] `session` 增加 `authorization_list`、`authorization_revoke`、`authorization_narrow`。
- [x] 操作限定当前 principal、Remote Session、Workspace 与 context；revoke/narrow 写审计。
- [x] session open 不自动返回旧 context grant。

## 5. 验证矩阵

- [x] 同一有界 Git 工作包一次授权后连续多个 Confirm 命令不再等待。
- [x] read-only 和普通 Git mutation 均正确匹配并审计。
- [x] 新 Workspace／新仓库／扩大写域／目标或 purpose 变化重新确认。
- [x] deny 优先；撤销后下一动作受限；新 context 不继承。
- [x] 高风险命令不复用；`move_out` 强制 confirmation UUID 不变。
- [x] Runtime 重启／重试后 grant 一致且无重复 active grant。
- [x] 首个冻结候选 `e37eec9` 的独立 Reviewer 结论为 NEEDS_FIX，指出 5 个 P1：commit 未暂存文件 filter、remote helper / `remote.<name>.vcs`、隐藏子模块递归 fetch、Workspace 外 PATH wrapper、Git read target 丢失。第一轮修复形成 `42e952e` 并通过当轮完整验证；此前 full-repo race 的 `internal/oauth/TestLoadOrCreateTokenSecretConcurrentFirstUse` 间歇失败已在 exact base `3f81d08` 上复现，#861 未修改 OAuth。
- [x] 同一 Reviewer 对 `42e952e` 第二轮结论仍为 NEEDS_FIX，剩余 3 个 P1：`transport::address`/非 canonical scp-like remote 可让分类 repository 与 Git transport 解释不同；非空 `GIT_EXEC_PATH` 可让可信 Git 启动未受控子程序；`git branch`/`--show-current` 仍可能以空 target 进入 grant matcher。
- [x] 新增结构性回归而非只补 exact case：fetch/push helper marker、真实可信 Git + hostile `GIT_EXEC_PATH` Runtime marker、hostile PATH 清洗、非受信 credential helper、branch target/narrow/detached/plain branch，以及 grant-eligible Git action repository/target/environment invariant。
- [x] 收敛修复后的核心动态门禁已通过：Windows `internal/authorization` 102.864s；Windows `TestConversationAuthorization*` 66.211s；Linux authorization 4.983s；Linux `go test ./... -count=1` exit 0（authorization 18.578s、server 172.194s）；affected race PASS（authorization 6.732s、server 267.279s）。
- [x] 最终静态/规格门禁已通过：gofmt、`git diff --check`、普通 Linux build、`go vet ./...`、CGO=0 build 均 exit 0；OpenSpec strict 为 2 passed / 0 failed。

## 6. 交付与质量门

- [x] 作者自检完整 diff、规格映射、风险和未覆盖项。
- [ ] 本轮收敛修复完成并重跑门禁后，以 `42e952e` 为唯一 parent 创建普通 follow-up commit，记录 exact commit/tree；不得 amend 已 Review 候选。
- [x] 已建 Draft PR `richarsun/mcpx#3` 并关联 #861；当前远端冻结候选仍是 `42e952e`，第二轮 Review 为 NEEDS_FIX。
- [ ] 公共授权协议／安全边界变化必须进入同一独立 Reviewer；第三轮重点审 `42e952e..new-head`、四条安全不变量及新增 side-effect/invariant 回归，作者不得自签，PASS 前保持 Draft/Review required。
- [ ] 正常 fast-forward push 原 feature branch，向 #861 回写 new commit/tree、第二轮 3 个 P1 的结构性修复、验证和剩余风险，并明确“未部署”；不 merge/release/deploy/tag。
