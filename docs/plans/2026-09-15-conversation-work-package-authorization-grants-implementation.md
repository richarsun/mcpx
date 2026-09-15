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
- [x] 首个冻结候选 `e37eec9` 的独立 Reviewer 结论为 NEEDS_FIX，指出 5 个 P1：commit 未暂存文件 filter、remote helper / `remote.<name>.vcs`、隐藏子模块递归 fetch、Workspace 外 PATH wrapper、Git read target 丢失。修复后新增逐项负向回归并通过；Windows `internal/authorization` 全测与 `TestConversationAuthorization*` Runtime E2E 通过；Linux gofmt、diff-check、普通 build、vet、CGO=0 build、authorization 全测、整仓 `go test ./... -count=1` 及 `go test -race ./internal/authorization ./internal/server -count=1` 均重新通过；OpenSpec CURRENT/change 全量 strict validation 为 2/2 PASS。此前 full-repo race 的 `internal/oauth/TestLoadOrCreateTokenSecretConcurrentFirstUse` 间歇失败已在 exact base `3f81d08` 上复现，#861 未修改 OAuth，未越界修复。

## 6. 交付与质量门

- [x] 作者自检完整 diff、规格映射、风险和未覆盖项。
- [ ] commit/push 独立 feature branch，记录 exact commit/tree。
- [x] 已建 Draft PR `richarsun/mcpx#3` 并关联 #861；首个冻结候选 `e37eec9` 已提交审查。
- [ ] 公共授权协议／安全边界变化必须进入独立 Reviewer；首审 `e37eec9` 为 NEEDS_FIX，5 个 P1 修复完成且门禁重跑通过，仍须对新的冻结候选复审 PASS，作者不得自签，放行前保持 Draft/Review required。
- [ ] #861 需在新修复 commit/tree push 后再次回写验证、Reviewer 修复、PR 和剩余风险，并明确“未部署”。
