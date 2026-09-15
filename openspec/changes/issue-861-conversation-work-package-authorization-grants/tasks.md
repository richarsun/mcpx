# Tasks: Conversation Work-Package Authorization Grants

## Specification and Model

- [x] 将 #861 明确目标、边界和正反验收映射为 L3 OpenSpec。
- [x] 定义规范化 Request、Scope、Grant、stable digest、状态和有效期。
- [x] 增加 SQLite migration、唯一 active-scope 约束和恢复存储。

## Runtime Protocol

- [x] 为 execute 增加 context、grant ID 和首次 authorization request 输入。
- [x] 实现首条 exact confirmation 后创建/恢复 grant。
- [x] 在每次动作上保持策略优先，Deny 不可覆盖，Confirm 仅在匹配时跳过。
- [x] 为 session 增加 list、revoke、narrow，并保证 scope/expiry 只能收窄。
- [x] 保持新 conversation 默认不继承旧 grant，move_out schema 与强协议不变。

## Classification, Audit, and Recovery

- [x] 实现保守 Git/GitHub allowlist，并对高风险、未知和代码执行型验证命令 fail-closed。
- [x] 绑定实际 Git top-level/common-dir、fetch/push URL、targets 和 staged/write paths。
- [x] 在响应和审计中记录 grant 来源、匹配依据、创建/复用/不匹配和 bypass 状态。
- [x] 将 authorization 边界与 purpose 纳入幂等 fingerprint。
- [x] 支持 grant narrow/revoke/expire 后的已完成请求精确重放，变更边界返回 conflict。

## Verification and Delivery

- [x] 授权模型、持久化、分类器正反测试。
- [x] Runtime Git 工作包、边界、deny、lifecycle、recovery、audit、move_out 隔离聚焦 E2E。
- [x] 首个冻结候选 `e37eec9` 经独立 Reviewer 返回 NEEDS_FIX 后，已针对 5 个 P1 增加负向回归并完成修复；重新运行完整 gofmt、diff-check、普通 build、CGO=0 build、go vet、整仓 `go test ./... -count=1` 与 affected race，全部门禁通过，OpenSpec CURRENT/change 全量 strict validation 为 2/2 PASS。历史 full-repo race 的唯一 OAuth 间歇失败已在 exact base `3f81d08` 复现，#861 未修改 OAuth。
- [ ] 冻结 Reviewer 修复后的完整 diff、new exact commit 和 tree，并完成作者自检。
- [ ] 由同一独立只读 Reviewer 复核 `e37eec9..new-head` 修复 delta 及新冻结候选；未取得 PASS 前保持 review-required。
- [ ] 正常 push 新修复 commit 到既有 feature branch / Draft PR `richarsun/mcpx#3`，并向 #861 回写新 commit/tree、五项修复、验证和剩余风险。
- [x] 不部署、不发布；只有后续新的明确授权才进入发行阶段。
