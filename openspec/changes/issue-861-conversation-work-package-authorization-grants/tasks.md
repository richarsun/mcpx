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
- [x] 首个冻结候选 `e37eec9` 经独立 Reviewer 返回 NEEDS_FIX 后，已针对 5 个 P1 增加负向回归并完成第一轮修复；候选推进为 `42e952e` / tree `6597b90c...`，并重新通过当轮门禁。
- [x] 同一独立 Reviewer 对 `42e952e` 第二轮复审仍返回 NEEDS_FIX：`transport::address` / scp-like remote 可造成 repository 解释漂移；`GIT_EXEC_PATH` 可让可信顶层 Git 启动未受控 child program；`git branch` read 仍可产生空 `Action.Targets`。Reviewer 已确认第一轮 commit filter、隐藏 submodule 以及顶层 PATH wrapper 等修复本身闭合。
- [x] 按本 change 的四条安全不变量完成 Git grant surface audit：remote identity、execution surface/environment、target completeness、classification/execution equivalence；逐项核对全部 grant-eligible Git action 的 repository/target/write-domain/top-level executable/argv/environment/child-helper 执行面。
- [x] 结构性修复第二轮 3 个 P1：在本地路径归一化前拒绝 helper/scp 歧义 remote；分类探测与 grant-backed 实际进程共享冻结 environment，在任何 Git 探测前拒绝非空 `GIT_EXEC_PATH`；`git branch --show-current` 绑定当前 branch，plain `git branch` grant-ineligible。另将 grant-backed Git PATH 收敛到受信任 Git/系统目录，并只允许可绑定到同一受信任 Git for Windows 安装的 system `credential.helper=manager`。
- [x] 增加 fetch/push remote-helper side-effect marker、Runtime `GIT_EXEC_PATH` child marker、hostile PATH 清洗、非受信 credential helper、branch narrow/detached/plain-read 以及 Git action repository/target/environment invariant 回归。
- [x] 重新运行定向/包级/Runtime/整仓与静态门禁：Windows `internal/authorization` PASS 102.864s；Windows `TestConversationAuthorization*` PASS 66.211s；Linux authorization PASS 4.983s；Linux `go test ./... -count=1` PASS（authorization 18.578s、server 172.194s）；affected race PASS（authorization 6.732s、server 267.279s）；gofmt、diff-check、普通 build、vet、CGO=0 build 均 exit 0；OpenSpec strict 2 passed / 0 failed。历史 unrelated full-repo race 问题未声明为 PASS。
- [x] 以 `42e952e` 为唯一 parent 创建普通 follow-up `83921e3138bc2a05f9e956c038104e38980f3aeb` / tree `2f376d0107dd8798a12bfb40a29fd6d9044dcc91`，正常 fast-forward push 原 branch；保持 Draft PR `richarsun/mcpx#3` 与 #861 open，未 amend/force-push/merge/release/deploy/tag。
- [x] 同一独立 Reviewer 对 `83921e3` 第三轮复审返回 NEEDS_FIX：POSIX `C:/repo` 盘符解释、URL-specific credential helper、SSH config execution surface、branch/tag/object revision ambiguity 共 4 个 P1；旧 PASS/NEEDS_FIX 历史不改写。
- [x] M1 将包含 PR #2 的当前 deployed confirmation-recovery head `3ab65746753924ce5b31c6a9996c94c1365bba6b` 机械整合进 PR #3 lineage，形成本地 merge commit `f190d591c1970acaa0c80c969d055c366a073bda`；保留双方历史，未 push、未合 main、未部署。
- [x] 正式记录 Stage V1 收窄合同：Windows 单账号/单 Session/Workspace/repository + GitHub HTTPS；SSH、超出窄模型的 credential helper 与歧义 revision 均 grant-ineligible / fallback to existing confirmation。
- [x] P1-1：Windows drive-path 例外已平台化；POSIX `C:/repo` 在 local normalization 前按 scp-like remote fail-closed，Linux lookalike bare repo + fetch/push + SSH marker 回归通过；Windows 合法 drive-absolute local remote 正路继续由既有 local fetch 回归覆盖。
- [x] P1-2：credential-helper 已收窄为无 helper 或 Windows 同一受信任 Git 安装的唯一 system `credential.helper=manager`；URL-specific、empty reset、multiple、shell、absolute/custom、来源不可证明及 `GIT_CONFIG_*` 注入均 fail-closed；canonical GitHub HTTPS 正向分类在 Windows/Linux 均通过。
- [x] P1-3：Stage V1 canonical scp 与 `ssh://` remote 均 grant-ineligible / fallback ordinary confirmation；恶意 ssh_config/marker 未经 grant classification 执行。
- [x] P1-4：git_read target 已收窄为 default HEAD、显式 `refs/heads/...` 与 verified full OID；bare symbolic revision fallback，full OID 在同名 40-hex ref 前按 object identity 校验，actual argv 使用 canonical ref/OID；branch/tag/OID ambiguity 与 narrow alias 回归通过。
- [x] 第三轮验证完成：Windows P1 focused PASS 30.054s、target ambiguity PASS 12.720s、最新 exact worktree `internal/authorization` PASS 114.205s、`TestConversationAuthorization*` PASS 51.934s、HTTPS 正向 PASS 4.510s；Linux authorization 当前树 PASS 10.130s；affected race PASS（authorization 10.618s、server 351.021s）；diff-check、普通 build、vet、CGO=0 build exit 0；OpenSpec strict PASS。Linux `go test ./... -count=1` 唯一 FAIL 为 `TestReviewCancelStopsGrandchildEffects/parent-exits`，current candidate 重复 5/5 FAIL，deployed PR #4 exact `3ab6574` 重复 3/3 同样 FAIL，确认是既有 PR #4 baseline，未声明 full-test PASS。
- [ ] 冻结最终 integrated exact commit/tree，确认 worktree/staged clean 与 `83921e3..new-head` delta 后正常 fast-forward push PR #3 branch，并回写 Draft PR/#861/#823；必要时再同步中央 #824 OpenSpec。
- [ ] 由同一独立 Reviewer 对最终 exact candidate、`83921e3..new-head`、4 P1 原失败机制、四条安全不变量和 M1 integration 给出新 PASS/NEEDS_FIX；PASS 前保持 Draft/review-required。
- [x] 不部署、不发布；只有后续新的明确授权才进入发行阶段。
