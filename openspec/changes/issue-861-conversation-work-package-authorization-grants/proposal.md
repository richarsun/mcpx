# Proposal: Conversation Work-Package Authorization Grants

## Status

- Intent source: `EXPLICIT` — `richarsun/personal-ai-ops#861`
- Change level: L3（公共授权协议与安全边界）
- Candidate state: M1 integrated; third-round Stage V1 fixes verified, unrelated deployed PR #4 baseline full-test failure recorded; freeze/delivery/independent review pending
- Deployment state: not deployed, not released

## Why

MCPX 现有 `user_confirmed=true` 只绑定单个 exact command digest。真人已经对边界明确的 Git 工作包做出一次授权后，Runtime 仍会对 fetch、switch、diff、add、commit、push、PR 和安全 cleanup 等后续普通动作逐条要求确认，既增加交互成本，也无法表达可审计、可撤销、可恢复的工作包授权边界。

## What Changes

1. 新增持久化的 conversation/work-package authorization grant，绑定 principal、authorization context、Remote Session、Workspace、工作包、目标、动作类别、仓库、target、写域、风险上限、状态和有效期。
2. 首次明确确认后创建或恢复稳定 grant；后续同一上下文和同一授权范围内的普通 Git/GitHub Confirm 动作可复用 grant，不再逐命令确认。
3. 每次执行仍先运行现有策略；Deny 永远优先。Workspace、仓库、purpose、target、写域或风险边界变化时不匹配并重新确认。
4. 提供 list、revoke、narrow 生命周期操作；narrow 可缩小 scope 和/或单独缩短有效期，立即影响后续动作。
5. 将 grant 来源、匹配依据、创建/复用/不匹配决定写入执行响应与审计；授权边界参与幂等指纹，并支持断连后的稳定恢复。
6. 保持 move_out 的 prepare → confirm → submit 强协议独立；高风险及无法可靠分类的命令不得因 grant 自动放行。

## Stage V1 Support Matrix

第三轮独立 Review 的 4 个 P1 将首个可验收面进一步收窄为 **Windows 单账号 / 单 Remote Session / 单 Workspace / 单 repository / GitHub HTTPS remote / 有界 ordinary Git actions**。当前正向目标是 `controller-win-01` 上的明确 Chat account 与明确 Workspace；不把这一 intermediate milestone 外推为全部平台或全部 Git 语义。

Stage V1 只对能够证明 classification/execution equivalence 的普通 Git 动作复用 grant。以下形态不禁止用户使用 Git，而是 **grant-ineligible / fallback to existing confirmation**：

- 所有 SSH / scp-like Git remote，包括 canonical `git@github.com:owner/repo` 与 `ssh://...`；
- URL-specific、reset、multiple、shell、absolute/custom 或来源不可证明的 credential helper；
- 会注入/改变 Git config 来源的未建模 `GIT_CONFIG_*` 环境；
- 裸 symbolic revision、range 或其他不能唯一证明解释的 revision grammar；
- `go test` / `go vet` / `go build` 等代码执行型验证命令及现有高风险/未知动作。

Revision 正向只包含默认 HEAD、显式 `refs/heads/<name>` 和已验证 full object ID；分类批准后实际 Git argv 必须使用该 canonical ref/OID。Windows drive-absolute local path 例外只在 Windows 生效，POSIX `C:/repo` 不得按 Windows 本地路径解释。

## Non-Goals

- 不实现或修复 #859 的 stdin 行为。
- 不修复 #860 的 move_out 实际移动问题。
- 不把 grant 做成账号级、设备级或永久白名单。
- 不关闭、降低或绕过现有命令安全策略。
- 不让 production、credential、payment、永久删除、force push、系统网络/服务控制等高风险动作自动继承普通 grant。
- 首版不让 `go test`、`go vet`、`go build` 等可能执行仓库代码的验证命令自动复用 grant；它们继续走现有逐命令确认。
- 本 change 不包含部署、发布、Tunnel、账号权限或设备配置修改。
- Stage V1 不承诺 SSH grant reuse、URL-specific/multiple/shell/custom credential helper grant、复杂 revision grammar、双账号、全平台或全部中断场景。

## Acceptance

- 同一有界 Git 工作包首次确认后，连续普通 read/mutation 命令可以复用同一 grant。
- 新 conversation、Remote Session、Workspace、仓库、target、purpose 或写域扩大时重新受限。
- Deny、高风险越界和 move_out 独立强协议不被绕过。
- revoke 或 narrow 后，下一动作立即遵守新边界。
- 审计可解释 grant ID/digest、来源、是否创建/复用、匹配依据和不匹配原因。
- SQLite 恢复和幂等重试不产生重复 grant、重复效果或跨授权回放。
- 具备正反场景、生命周期、恢复及 schema 隔离测试。

## Risks

- 命令分类错误可能导致授权过宽，因此分类器采用严格 allowlist 和 fail-closed；未知参数、外部执行面或无法证明的路径回退逐命令确认。
- grant 是协议状态，持久化、幂等和审计必须原子一致；恢复测试和唯一 active-scope 约束用于阻止重复或分叉状态。
- 该候选涉及授权安全边界，合并前需要独立只读 Review；作者自测不能替代该质量门。
