# MCPX：对话／工作包级授权 Grant 规格

- 记录日期：2026-09-15
- 关联 Issue：`richarsun/personal-ai-ops#861`
- 目标源码：`richarsun/mcpx`
- 基线：`main@3f81d08df744cf84d0a1fba61cd43b70e04c74b2`
- 等级：L3（公共执行协议、持久授权状态与安全边界变化）
- 状态：实施候选；未经独立 Review、合并、发布或部署

## 目标

让用户对当前对话中的一个边界明确工作包只做一次语义授权。授权后，同一 `authorization_context_id`、Remote Session、Workspace、principal、工作包和范围内的普通 `execute(action=run)` 命令可复用持久 grant，不再逐条命中 exact-command confirmation；底层命令策略、deny、高风险门禁和独立强确认协议保持有效。

## 非目标

- 不做账号级、设备级或永久白名单。
- 不修改 #859 stdin、#860 move_out 实际移动问题。
- 不改变生产配置、Tunnel、账号权限或设备配置。
- 不让 grant 覆盖 `move_out`、凭据、付款、生产发布、永久删除、force push、系统网络或无法安全分类的命令。
- 不把源码候选、PR 或测试通过表述为已部署生效。

## 协议

### Requirement: Grant 必须是显式、持久、可审计的对话级授权

Runtime MUST 使用客户端显式携带的 `authorization_context_id` 区分宿主对话；MUST NOT 把可重连的 Remote Session 或临时 `Mcp-Session-Id` 当作对话身份。Grant MUST 绑定 principal、`authorization_context_id`、Remote Session、Workspace、`work_package_id`、目标、动作类别、仓库、对象／分支／PR 目标、文件写域、ordinary 风险上限、状态和有效期，并提供服务端生成的稳定 `grant_id`、`scope_digest` 与 `grant_digest`。

#### Scenario: 同一对话恢复后继续
- **WHEN** Runtime 断连或重启，但调用方继续携带同一 `authorization_context_id`、`grant_id` 与仍有效的工作包边界
- **THEN** Runtime 从持久状态恢复 grant，重新按当前策略和当前动作匹配后复用
- **AND** 不因为重试或断连创建重复 active grant

#### Scenario: 新对话默认不继承
- **WHEN** 新对话未携带旧 `authorization_context_id`，或使用新的 context ID
- **THEN** 旧 grant 不匹配
- **AND** Runtime 不在 session bootstrap 中自动暴露或选择旧对话 grant

### Requirement: 首次语义确认必须冻结完整工作包边界

调用方 MAY 在首次需要确认的 `execute(action=run)` 中携带 `authorization_request`。Runtime MUST 在返回确认前规范化并冻结该请求；exact command digest MUST 同时覆盖授权请求 digest，防止确认重试时扩大范围。用户以相同业务参数和 `user_confirmed=true` 重试后，Runtime MUST 原子创建或复用同一 active grant，再执行首个动作。

#### Scenario: 一次确认后连续 Git E2E
- **WHEN** 用户确认的工作包明确包含普通 Git 读取、本地变更、远端 fetch/push、PR 创建／读取／合并和安全分支清理，以及相应仓库、分支／PR 与写域
- **THEN** 首个命令创建 grant
- **AND** 后续仍在范围内的命令携带同一 context/grant 即可执行，不再逐命令询问

#### Scenario: 授权请求在确认前变化
- **WHEN** command、purpose、scope 或 `authorization_request` 的任一冻结边界发生变化
- **THEN** 原 pending confirmation 不得被消费
- **AND** Runtime 生成新的确认摘要

### Requirement: 每次复用必须重新执行策略与范围判定

Runtime MUST 先执行现有命令策略；Deny MUST 永远优先。只有策略结果为 Confirm 或 Allow、命令可被保守分类、grant active 且未过期，并且 principal、context、Remote Session、Workspace、工作包、动作类别、全部仓库、目标和写域均匹配时，grant 才可复用。普通 Allow/read-only 动作即使不需要 grant 放权，也 MUST 在提供 grant 时记录是否匹配。

#### Scenario: 同工作包内读取与普通 mutation
- **WHEN** `git status/diff/log/show`、受限 `git fetch/switch/add/commit/push`、受限 `gh pr create/view/merge` 或安全 `git branch -d` 仍在授权范围内
- **THEN** 当前策略继续生效
- **AND** 匹配的 grant 可复用，审计记录 `created` 或 `reused`

#### Scenario: 新 Workspace、仓库或写域
- **WHEN** 动作切换 Remote Session／Workspace，访问未列仓库，或 `git add`／commit 的文件超出 `write_paths`
- **THEN** grant 不匹配
- **AND** Confirm 类命令回到现有逐动作确认，Deny 类命令仍直接拒绝

#### Scenario: purpose 或目标实质变化
- **WHEN** 当前 purpose 不再属于 grant 目标，或分支、远端、PR、base/head 等目标超出 scope
- **THEN** grant 不匹配并说明具体边界差异

### Requirement: 高风险与独立强协议不得被 grant 静默绕过

Runtime MUST 将 force push、ref 删除、永久文件删除、凭据／secret／auth 变更、付款、生产部署／发布、系统网络／服务控制，以及无法安全分类的命令标为 grant-ineligible。首版中 `go test/vet/build` 等可能执行仓库代码的验证命令同样 grant-ineligible，继续走现有逐命令确认。Grant MUST NOT 接入 `move_out`；`move_out(action=submit)` MUST 继续要求 `prepare` 返回的服务端 `confirmation_uuid`。

#### Scenario: 高风险越界
- **WHEN** 调用携带有效 grant 但命令包含 force push、delete ref、`git clean/reset --hard`、凭据、付款、生产或系统网络动作
- **THEN** grant 不得放行
- **AND** 现有 Deny／Confirm 策略继续决定结果

#### Scenario: move_out 不受影响
- **WHEN** 调用方拥有 active grant 但未提供有效 `confirmation_uuid`
- **THEN** `move_out(action=submit)` 仍返回 `confirmation_required`

### Requirement: 用户必须能立即撤销或缩小授权

`session` MUST 提供仅针对当前 principal、Remote Session 与 `authorization_context_id` 的 grant list、revoke 和 narrow 动作。Revoke MUST 使下一次匹配立即失败。Narrow MUST 只允许动作、仓库、目标、写域、风险或有效期的真子集；MUST 创建新的稳定 grant 身份并把旧 grant 标记 superseded，不能原地扩大。

#### Scenario: 撤销后下一动作受限
- **WHEN** 用户撤销 active grant
- **THEN** 下一条原本可复用的 Confirm 命令重新等待确认

#### Scenario: 缩小不允许扩权
- **WHEN** narrow 请求增加动作、仓库、目标、写域、风险上限或延长到期时间
- **THEN** Runtime 拒绝请求且旧 grant 边界不变

### Requirement: 审计必须说明授权来源与匹配原因

每个带 grant 的执行动作 MUST 在命令审计 detail 中记录 decision、grant ID/digest、source request/command digest、context、work package、scope digest、当前分类出的动作／仓库／目标／写域，以及匹配或拒绝原因。创建、复用、撤销、缩小和过期状态 MUST 可由持久状态与审计重建；秘密值不得写入日志。

#### Scenario: 重试不产生重复授权
- **WHEN** 相同确认重试或 idempotent execute 被重放
- **THEN** Runtime 返回同一 active grant 或原执行结果
- **AND** 不新增第二个等价 active grant，也不扩大 scope

## 兼容与边界

- 未携带 authorization 字段的调用保持现有 exact-command confirmation 行为。
- grant 只减少普通 Confirm 类命令的重复询问，不把 Confirm 改成全局 Allow。
- 客户端负责为新宿主对话生成新的 `authorization_context_id`；Runtime 不依赖不稳定的 transport session ID。
- 首版命令分类采用保守 allowlist；未知命令宁可重新确认，不做模糊推断。
