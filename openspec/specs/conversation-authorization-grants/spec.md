# Conversation Authorization Grants Specification

## Purpose

定义 MCPX 在当前对话与有界工作包内复用一次明确授权时的持久化模型、范围匹配、安全优先级、生命周期、审计、恢复与兼容行为。

## Requirements

### Requirement: Grant 必须持久化并绑定明确授权上下文

Runtime SHALL 以可机器复用、可审计且可撤销的 grant 表达一次明确工作包授权。Grant SHALL 绑定 principal、authorization context、Remote Session、Workspace、work package ID/goal、purpose、动作类别、repository identities、targets、write paths、风险上限、状态、有效期及稳定 ID/digest。

#### Scenario: 首次确认创建稳定 grant

- **WHEN** 调用方为当前普通命令提交完整 `authorization_request`，并对 Runtime 返回的 exact pending digest 明确确认
- **THEN** Runtime SHALL 原子创建或恢复一个 active grant
- **AND** 响应 SHALL 返回稳定 grant ID、grant digest、scope digest 和来源摘要

#### Scenario: Transport 重试不产生重复 grant

- **WHEN** 首次确认已经提交，但客户端在收到响应前断连并以相同语义请求重试
- **THEN** Runtime SHALL 返回同一个 grant
- **AND** 不得创建第二个 active grant

### Requirement: 同一有界工作包内的普通动作必须可以复用授权

Runtime SHALL 在每次动作重新运行现有策略和 scope 匹配。只有策略结果为 Confirm、命令属于普通可分类动作、grant active 且未过期，并且所有绑定与范围均匹配时，Runtime SHALL 使用 grant 跳过逐命令确认。

#### Scenario: 连续 Git 工作包复用一次授权

- **WHEN** 同一 conversation、Remote Session、Workspace 和工作包连续执行授权范围内的 status/diff/fetch/switch/add/commit/push、受限 PR 操作或安全 branch cleanup
- **THEN** 后续 Confirm 类命令 SHALL 不再逐条要求确认
- **AND** 每个动作 SHALL 记录使用了哪个 grant 及为什么仍在范围内

#### Scenario: Read-only 与 mutation 使用同一边界

- **WHEN** read-only Git 动作和普通 Git mutation 都位于同一 grant scope
- **THEN** Runtime SHALL 对二者执行相同的 context、repository、target、purpose、risk 和 write-domain 匹配
- **AND** Allow/read-only 动作可以记录匹配，但不得误报为使用 grant 绕过 confirmation

### Requirement: Deny 和高风险边界必须优先

现有命令策略的 Deny SHALL 永远优先于 grant。Force push、ref 删除、永久删除、credential/secret/auth、payment、production deploy/release、系统网络/服务控制、无法可靠分类的命令以及其他高风险动作 SHALL NOT 因普通 grant 自动放行。

#### Scenario: Deny 优先

- **WHEN** 命令策略将动作判定为 Deny，即使调用携带有效且匹配的 grant
- **THEN** Runtime SHALL 直接拒绝动作
- **AND** 审计 SHALL 说明 grant 未覆盖 policy deny

#### Scenario: 高风险或未知动作越界

- **WHEN** 命令包含 force/delete/reset/clean、凭据、生产、付款、系统服务、永久删除、未知复合语法或外部执行面
- **THEN** 分类器 SHALL 将其标为 grant-ineligible
- **AND** grant SHALL NOT 自动扩权

#### Scenario: 代码执行型验证命令保持逐条确认

- **WHEN** 调用执行 `go test`、`go vet`、`go build` 或其他可能运行仓库代码的验证命令
- **THEN** 首版分类器 SHALL 不允许普通 grant 自动复用
- **AND** 现有逐命令安全策略 SHALL 继续生效

### Requirement: 边界实质变化必须重新受限

Grant SHALL 只在当前 principal、authorization context、Remote Session、Workspace、work package、purpose、repository、target、write path 和风险均在 scope 内时匹配。任一实质变化 SHALL 导致不匹配。

#### Scenario: 新 conversation 不继承旧 grant

- **WHEN** 调用使用新的 authorization context，或 session open 未显式提供旧 context
- **THEN** Runtime SHALL NOT 自动返回或复用旧 conversation grant

#### Scenario: Workspace、仓库或写域扩大

- **WHEN** 动作切换 Remote Session/Workspace、访问未授权 repository，或 add/commit 涉及 scope 外路径
- **THEN** Runtime SHALL 将 grant 判为不匹配
- **AND** Confirm 动作 SHALL 返回现有逐命令确认流程及精确 mismatch reason

#### Scenario: Purpose 或 target 变化

- **WHEN** purpose、branch、remote、PR、base/head 等目标不再符合 grant scope
- **THEN** Runtime SHALL 不复用 grant
- **AND** 审计 SHALL 标记 mismatch 而不是 grant reused

### Requirement: 用户必须可以撤销或缩小授权

Runtime SHALL 提供当前绑定下的 list、revoke 和 narrow。Revoke SHALL 立即使 grant inactive；narrow SHALL 以新 grant 原子替换旧 grant，并只允许 scope 真子集和/或更短有效期。

#### Scenario: 撤销后下一动作重新受限

- **WHEN** 用户撤销 active grant
- **THEN** 下一未完成动作 SHALL 不再匹配该 grant
- **AND** 重复 revoke SHALL 返回一致终态而不产生额外 grant

#### Scenario: 仅缩短有效期

- **WHEN** 用户保持 scope 不变但将 expiry 缩短为当前 expiry 之前且仍晚于当前时间
- **THEN** Runtime SHALL 创建替代 grant 并 supersede 旧 grant
- **AND** 不得要求同时删除其他 scope 维度

#### Scenario: Narrow 不得扩大

- **WHEN** narrow 请求新增动作类别、repository、target、write path、风险或延长有效期
- **THEN** Runtime SHALL 拒绝请求
- **AND** 原 grant SHALL 保持 active 且不变

### Requirement: 审计必须解释授权决定

每次携带授权元数据的动作 SHALL 在响应和审计中说明 decision、grant 来源、是否匹配、是否真正用于 confirmation bypass、match basis 或 mismatch reasons。

#### Scenario: 成功复用

- **WHEN** Confirm 动作使用匹配 grant 跳过逐命令确认
- **THEN** 审计 SHALL 记录 grant ID/digest、source request/command digest、当前 action 和全部正向匹配依据
- **AND** `grant_reused` 与 `grant_used_for_confirmation_bypass` SHALL 为 true

#### Scenario: 不匹配回退确认

- **WHEN** grant 存在但当前动作越出边界
- **THEN** 审计 SHALL 记录具体 mismatch reasons
- **AND** 不得将该动作标为 grant reused 或 confirmation bypass

### Requirement: 恢复和幂等不得造成重复效果或跨边界回放

授权 context、grant、request 和授权调用的 purpose SHALL 参与幂等业务指纹。已完成请求 SHALL 能在 grant 后续 narrow、revoke 或 expire 后精确重放；改变任何授权边界或业务参数 SHALL 返回幂等冲突。

#### Scenario: 断连后精确重放

- **WHEN** 普通 grant-backed 命令已经完成并持久化结果，但客户端断连后以相同 key 和相同参数重试
- **THEN** Runtime SHALL 返回 durable replay
- **AND** 不得再次执行命令或重新要求 grant confirmation

#### Scenario: Purpose 或 grant 改变

- **WHEN** 调用复用同一 idempotency key 但改变 purpose、context、grant、authorization request 或业务参数
- **THEN** Runtime SHALL 返回 `IDEMPOTENCY_CONFLICT`
- **AND** 不得重放旧授权下的结果

### Requirement: move_out 强安全协议必须保持独立

Conversation grant SHALL NOT 扩展或替代 `move_out` 的 prepare → confirm → submit 协议。

#### Scenario: move_out schema 隔离

- **WHEN** 列出 execute、session 和 move_out 的公开 schema
- **THEN** execute/session 可以公开 conversation grant 字段
- **AND** move_out SHALL NOT 接受 authorization context、grant ID、request、narrow 或 revoke 字段
- **AND** submit SHALL 继续要求 prepare 生成的服务端 confirmation UUID

### Requirement: 未使用 grant 的旧客户端必须保持兼容

新增授权字段 SHALL 为 opt-in。未提供 authorization 元数据的 execute 调用 SHALL 保持原命令策略、exact confirmation 和既有错误语义。

#### Scenario: 旧客户端继续逐命令确认

- **WHEN** 调用方未提供 context、grant ID 或 authorization request
- **THEN** Runtime SHALL 使用原有 Allow/Confirm/Deny 流程
- **AND** 不得隐式创建、查找或继承 conversation grant
