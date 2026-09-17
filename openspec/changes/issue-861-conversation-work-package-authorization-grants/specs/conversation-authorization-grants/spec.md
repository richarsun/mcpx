## ADDED Requirements

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

### Requirement: Grant reuse 必须绑定唯一且等价的 Git 执行面

Runtime SHALL 只对能够证明分类语义与实际执行语义一致的 Git 动作复用 grant。分类器 SHALL 将 repository/target、顶层 executable、argv 以及会改变 Git child program/transport 解析的关键环境共同视为授权执行边界；任何歧义、未知或漂移 SHALL fail-closed。

#### Scenario: Remote 字符串不得有第二种 Git transport 解释

- **WHEN** remote URL 使用 `<transport>::<address>`、非明确允许的 scp-like `host:path` / `user@host:path`，或其他会被 Git 解释为 helper/SSH transport 而分类器可能当成本地路径的形式
- **THEN** 分类器 SHALL 在 Workspace 本地路径归一化之前将该动作标为 grant-ineligible
- **AND** fetch/push SHALL NOT 在任何 remote helper 启动后才以非零退出码作为安全回退
- **AND** 合法 Windows 绝对盘符路径 SHALL 与 scp-like 语法明确区分

#### Scenario: Git child program 环境不得绕过可信顶层 executable

- **WHEN** 当前进程环境设置了能够替换 Git child program 的 `GIT_EXEC_PATH`
- **THEN** grant 分类 SHALL 在任何 Git 探测或 child program 副作用之前 fail-closed，或使用经验证且冻结的安全替代值
- **AND** grant-backed 实际执行 SHALL 使用与分类探测相同的受控环境语义，而不是重新继承不同的进程环境
- **AND** grant-backed Git 的 PATH SHALL 由已验证 Git 安装与必要系统目录派生，不得保留任意宿主 PATH shadow

#### Scenario: HTTPS credential helper 必须绑定受信任 Git 安装

- **WHEN** grant-eligible GitHub HTTPS remote 的有效 Git 配置启用了 credential helper
- **THEN** Runtime SHALL 只允许绑定同一受信任 Git 安装的 system manager，或本 spec 定义的 Windows GitHub CLI 固定凭据链窄例外
- **AND** 超出这两种模型的未知、shell、多个或来源不可证明的 helper SHALL fail-closed

#### Scenario: 所有 grant-eligible git_read 都必须有规范 target

- **WHEN** Git read 动作进入 grant allowlist
- **THEN** `Action.Targets` SHALL 包含至少一个可规范化 branch/object target
- **AND** `git branch --show-current` SHALL 绑定当前 attached branch
- **AND** detached/未知 target 或 plain `git branch` SHALL grant-ineligible，而不是以空 target 跳过 matcher 检查

#### Scenario: 分类与执行不得漂移

- **WHEN** Runtime 已用 grant 批准一个 Git 动作
- **THEN** 实际执行 SHALL 使用分类时冻结的可信 executable、argv 和受控 environment
- **AND** repository/target/remote/helper 的实际解释 SHALL 不得比分类得到的执行面更宽

#### Scenario: POSIX C drive lookalike remote 在任何 SSH 副作用前 fail-closed

- **WHEN** POSIX 上 fetch/push remote 为 `C:/repo`，Workspace 中同时存在形似本地 bare repo 的 lookalike 路径
- **THEN** Runtime SHALL NOT 套用 Windows drive-absolute local-path 例外
- **AND** 动作 SHALL 在 SSH、remote helper 或 marker side effect 启动前 grant-ineligible

#### Scenario: Windows 绝对盘符本地路径保持正向

- **WHEN** Windows 上 remote/repository 是合法且位于授权 Workspace 边界内的 drive-absolute local path
- **THEN** Runtime MAY 按 Windows 本地路径语义分类
- **AND** 既有 Workspace scope/path escape 检查 SHALL 继续生效

#### Scenario: URL-scoped credential helper 超出窄模型时禁用 grant reuse

- **WHEN** 有效 Git 配置包含 `credential.<url>.helper` 且不满足 Windows GitHub CLI 固定凭据链窄例外
- **THEN** Stage V1 SHALL 将该 network Git 动作标为 grant-ineligible
- **AND** 用户仍可通过 existing ordinary confirmation 执行该 Git 形态

#### Scenario: Empty credential helper reset 必须被检测

- **WHEN** 任一有效配置层对匹配 URL 提供空 helper reset
- **THEN** Runtime SHALL NOT 把仅查询到的 system/default helper 当成完整 helper chain
- **AND** 除 Windows GitHub CLI 固定凭据链窄例外外，grant reuse SHALL fail-closed

#### Scenario: Multiple credential helpers 必须 fail-closed

- **WHEN** Git 的有效 helper chain 含多个 helper
- **THEN** Stage V1 SHALL NOT 尝试证明其组合执行面安全
- **AND** 动作 SHALL 回到 ordinary confirmation

#### Scenario: Shell credential helper 必须 fail-closed

- **WHEN** 有效 helper 使用不属于 Windows GitHub CLI 固定凭据链窄例外的 `!shell-command`
- **THEN** grant 分类 SHALL 在 helper side effect 前 fail-closed
- **AND** marker command SHALL NOT 因 grant 分类或 grant-backed 执行被启动

#### Scenario: Absolute 或 custom credential helper 必须 fail-closed

- **WHEN** helper 指向 absolute/custom executable 或来源不可信，且不属于 Windows GitHub CLI 固定凭据链窄例外
- **THEN** Stage V1 SHALL 将动作标为 grant-ineligible
- **AND** SHALL NOT 通过运行 helper 来判断其可信性

#### Scenario: Windows trusted system manager 正向路径

- **WHEN** Windows GitHub HTTPS remote 只配置一个 `credential.helper=manager`，其配置可证明来自同一受信任 Git for Windows system config，且 helper binary 位于同一已验证安装树
- **THEN** credential helper 检查 MAY 允许继续 grant classification
- **AND** 其他 repository/target/environment 不变量仍须独立满足

#### Scenario: System manager 加 URL override 必须 fail-closed

- **WHEN** system config 提供受信任 manager，但 repository/global/其他有效层同时提供不符合 Windows GitHub CLI 固定凭据链窄例外的 URL-specific reset 或 override
- **THEN** Runtime SHALL 将动作标为 grant-ineligible
- **AND** SHALL NOT 只依据 system manager 判定 helper 执行面可信

#### Scenario: Git config 环境注入必须 fail-closed

- **WHEN** 当前环境存在会改变 config source 或注入 config 的未冻结 `GIT_CONFIG_*` 变量
- **THEN** Stage V1 SHALL 在 Git config/helper 探测副作用前拒绝 grant reuse
- **AND** ordinary confirmation 路径 SHALL 保持可用

#### Scenario: Canonical SSH remote 回退 ordinary confirmation

- **WHEN** remote 为 `git@github.com:owner/repo`、其他 scp-like form 或 `ssh://...`
- **THEN** Stage V1 SHALL 将其标为 grant-ineligible
- **AND** SHALL NOT 把 SSH Git 整体判为 Deny

#### Scenario: SSH config 不得经 grant path 执行

- **WHEN** user/system SSH config 含 `HostName`、`ProxyCommand`、`Match exec`、`Include` 或恶意 marker
- **THEN** grant classification 与 grant-backed execution SHALL NOT 启动 SSH 或触发该 marker
- **AND** Runtime SHALL 不以解析完整 SSH config 作为 Stage V1 前提

#### Scenario: Branch 与 tag 同名的裸 revision 必须 fail-closed

- **WHEN** `refs/heads/main` 与 `refs/tags/main` 同时存在且指向不同对象，而命令输入裸 `main`
- **THEN** Runtime SHALL NOT 猜测 branch/tag precedence 并复用 grant
- **AND** 该 revision SHALL 回到 ordinary confirmation

#### Scenario: 显式 refs/heads branch 是正向 canonical target

- **WHEN** Git read 使用显式 `refs/heads/<branch>` 且该 ref 经验证存在并位于 grant scope
- **THEN** `Action.Targets` SHALL 绑定该 canonical branch target
- **AND** actual argv SHALL 使用该已验证 canonical ref

#### Scenario: Full object ID 按 object identity 解析

- **WHEN** 输入是经验证存在的 full object ID，即使仓库同时存在与该 40-hex 字符串同名的 ref
- **THEN** Runtime SHALL 将 target 绑定为 object identity
- **AND** actual argv SHALL 使用已验证 full OID，而不是先误分类成同名 branch/ref

#### Scenario: Narrow 后 alias 不得恢复已移除 target

- **WHEN** grant 已 narrow 移除某 target
- **THEN** bare/tag/OID alias SHALL NOT 让后续 read 重新访问该已移除 target
- **AND** target matcher SHALL 基于 canonical validated identity 做边界判断

#### Scenario: Unsupported revision 回到 ordinary confirmation

- **WHEN** revision 是裸 symbolic name、`HEAD~1`、range 或其他 Stage V1 未唯一建模语法
- **THEN** Runtime SHALL 将动作标为 grant-ineligible
- **AND** SHALL NOT 静默扩大 grant classifier 或把该 Git 能力改成不可用

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


### Requirement: Windows GitHub CLI 固定凭据链窄例外

Runtime SHALL 只接受下述固定凭据链作为 URL-specific/reset/shell-helper 拒绝规则的窄例外；其他拒绝场景保持有效。

#### Scenario: 当前正常 HOME 的官方 GitHub CLI 配置

- **WHEN** Windows canonical GitHub HTTPS 使用用户 global .gitconfig 的精确 host helper，值依次为空 reset 与固定的受信任安装绝对路径 gh.exe auth git-credential，generic helper 也符合既有约束
- **THEN** Runtime MAY 将该动作继续按 repository/target/scope 等边界分类为 grant eligible
- **AND** 同形 gist.github.com helper MAY 共存；normal HOME 的 fetch/push 必须分别验收
- **AND** Runtime SHALL 校验 gh 的原生可执行格式、解析后安装路径及固定参数，不执行 helper 探测、不读取或回显凭据、不修改 global config

#### Scenario: 窄例外不能扩展为任意 shell 或 URL helper

- **WHEN** helper 来源不是用户 global .gitconfig，URL 不是精确 github.com/gist.github.com，reset/值数/顺序不符，程序不可信，或附加命令/参数/更多 helper
- **THEN** Runtime SHALL 在执行 helper 前回退原确认，不匹配 grant
- **AND** 下一动作发现配置变化 SHALL 重新判定；撤销/narrow/幂等与 deny 优先保持原合同
