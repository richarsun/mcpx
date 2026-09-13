# 仓库指南

本入口用于 `richarsun/mcpx` 自维护 fork。开工须读取 [fork 薄适配](docs/FORK_MAINTENANCE.md)，核对当前仓库、目标分支和本次授权；它不适用于 `opentokenz/mcpx` 上游维护者。工程约定来自 [上游 AGENTS.md 固定基线](https://github.com/opentokenz/mcpx/blob/3f81d08df744cf84d0a1fba61cd43b70e04c74b2/AGENTS.md)，下文已直接替换授权、测试、版本与发布的差异条款，不并行启用互相矛盾的旧条文。

## 项目结构与模块组织

MCPX 是运行在开发环境中的 **MCP Runtime（网关）**，Go module 为 `mcpx`，需 **Go 1.26.1+**（以 `go.mod` 为准）。

| 路径 | 说明 |
|------|------|
| `cmd/mcpx-server/` | 可执行入口（`main`、子命令如 `oauth-register`） |
| `internal/observation/` | 观测系统：`timeline`、`render`、`diff`、`event`、`store`、`width` 等，用于实时观测、事件流、变更摘要、终端展示和模型友好交互（最近新增 observation_bridge.go） |
| `docs/plans/`、`docs/specs/` | 实现计划与设计规格 |
| `bin/` | 本地构建产物（已 gitignore） |
| `~/.mcpx/` | 运行时数据（配置、SQLite、日志、任务），**不在本仓库** |

本地产品文档 `prd/`、`docs/superpowers/` 被 `.gitignore` 排除，勿提交。

## 版本策略

- 以本次批准的行为和实际运行状态维护当前契约，不为假设中的旧版预建兼容层；实质兼容行为变化须有任务授权。
- 涉及既有数据、配置或持久会话时，必须核对升级、恢复与回滚责任，不能用“不兼容旧版”免除数据责任。实现、文档和必要回归测试同步修改。

## 构建、测试与开发命令

以下为 Go 工程检查入口。实际 [CI](.github/workflows/ci.yml) 在 Ubuntu 执行 Format、Vet、Build with provenance；当前不运行单测或 race，不能称 CI 已证明它们通过。Windows 入口与限制见 [fork 薄适配](docs/FORK_MAINTENANCE.md#验证入口)。

```bash
# 编译
go build -o bin/mcpx-server ./cmd/mcpx-server

# 单测（按改动选择相关包；全仓结果单列）
go test ./... -count=1

# 竞态检测
go test -race ./... -count=1

# 格式检查（仅 cmd + internal）
test -z "$(gofmt -l ./cmd ./internal)"

# 静态检查
go vet ./...

# 发布构建（CGO 关闭，与 CI/GoReleaser 一致）
CGO_ENABLED=0 go build -o bin/mcpx-server ./cmd/mcpx-server
```

本地运行：先执行 `./bin/mcpx-server workspace register /path/to/project`，再执行 `./bin/mcpx-server` 启动服务；终端观测使用 `./bin/mcpx-server observe <workspace-name>`。版本：`./bin/mcpx-server -version`。
发版：当前 [Release](.github/workflows/release.yml) 由 `main` push 或 `workflow_dispatch` 触发，并可能创建 Tag/Release。合并前须核对目标仓 Actions 实际启用状态及发布副作用；未获发布授权不得通过合并或手动触发间接发布。这里不授权 Tag、Release、部署或重启。

## 编码风格与命名

- 使用 `gofmt`；改动保持与现有包风格一致（小写包名、导出类型 PascalCase、YAML 字段 `snake_case` tag）。
- 平台相关文件用 `_unix.go` / `_windows.go` / `_darwin.go` 后缀（见 `changeset`、`environment`、`cmd`）。
- 优先改 `internal/` 对应包；工具面注册与 HTTP 网关在 `internal/server/`。
- 最小充分改动；不要引入未使用的依赖。

## 测试指南

- 框架：Go 标准库 `testing`。
- 命名：`*_test.go`，与被测包同目录（如 `internal/auth/token_test.go`）。
- 改后端逻辑后应补/跑相关包测试；宣称完成前至少对改动包执行 `go test ./path/to/pkg -count=1`，合并前按改动风险执行全仓检查并如实记录平台限制；当前 CI 不运行单测。
- 支撑本次实现的必要回归测试随源码进入版本管理，无需逐项重复确认；临时实验、运行状态与私有材料不混入提交。

## 提交与 PR

- 历史风格：Conventional Commits，**subject 中文动词开头**，例如：
  - `feat(cli): 增加 oauth-register 子命令`
  - `fix(oauth): 持久化 DCR 客户端`
  - `docs(readme): 补充接入说明`
  - `chore(repo): …` / `ci(release): …`
- 已批准范围内的实现、必要测试、`commit`、`push`、PR 和审核修复连续执行，不逐次重复索权。只读调研不获得写入权；新写域、发布、部署等未覆盖动作另按真实授权判断。入口本身不产生授权。
- PR：说明动机、行为、授权与 Issue；涉及鉴权/网关/配置时写清兼容与风险。适用检查按实际执行结果记录，不把 CI、定向测试和真实 Chat 验收混为一项。合并遵守适用审核门和获授权 Owner 责任，不赋予自己上游合并权。

## 安全与配置（要点）

- 进程配置与密钥在 `~/.mcpx/config.yaml`（及环境变量如 `MCPX_HOME`、`MCPX_LOG_LEVEL`），**勿把真实 token/password/secret 写入仓库或文档示例**。
- 鉴权为进程级（`auth.mode`：open / bearer / oauth / dual）；项目级 `.mcpx.yaml` 只覆盖描述与安全策略等，不覆盖全局凭证。
- 命令与文件策略见 `security.commands` / `security.files`；默认偏安全（命令默认 `confirm`）。
- 审计日志与任务日志在 `~/.mcpx/`，权限敏感，勿打包进 release（GoReleaser 仅发二进制）。
