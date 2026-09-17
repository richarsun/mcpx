# MCPX fork 薄适配

本文件由根 [AGENTS.md](../AGENTS.md) 必须读取的链接承接，仅维护 `richarsun/mcpx` 的差异，不复制全局流程、不修改 MCPX 产品的鉴权或 command confirm。需求与验收：[中央 Issue #849](https://github.com/richarsun/personal-ai-ops/issues/849)。

## 规则与授权

平台约束、当前真人指令、适用全局规则与仓库事实分别判断；仓库入口和岗位名称不能产生本次授权。Codex 从本机实际 `CODEX_HOME`（未设置时使用本机默认目录）按需读取 `rules/development-process.md` 的事实源与授权、Git 与分支、Review、发布部署章节，不在本仓保存全局正文副本。

Chat 使用现有专业 Chat 启动机制，由获准执行者提供可访问的全局规则固定版本链接、此仓库 exact commit 下的入口及本次授权；不能要求 Chat 读取 Windows 私有路径，也不修改账号个性化设置。链接可访问、实际读取与行为验证分别记录，缺件不能假定已加载。

| 上游约定 | 本 fork 的差异 |
| --- | --- |
| 每次 commit/push 必须重新确认 | 复用真人已批准工作包中的连续交付授权；明确停点或新增未覆盖动作仍须遵守 |
| 单测是否提交由当轮决定 | 必要回归测试与实现一同提交，临时实验及私有状态另存 |
| 绝对不考虑旧版及迁移 | 不泛建兼容层；实际既有数据的升级、恢复和回滚责任必须处理 |
| Bash 检查及过时 CI/标签描述 | 使用下列 Windows 入口，按真实 workflow 区分 CI、测试和发布 |

上游原文来源：[`AGENTS.md@3f81d08`](https://github.com/opentokenz/mcpx/blob/3f81d08df744cf84d0a1fba61cd43b70e04c74b2/AGENTS.md)；逐次确认条款在 [首次提交 a1b38a6](https://github.com/opentokenz/mcpx/blob/a1b38a6a3bff637cf2757b07fdd4feb127e616d5/AGENTS.md) 已存在。保留其模块结构、Go 风格、最小充分改动与凭据保护；更新上游时需人工核对这些差异，不机械覆盖入口。

## 维护与贡献分支

- 上游：`https://github.com/opentokenz/mcpx.git`；自维护 fork：`https://github.com/richarsun/mcpx.git`。remote 名称只作本地别名，开工 fresh-read URL、refs、状态与包含关系，不凭 `origin` 猜目标。
- 使用已有 fork `main` 作为维护/集成目标，不新建长期 develop/master 或调度分支。已有 `dev` 等复制自上游的 refs 不自动成为本 fork 交付目标，也不清理它们。
- #849 从双方共同 `main@3f81d08df744cf84d0a1fba61cd43b70e04c74b2` 建 `codex/849-mcpx-fork-rules`，PR 回 `richarsun/mcpx:main`。该基线不含 Runtime 候选 `2ce11b5e290c6f0c33910fad2b3f11637733b03b`；不得将其夹带进适配 PR。
- 内部维护改动通过 fork PR 完成适用 Review/Fixup及获授权 Owner 手工合并。`main` 合并前检查 Release workflow 的实际状态；可能触发未获准发布时停止合并，先取得具体发布或发布隔离处理的授权，不擅自改 Actions 设置。
- 通用 Runtime 上游贡献从 fresh 上游基线独立准备，完整 diff 排除 fork 私有治理。现有 [上游 PR #22](https://github.com/opentokenz/mcpx/pull/22) 沿原审核链，不混入本适配。上游是否合并由上游维护者决定，fork 权限不等于上游权限。
- 部署必须另有 exact source/commit/tree、制品 SHA、目标设备、测试、风险、恢复步骤和真人批准。稳定部署来源须可由已放行维护分支追溯；任务分支、上游 Draft PR、本地测试或规则合并均不代表已部署。

## 验证入口

命令依据本仓 `go.mod`、[CI](../.github/workflows/ci.yml) 与 [Release](../.github/workflows/release.yml)。只运行本次必要检查；环境缺失写 NOT_RUN，不自动安装编译器或修改全局 Go 环境。

PowerShell 示例（进程环境仅用于 Windows 本地目标；交叉编译按任务明确目标）：

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go test ./internal/operation -count=1
# 将包路径替换为本次实际改动包，不将此例当作全部覆盖。
go vet ./internal/operation
gofmt -l internal/operation/service.go
git diff --check
$env:CGO_ENABLED = '0'
go build -o bin/mcpx-server.exe ./cmd/mcpx-server
```

构建命令不是运行许可，不在既有 Runtime 目录启动候选。`-version` 为版本查询参数，不能以位置参数 `version` 代替。`go test ./... -count=1` 是全仓检查；race 需要当前平台支持及既有 C 工具链，与 CGO=0 发布构建分开。

本事项关联的 Windows 现场已发现 Unix 文件权限/printf/sleep/python3、symlink 权限和 named pipe 关闭测试限制；后续按 exact 候选和平台记录，不能将历史失败永久豁免。定向 PASS、全仓结果、CI 实际 jobs、二进制身份、两个账号真实 Chat 分别留证。当前 CI 的格式/vet/构建通过不证明单测或 race 已执行。

## 采用与恢复

本 PR 只改变 fork 仓库入口，不发行或部署本机全局规则，不安装或重启 Runtime。合并后，新的 fork 检出须实际读取根入口及本文件；既有检出和 Chat 不自动采用。回滚使用正常 revert 并核对入口链接，保留上游来源，不强推、不清理已有改动。
