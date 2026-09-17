# Windows move_out 回收入口

对应 [中央 #860](https://github.com/richarsun/personal-ai-ops/issues/860)。修复 Windows 文件、显式目录通过 prepare 后仍返回 `MOVE_OUT_FAILED` 的调用错误。

## 行为与边界

- prepare、confirmation UUID、Session/Workspace、purpose、有效期、路径与 revision 校验沿用既有流程；本次不放宽授权或特殊文件类型。
- 确认后由 PowerShell 调用 Windows 回收站接口。固定脚本使用 `-EncodedCommand`，目标路径仅经该子进程的环境变量传递，以字面路径读取，支持中文、空格、引号和方括号。
- 每个目标最多等待 30 秒，替代只读探针的 2 秒上限；父请求取消仍生效。仅在找不到 `powershell.exe` 时选择 `pwsh.exe`。某个回收进程启动失败、执行失败或超时后，不尝试第二个解释器，也不回退永久删除。
- 成功必须同时满足进程成功退出和源路径消失。失败仍为 `MOVE_OUT_FAILED`，`target_preview[].error_message` 补充可用的异常类型/HRESULT、程序缺失或中断诊断；不回传任意脚本输出。
- 中断结果需要检查原目标和回收站，不能将失败理解为绝对没有副作用。沿用同一 confirmation UUID 回读已保存结果，不盲目另建请求。

## 验证

Windows 下设置进程变量 `MCPX_TEST_REAL_RECYCLE=1` 才运行真实回收测试。测试只创建并处理自己的临时文件和目录，包含中文及特殊字符；通过公开 prepare/submit 校验实际回收站条目、原内容和幂等重放，不清空回收站。目录 junction 的现有拒绝边界另作验证；不据此宣称一般符号链接已实测通过。

缺失程序、底层异常和取消测试验证失败诊断与源文件保留。POSIX 平台的模拟测试只覆盖分支契约，不能替代 Windows 真实回收测试。本修复不代表新二进制已安装或经过远程 Chat 调用验收。
