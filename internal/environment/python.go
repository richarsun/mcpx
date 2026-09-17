package environment

import "runtime"

// PythonExecutable 统一环境探测和临时脚本的入口，不修改 PATH 或系统执行别名。
func PythonExecutable() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
}
