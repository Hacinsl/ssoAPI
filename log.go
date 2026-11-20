package ssoapi

import (
	"fmt"
	"log"
	"os"

	httputils "github.com/Hacinsl/httpUtils"
)

const (
	LogLevelError int = 1 // 仅输出错误
	LogLevelWarn  int = 2 // 输出错误与警告
	LogLevelInfo  int = 3 // 输出错误、警告与信息
	LogLevelDebug int = 4 // 输出全部日志
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

func logInfo(format string, args ...any) {
	if !EnableLog || LogLevel < 3 {
		return
	}
	logger.Output(2, "[ssoAPI INFO] "+fmt.Sprintf(format, args...))
}

func logWarn(format string, args ...any) {
	if !EnableLog || LogLevel < 2 {
		return
	}
	logger.Output(2, "[ssoAPI WARN] "+fmt.Sprintf(format, args...))
}

func logError(format string, args ...any) {
	if !EnableLog {
		return
	}
	logger.Output(2, "[ssoAPI ERROR] "+fmt.Sprintf(format, args...))
}

func logDebug(format string, args ...any) {
	if !EnableLog || LogLevel < 4 {
		return
	}
	logger.Output(2, "[ssoAPI DEBUG] "+fmt.Sprintf(format, args...))
}

// applyHTTPDebug 把当前的日志开关同步给 httpUtils 的请求/响应抓包输出。
func applyHTTPDebug() {
	httputils.EnableDebugOutput = EnableLog && LogLevel >= LogLevelDebug
}
