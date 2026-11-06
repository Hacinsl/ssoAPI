package ssoapi

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mxschmitt/playwright-go"
)

// chromium 是库里唯一用到的浏览器；只装它可省下近 400MB。
var installBrowsers = []string{"chromium"}

// EnvStatus 描述当前设备上 Playwright 驱动与 Chromium 的就绪情况。
type EnvStatus struct {
	Ready         bool   // 驱动与浏览器均可用
	DriverVersion string // playwright 驱动版本，例如 1.62.1
	BrowserPath   string // chromium 可执行文件路径
	Err           error  // 未就绪时的具体原因
}

func (s EnvStatus) String() string {
	var b strings.Builder
	if s.DriverVersion != "" {
		fmt.Fprintf(&b, "Driver version: %s\n", s.DriverVersion)
	}
	if s.BrowserPath != "" {
		fmt.Fprintf(&b, "Browser path: %s\n", s.BrowserPath)
	}
	if s.Ready {
		b.WriteString("Status: ready")
	} else if s.Err != nil {
		fmt.Fprintf(&b, "Status: not ready (%v)", s.Err)
	} else {
		b.WriteString("Status: not ready")
	}
	return b.String()
}

// EnsureOptions 控制自动安装行为。
type EnsureOptions struct {
	// AutoInstall 为 true 时，检测到缺失会立即联网下载（驱动 + chromium）。
	AutoInstall bool
	// WithDeps 仅 Linux 有效，额外安装系统依赖（需要 root/sudo）。
	WithDeps bool
	// Verbose 打印下载与安装过程，默认 false 时静默。
	Verbose bool
	// Timeout 是最终真实启动校验的超时，<=0 时用 30s。
	Timeout time.Duration
}

// CheckEnvironment 只做检测，不下载任何东西：
//  1. 驱动是否已安装且版本匹配（playwright.Run 失败即缺失）；
//  2. chromium 可执行文件是否存在于磁盘。
//
// 它不会启动浏览器，通常几十毫秒即可返回。
func CheckEnvironment() EnvStatus {
	status := EnvStatus{DriverVersion: driverVersion()}

	pw, err := playwright.Run()
	if err != nil {
		status.Err = fmt.Errorf("playwright driver is unavailable (%w)", err)
		return status
	}
	defer func() { _ = pw.Stop() }()

	path := pw.Chromium.ExecutablePath()
	status.BrowserPath = path
	if path == "" {
		status.Err = fmt.Errorf("chromium executable path is empty, browser is not installed")
		return status
	}
	if _, err := os.Stat(path); err != nil {
		status.Err = fmt.Errorf("chromium executable does not exist: %w", err)
		return status
	}

	status.Ready = true
	return status
}

// VerifyLaunch 真正拉起一次无头 Chromium 再关闭，确认端到端可用。
func VerifyLaunch(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	pw, err := playwright.Run()
	if err != nil {
		return fmt.Errorf("failed to start playwright driver: %w", err)
	}
	defer func() { _ = pw.Stop() }()

	launchArgs := []string{
		"--lang=zh-CN",
		"--disable-blink-features=AutomationControlled",
		"--hide-scrollbars",
		"--mute-audio",
	}
	if noSandbox {
		launchArgs = append(launchArgs, "--no-sandbox", "--disable-dev-shm-usage")
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     launchArgs,
		Timeout:  playwright.Float(float64(timeout.Milliseconds())),
	})
	if err != nil {
		return fmt.Errorf("failed to launch chromium: %w", err)
	}
	return browser.Close()
}

// InstallEnvironment 无条件执行一次安装（幂等：已装好时几乎无耗时）。
func InstallEnvironment(opt EnsureOptions) error {
	opts := &playwright.RunOptions{
		Browsers: installBrowsers,
		WithDeps: opt.WithDeps,
		Verbose:  opt.Verbose,
	}
	if err := playwright.Install(opts); err != nil {
		return fmt.Errorf("failed to install playwright runtime: %w", err)
	}
	return nil
}

// EnsureEnvironment 是“自检 + 按需安装 + 真实启动校验”的一站式入口：
func EnsureEnvironment(opt EnsureOptions) (EnvStatus, error) {
	status := CheckEnvironment()
	if !status.Ready {
		if !opt.AutoInstall {
			return status, fmt.Errorf("runtime environment is not ready: %v; "+
				"please run `go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6201.1 install chromium` "+
				"or enable AutoInstall to download it automatically", status.Err)
		}
		if err := InstallEnvironment(opt); err != nil {
			return status, err
		}
		status = CheckEnvironment()
		if !status.Ready {
			return status, fmt.Errorf("still unavailable after installation: %v", status.Err)
		}
	}

	if err := VerifyLaunch(opt.Timeout); err != nil {
		status.Ready = false
		status.Err = err
		return status, fmt.Errorf("environment self-check failed: %w", err)
	}
	return status, nil
}

// driverVersion 读取驱动版本号。
func driverVersion() string {
	driver, err := playwright.NewDriver()
	if err != nil {
		return ""
	}
	return driver.Version
}
