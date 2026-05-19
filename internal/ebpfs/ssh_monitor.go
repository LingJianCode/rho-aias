package ebpfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"rho-aias/internal/logger"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// runtimeConfig 与 eBPF C 端 struct runtime_config 对应
type runtimeConfig struct {
	AggressiveMode      uint8
	PreauthShortConnNs uint64
}

// SshMonitor SSH 登录行为监控的 eBPF 门面
// 封装 bpf2go 生成的 sshMonitorObjects，对外暴露高层 API
type SshMonitor struct {
	objects *sshMonitorObjects
	links   []link.Link
	reader  *ringbuf.Reader
}

// NewSshMonitor 创建 SshMonitor 实例（不加载，仅分配）
func NewSshMonitor() *SshMonitor {
	return &SshMonitor{}
}

// Load 加载 eBPF 对象到内核（运行时配置全部通过 Map.Put() 写入，无需 spec 全局变量）
func (s *SshMonitor) Load(ports []uint16, shortConnSeconds int, mode string) error {
	spec, err := loadSshMonitor()
	if err != nil {
		return fmt.Errorf("load ssh_monitor spec: %w", err)
	}

	// 直接加载，无需 spec.Variables 设置
	var obj sshMonitorObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		return fmt.Errorf("load and assign ssh_monitor objects: %w", err)
	}
	s.objects = &obj

	// 写入端口列表
	if err := s.putPorts(ports); err != nil {
		return err
	}

	// 写入运行时配置（mode + short_conn_ns 合一到 config_map）
	return s.putRuntimeConfig(shortConnSeconds, mode)
}

// putRuntimeConfig 将运行时配置写入 config_map（BPF_MAP_ARRAY[0] = runtime_config）
func (s *SshMonitor) putRuntimeConfig(shortConnSeconds int, mode string) error {
	cfgKey := uint32(0)
	cfgVal := runtimeConfig{
		AggressiveMode:      0,
		PreauthShortConnNs: uint64(shortConnSeconds) * uint64(time.Second),
	}
	if mode == "aggressive" {
		cfgVal.AggressiveMode = 1
	}
	if err := s.objects.ConfigMap.Put(&cfgKey, &cfgVal); err != nil {
		return fmt.Errorf("set config_map: %w", err)
	}
	return nil
}

// UpdateRuntimeConfig 运行时动态更新全部运行时参数（mode + short_conn_ns）
func (s *SshMonitor) UpdateRuntimeConfig(shortConnSeconds int, mode string) error {
	if s.objects == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}
	return s.putRuntimeConfig(shortConnSeconds, mode)
}

// putPorts 将端口列表写入 monitored_ports hash map
func (s *SshMonitor) putPorts(ports []uint16) error {
	portVal := uint8(1)
	for _, p := range ports {
		if err := s.objects.MonitoredPorts.Put(&p, &portVal); err != nil {
			return fmt.Errorf("set monitored_ports[%d]: %w", p, err)
		}
	}
	return nil
}

// UpdatePorts 运行时动态更新监控端口列表
func (s *SshMonitor) UpdatePorts(ports []uint16) error {
	if s.objects == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}
	return s.putPorts(ports)
}

// AttachProbes 附加所有 kprobe/tracepoint/fexit 探针
func (s *SshMonitor) AttachProbes() error {
	if s.objects == nil {
		return errors.New("objects not loaded")
	}
	s.links = make([]link.Link, 0, 4)

	// A1. fexit/inet_csk_accept（优先）
	if l, err := link.AttachTracing(link.TracingOptions{
		Program: s.objects.HandleAcceptFexit,
	}); err == nil {
		s.links = append(s.links, l)
		logger.Debug("[FailGuard] Attached fexit/inet_csk_accept")
	} else {
		// A2. 回退到 kretprobe
		logger.Warnf("[FailGuard] fexit/inet_csk_accept failed (%v), fallback to kretprobe", err)
		l2, err := link.Kretprobe("inet_csk_accept", s.objects.HandleAcceptKretprobe, &link.KprobeOptions{})
		if err != nil {
			return fmt.Errorf("kretprobe/inet_csk_accept also failed: %w", err)
		}
		s.links = append(s.links, l2)
		logger.Info("[FailGuard] Attached kretprobe/inet_csk_accept")
	}

	// B. tracepoint sched_process_fork
	lFork, err := link.Tracepoint("sched", "sched_process_fork", s.objects.HandleFork, nil)
	if err != nil {
		return fmt.Errorf("tracepoint/sched/process_fork: %w", err)
	}
	s.links = append(s.links, lFork)

	// C. uretprobe/pam_authenticate
	pamPath, pamErr := findLibPAM()
	if pamErr != nil {
		logger.Warnf("[FailGuard] libpam.so.0 not found: %v — PAM auth events will be unavailable", pamErr)
	} else {
		// uretprobe requires the target file to have executable permission (+x).
		// .so shared libraries are typically 0644 (no +x), especially in containers.
		chmodTarget := pamPath
		if fi, statErr := os.Lstat(pamPath); statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
			// pamPath is a symlink → resolve to real .so and chmod that
			if resolved, resolveErr := filepath.EvalSymlinks(pamPath); resolveErr == nil {
				chmodTarget = resolved
			}
		}
		if chmodErr := os.Chmod(chmodTarget, 0755); chmodErr != nil {
			logger.Warnf("[FailGuard] chmod +x %s failed: %v", chmodTarget, chmodErr)
		}
		ex, err := link.OpenExecutable(pamPath)
		if err != nil {
			logger.Warnf("[FailGuard] open libpam executable failed: %v — PAM auth unavailable", err)
		} else {
			up, err := ex.Uretprobe("pam_authenticate", s.objects.HandlePamAuth, nil)
			if err != nil {
				logger.Warnf("[FailGuard] uretprobe/pam_authenticate attach failed: %v", err)
			} else {
				s.links = append(s.links, up)
				logger.Info("[FailGuard] Attached uretprobe/pam_authenticate")
			}
		}
	}

	// D. tracepoint sched_process_exit
	lExit, err := link.Tracepoint("sched", "sched_process_exit", s.objects.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("tracepoint/sched/process_exit: %w", err)
	}
	s.links = append(s.links, lExit)

	logger.Infof("[FailGuard] Attached %d probes successfully", len(s.links))
	return nil
}

// EventsReader 创建 RingBuf 事件读取器
func (s *SshMonitor) EventsReader() (*ringbuf.Reader, error) {
	if s.objects == nil {
		return nil, errors.New("objects not loaded")
	}
	reader, err := ringbuf.NewReader(s.objects.Events)
	if err != nil {
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}
	s.reader = reader
	return reader, nil
}

// DetachLinks 分离所有已附加的探针
func (s *SshMonitor) DetachLinks() {
	for i, l := range s.links {
		if l != nil {
			if err := l.Close(); err != nil {
				logger.Warnf("[FailGuard] Error detaching link[%d]: %v", i, err)
			}
		}
	}
	s.links = nil
}

// Close 释放所有资源（reader → links → objects）
func (s *SshMonitor) Close() {
	if s.reader != nil {
		s.reader.Close()
		s.reader = nil
	}
	s.DetachLinks()
	if s.objects != nil {
		s.objects.Close()
		s.objects = nil
	}
}

// ============================================
// findLibPAM 查找 libpam.so.0 路径
// ============================================

func findLibPAM() (string, error) {
	envPath := os.Getenv("FAILGUARD_LIBPAM_PATH")
	if envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, nil
		}
		logger.Warnf("[FailGuard] FAILGUARD_LIBPAM_PATH=%s not found, searching default paths", envPath)
	}

	commonPaths := []string{
		"/usr/lib/x86_64-linux-gnu/libpam.so.0",
		"/usr/lib/aarch64-linux-gnu/libpam.so.0",
		"/lib/x86_64-linux-gnu/libpam.so.0",
		"/lib/aarch64-linux-gnu/libpam.so.0",
		"/lib64/libpam.so.0",
		"/usr/lib/libpam.so.0",
	}

	ldconfigOut, err := exec.Command("ldconfig", "-p").Output()
	if err == nil {
		parsedPath := parseLDConfigForLib(ldconfigOut, "libpam.so.0")
		if parsedPath != "" {
			return parsedPath, nil
		}
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	if pathFromProc := findLibPAMFromProcMaps(); pathFromProc != "" {
		return pathFromProc, nil
	}

	return "", errors.New("libpam.so.0 not found in system")
}

func parseLDConfigForLib(output []byte, libName string) string {
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		strLine := string(line)
		if len(strLine) > len(libName) && strLine[len(strLine)-len(libName):] == libName {
			fields := bytes.Fields([]byte(strLine))
			if len(fields) >= 4 {
				path := string(fields[3])
				if _, err := os.Stat(path); err == nil {
					return path
				}
			}
		}
	}
	return ""
}

func findLibPAMFromProcMaps() string {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return ""
	}

	target := "libpam.so.0"
	lines := bytes.Split(data, []byte("\n"))
	seen := make(map[string]bool)

	for _, line := range lines {
		idx := bytes.Index(line, []byte(target))
		if idx < 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte(" "), 6)
		if len(parts) < 6 {
			continue
		}
		path := string(bytes.TrimSpace(parts[5]))
		if path != "" && !seen[path] {
			seen[path] = true
			return path
		}
	}
	return ""
}
