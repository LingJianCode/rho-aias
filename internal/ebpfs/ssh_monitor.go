package ebpfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"rho-aias/internal/logger"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

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

// Load 加载 eBPF 对象到内核
func (s *SshMonitor) Load() error {
	var obj sshMonitorObjects
	if err := loadSshMonitorObjects(&obj, nil); err != nil {
		return fmt.Errorf("load ssh_monitor objects: %w", err)
	}
	s.objects = &obj
	return nil
}

// Configure 配置运行时参数（端口、模式等）
func (s *SshMonitor) Configure(sshPort uint16, shortConnSeconds int) error {
	if s.objects == nil {
		return errors.New("objects not loaded")
	}

	// 配置监控端口 map
	portVal := uint8(1)
	if err := s.objects.MonitoredPorts.Put(&sshPort, &portVal); err != nil {
		return fmt.Errorf("set monitored_ports[%d]: %w", sshPort, err)
	}

	// aggressive_mode 固定开启以支持 preauth 检测
	if err := s.objects.AggressiveMode.Set(uint8(1)); err != nil {
		return fmt.Errorf("set aggressive_mode: %w", err)
	}

	// preauth_short_conn_ns
	shortConnNS := uint64(shortConnSeconds) * uint64(time.Second)
	if err := s.objects.PreauthShortConnNs.Set(shortConnNS); err != nil {
		return fmt.Errorf("set preauth_short_conn_ns: %w", err)
	}

	return nil
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

	// C. uretprobe/pam_authenticate（当前跳过，cilium/ebpf v0.20.0 不支持 uretprobe）
	pamPath, pamErr := findLibPAM()
	if pamErr == nil {
		_ = pamPath
		logger.Warn("[FailGuard] uretprobe/pam_authenticate: cilium/ebpf v0.20.0 不支持 uretprobe，" +
			"PAM 认证检测暂不可用。升级依赖后可恢复此功能。")
	} else {
		logger.Warnf("[FailGuard] libpam.so.0 not found: %v — PAM auth events will be unavailable", pamErr)
	}

	// D. tracepoint sched_process_exit
	lExit, err := link.Tracepoint("sched", "sched_process_exit", s.objects.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("tracepoint/sched/process_exit: %w", err)
	}
	s.links = append(s.links, lExit)

	logger.Infof("[FailGuard] Attached %d probes successfully (PAM probe pending dependency upgrade)", len(s.links))
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
