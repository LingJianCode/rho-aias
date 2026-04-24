package ebpfs

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	netlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// netlinkTCLink 通过 netlink 操作 clsact qdisc + bpf filter 实现 TC 程序挂载
// 用于内核 < 6.6（不支持 TCX）的 fallback 路径
type netlinkTCLink struct {
	ifaceIndex int
	ifaceName  string
	prog       *ebpf.Program
	filter     *netlink.BpfFilter
}

// attachTCViaNetlink 通过 netlink 在指定网卡上挂载 TC egress 程序
func attachTCViaNetlink(ifaceIndex int, ifaceName string, prog *ebpf.Program) (*netlinkTCLink, error) {
	// 1. 确保 clsact qdisc 存在
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return nil, fmt.Errorf("netlink: add clsact qdisc on %s: %w", ifaceName, err)
		}
		// EEXIST: clsact 已存在，继续
	}

	// 2. 创建 bpf filter 挂载到 egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("netlink: add bpf filter on %s egress: %w", ifaceName, err)
	}

	return &netlinkTCLink{
		ifaceIndex: ifaceIndex,
		ifaceName:  ifaceName,
		prog:       prog,
		filter:     filter,
	}, nil
}

// Close 删除 filter 并尝试清理 qdisc
func (l *netlinkTCLink) Close() error {
	if l.filter != nil {
		if err := netlink.FilterDel(l.filter); err != nil {
			return fmt.Errorf("netlink: delete bpf filter on %s: %w", l.ifaceName, err)
		}
		l.filter = nil
	}

	// 尝试删除 clsact qdisc（如果没有其他 filter 在用则成功，否则忽略错误）
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: l.ifaceIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscDel(qdisc) // 忽略错误，可能还有其他 filter

	return nil
}
