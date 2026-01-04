package ebpf

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Xdp struct {
	InterfaceName string
	objects       xdpObjects
	link          link.Link
}

func NewXdp(interface_name string) *Xdp {
	return &Xdp{
		InterfaceName: interface_name,
	}
}

func (x *Xdp) Start() error {
	iface, err := net.InterfaceByName(x.InterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %s", x.InterfaceName, err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("failed to remove memlock: %s", err.Error())
	}
	if err := loadXdpObjects(&x.objects, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %s", err.Error())
	}

	// ---------- attach XDP ----------
	count := 0
	flagNames := []string{"offload", "driver", "generic"}
	for i, mode := range []link.XDPAttachFlags{link.XDPOffloadMode, link.XDPDriverMode, link.XDPGenericMode} {
		flagName := flagNames[i]
		x.link, err = link.AttachXDP(link.XDPOptions{
			Program:   x.objects.XdpProgFunc,
			Interface: iface.Index,
			Flags:     mode,
		})
		if err == nil {
			log.Printf("XDP program attached successfully, current mode: %s", flagName)
			break
		}
		count++
		fmt.Printf("failed to attach XDP program with %s mode: %s\n", flagName, err.Error())
	}
	if count == 3 {
		return errors.New("failed to attach XDP program")
	}
	return nil
}

func (x *Xdp) Stop() {
	if x.link != nil {
		x.link.Close()
	}
	x.objects.Close()
}
