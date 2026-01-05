package ebpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"rho-aias/utils"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type Xdp struct {
	InterfaceName string
	objects       *xdpObjects
	link          *link.Link
	reader        *perf.Reader
	done          chan struct{}
	linkType      string
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
	var ebpfObj xdpObjects
	if err := loadXdpObjects(&ebpfObj, nil); err != nil {
		return fmt.Errorf("failed to load eBPF objects: %s", err.Error())
	}
	x.objects = &ebpfObj
	x.reader, err = perf.NewReader(x.objects.Events, os.Getpagesize())
	if err != nil {
		x.Close()
		return fmt.Errorf("failed to create perf event reader: %s", err.Error())
	}
	x.done = make(chan struct{})

	// ---------- attach XDP ----------
	count := 0
	flagNames := []string{"offload", "driver", "generic"}
	for i, mode := range []link.XDPAttachFlags{link.XDPOffloadMode, link.XDPDriverMode, link.XDPGenericMode} {
		flagName := flagNames[i]
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   x.objects.XdpProg,
			Interface: iface.Index,
			Flags:     mode,
		})
		if err == nil {
			x.linkType = flagName
			x.link = &l
			log.Printf("XDP program attached successfully, current mode: %s", flagName)
			break
		}
		count++
		fmt.Printf("failed to attach XDP program with %s mode: %s\n", flagName, err.Error())
	}
	if count == 3 {
		x.Close()
		return errors.New("failed to attach XDP program")
	}
	return nil
}

func (x *Xdp) Close() {
	log.Println("Xdp close.")
	if x.done != nil {
		close(x.done)
	}
	if x.reader != nil {
		x.reader.Close()
	}
	if x.link != nil {
		(*x.link).Close()
	}
	if x.objects != nil {
		x.objects.Close()
	}
}

func (x *Xdp) GetLinkType() string {
	return x.linkType
}

func (x *Xdp) MonitorEvents() {
	log.Println("MonitorEvents")
	for {
		select {
		case <-x.done:
			return
		default:
			record, err := x.reader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					log.Printf("perf event reader closed, trying to restart eBPF")
					x.Close()
					if err := x.Start(); err != nil {
						log.Fatalf("failed to restart eBPF: %s", err.Error())
					} else {
						log.Printf("eBPF restarted successfully")
					}
					return
				}
				continue
			}
			var pi PacketInfo
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &pi); err != nil {
				continue
			}
			log.Println(pi.SrcIP)
		}
	}
}

func (x *Xdp) updateMap(iptype utils.IPType, value []byte, add bool) (err error) {
	switch iptype {
	case utils.IPTypeIPv4:
		if add {
			err = x.objects.Ipv4List.Put(value, uint8(1))
		} else {
			err = x.objects.Ipv4List.Delete(value)
		}
	case utils.IPTypeIPV4CIDR:
		if add {
			err = x.objects.Ipv4CidrTrie.Put(value, uint8(1))
		} else {
			err = x.objects.Ipv4CidrTrie.Delete(value)
		}
	case utils.IPTypeIPv6:
		if add {
			err = x.objects.Ipv6List.Put(value, uint8(1))
		} else {
			err = x.objects.Ipv6List.Delete(value)
		}
	case utils.IPTypeIPv6CIDR:
		if add {
			err = x.objects.Ipv6CidrTrie.Put(value, 1)
		} else {
			err = x.objects.Ipv6CidrTrie.Delete(value)
		}
	default:
		return fmt.Errorf("unsupported match type: %v", iptype)
	}
	return err
}

func (x *Xdp) AddRule(value string) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	log.Println(bytes, iptype)
	return x.updateMap(iptype, bytes, true)
}

func (x *Xdp) DeleteRule(value string) error {
	bytes, iptype, err := utils.ParseValueToBytes(value)
	if err != nil {
		return err
	}
	return x.updateMap(iptype, bytes, false)
}

func (x *Xdp) GetRule() ([]Rule, error) {
	var res []Rule
	ipv4List, err := x.ipv4List()
	if err != nil {
		return res, err
	}
	res = append(res, ipv4List...)
	ipv4TrieKeyList, err := x.ipv4TrieKey()
	if err != nil {
		return res, err
	}
	res = append(res, ipv4TrieKeyList...)
	return res, nil
}

func (x *Xdp) ipv4List() ([]Rule, error) {
	iter := x.objects.Ipv4List.Iterate()
	var key uint32
	var value uint8
	var res []Rule
	for iter.Next(&key, &value) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key)
		ip := net.IP(ipBytes)
		res = append(res, Rule{
			Key:   ip.String(),
			Value: value,
		})
	}
	if err := iter.Err(); err != nil {
		return []Rule{}, err
	}
	return res, nil
}

func (x *Xdp) ipv4TrieKey() ([]Rule, error) {
	iter := x.objects.Ipv4CidrTrie.Iterate()
	var key IPv4TrieKey
	var value uint8
	var res []Rule
	for iter.Next(&key, &value) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Addr)
		ip := net.IP(ipBytes)
		res = append(res, Rule{
			Key:   fmt.Sprintf("%s/%d", ip.String(), key.PrefixLen),
			Value: value,
		})
	}
	if err := iter.Err(); err != nil {
		return []Rule{}, err
	}
	return res, nil
}
