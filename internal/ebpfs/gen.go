package ebpfs

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../../ebpfs/xdp.bpf.c --ccflags -target=bpf -g -O2 -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tcEgress ../../ebpfs/tc_egress.bpf.c --ccflags -target=bpf -g -O2 -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $BPF2GO_ARCH sshMonitor ../../ebpfs/ssh_monitor.bpf.c --ccflags -g -O2 -Wall
