package ebpfs

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../../ebpfs/xdp.bpf.c --ccflags -target=bpf -g -O2 -Wall
