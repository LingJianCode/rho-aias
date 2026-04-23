package ebpfs

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-g -O2 -Wall" xdp ../../ebpfs/xdp.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-g -O2 -Wall" tcEgress ../../ebpfs/tc_egress.bpf.c
