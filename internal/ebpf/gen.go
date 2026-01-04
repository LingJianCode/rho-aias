////go:build ignore

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../../ebpf/xdp.bpf.c -- -g -O2 -Wall
