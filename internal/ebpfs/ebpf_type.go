package ebpfs

type Rule struct {
	Key   string
	Value uint8
}

// ebpf规定前缀为主机字节序(x86为小端)
type IPv4TrieKey struct {
	PrefixLen uint32 // __u32
	Addr      uint32 // __be32 → 用 uint32 存储网络字节序值
}
