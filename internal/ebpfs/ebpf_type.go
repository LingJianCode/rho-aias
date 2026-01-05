package ebpfs

type Rule struct {
	Key   string
	Value uint8
}

type IPv4TrieKey struct {
	PrefixLen uint32 // __u32
	Addr      uint32 // __be32 → 用 uint32 存储网络字节序值
}
