package ebpfs

type Rule struct {
	Key   string
	Value uint8
}

type IPv4TrieKey struct {
	PrefixLen uint32 // __u32
	Addr      [4]byte
}
