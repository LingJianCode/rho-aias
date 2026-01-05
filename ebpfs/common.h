#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/

// IPv4 分片相关
#define IP_MF 0x2000                 /* More Fragments flag */
#define IP_OFFSET 0x1FFF             /* Fragment offset mask */

// IPv6 分片相关
#define IP6F_OFF_MASK   0xFFF8       /* Fragment offset mask (bits 4-15) */
#define IP6F_MORE_FRAG  0x0001       /* More fragments flag (bit 3) */

#define IPPROTO_FRAGMENT  44         /* IPv6 Fragment extension header */ 