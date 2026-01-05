#!/usr/bin/env python3
"""
XDP eBPF 测试数据包生成器

使用 Scapy 构造各种类型的测试数据包，用于验证 XDP 程序的：
- IPv4 分片处理
- IPv6 扩展头处理
- IPv6 分片处理

依赖: pip install scapy
"""

import sys
import argparse
from scapy.all import *

# 禁用 Scapy 的警告
conf.verb = 0


class PacketGenerator:
    """生成各种类型的测试数据包"""

    def __init__(self, target_ip, interface=None):
        """
        初始化数据包生成器
        :param target_ip: 目标 IP 地址
        :param interface: 网络接口名称 (如 eth0, ens33)
        """
        self.target_ip = target_ip
        self.interface = interface
        self.is_ipv6 = ':' in target_ip

    def sendp(self, pkt):
        """发送数据包"""
        if self.interface:
            sendp(pkt, iface=self.interface, verbose=0)
        else:
            sendp(pkt, verbose=0)

    # ========== IPv4 测试数据包 ==========

    def ipv4_normal(self):
        """IPv4 正常 ICMP 包"""
        pkt = Ether() / IP(dst=self.target_ip) / ICMP()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv4 正常包 -> {self.target_ip}")
        return pkt

    def ipv4_frag_first(self):
        """
        IPv4 首片分片 (offset=0, MF=1)
        应该被 XDP 处理 (包含完整 IP 头)
        """
        # 创建一个会被分片的大数据包
        payload = b'A' * 2000
        pkt = Ether() / IP(dst=self.target_ip, flags='MF') / ICMP() / Raw(payload)

        # 分片
        frags = fragment(pkt, fragsize=1500)
        if len(frags) > 0:
            self.sendp(frags[0])  # 首片
            print(f"[OK] 已发送 IPv4 首片分片 (offset=0) -> {self.target_ip}")
        return frags

    def ipv4_frag_subsequent(self):
        """
        IPv4 后续分片 (offset>0)
        应该被 XDP 丢弃 (无完整 IP 头)
        """
        payload = b'A' * 2000
        pkt = Ether() / IP(dst=self.target_ip, flags='MF') / ICMP() / Raw(payload)

        frags = fragment(pkt, fragsize=1500)
        if len(frags) > 1:
            self.sendp(frags[1])  # 后续片
            print(f"[OK] 已发送 IPv4 后续分片 (offset>0) -> {self.target_ip}")
        return frags

    # ========== IPv6 测试数据包 ==========

    def ipv6_normal(self):
        """IPv6 正常 ICMPv6 包"""
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        pkt = Ether() / IPv6(dst=self.target_ip) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 正常包 -> {self.target_ip}")
        return pkt

    def ipv6_ext_hbh(self):
        """IPv6 带 Hop-by-Hop 扩展头"""
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + Hop-by-Hop 扩展头 -> {self.target_ip}")
        return pkt

    def ipv6_ext_routing(self):
        """IPv6 带 Routing 扩展头"""
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrRouting() / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + Routing 扩展头 -> {self.target_ip}")
        return pkt

    def ipv6_ext_dest(self):
        """IPv6 带 Destination Options 扩展头"""
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrDestOpt() / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + Destination 扩展头 -> {self.target_ip}")
        return pkt

    def ipv6_ext_multiple(self):
        """IPv6 带多个扩展头 (Hop-by-Hop + Routing + Dest)"""
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        pkt = (Ether() / IPv6(dst=self.target_ip) /
                IPv6ExtHdrHopByHop() /
                IPv6ExtHdrRouting() /
                IPv6ExtHdrDestOpt() /
                ICMPv6EchoRequest())
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + 多个扩展头 (3个) -> {self.target_ip}")
        return pkt

    def ipv6_frag_first(self):
        """
        IPv6 Fragment 首片 (offset=0, M=1)
        应该被 XDP 处理
        """
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        # offset=0 表示首片
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrFragment(offset=0, m=1) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 Fragment 首片 (offset=0) -> {self.target_ip}")
        return pkt

    def ipv6_frag_subsequent(self):
        """
        IPv6 Fragment 后续片 (offset>0)
        应该被 XDP 丢弃
        """
        if not self.is_ipv6:
            print(f"[SKIP] 需要目标为 IPv6 地址")
            return None
        # offset=1 表示不是首片 (单位是 8 字节)
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrFragment(offset=1, m=1) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 Fragment 后续片 (offset>0) -> {self.target_ip}")
        return pkt

    # ========== VLAN 测试数据包 ==========

    def vlan_8021q(self):
        """带 802.1Q VLAN 标签的包"""
        pkt = Ether() / Dot1Q(vlan=1) / IP(dst=self.target_ip) / ICMP()
        self.sendp(pkt)
        print(f"[OK] 已发送 802.1Q VLAN 包 -> {self.target_ip}")
        return pkt

    def vlan_qinq(self):
        """带 QinQ (双层 802.1ad) 标签的包"""
        pkt = Ether() / Dot1Q(vlan=1, type=0x88A8) / Dot1Q(vlan=2) / IP(dst=self.target_ip) / ICMP()
        self.sendp(pkt)
        print(f"[OK] 已发送 QinQ VLAN 包 -> {self.target_ip}")
        return pkt


def main():
    parser = argparse.ArgumentParser(
        description='XDP eBPF 测试数据包生成器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
测试场景示例:
  %(prog)s 192.168.1.1 ipv4_normal           # 发送 IPv4 正常包
  %(prog)s 192.168.1.1 ipv4_frag_first       # 发送 IPv4 首片分片
  %(prog)s 192.168.1.1 ipv4_frag_subsequent  # 发送 IPv4 后续分片
  %(prog)s ::1 ipv6_normal                   # 发送 IPv6 正常包
  %(prog)s ::1 ipv6_ext_hbh                  # 发送 IPv6 + Hbh 扩展头
  %(prog)s ::1 ipv6_frag_first               # 发送 IPv6 Fragment 首片
  %(prog)s 192.168.1.1 vlan_8021q            # 发送 VLAN 包

运行所有测试:
  %(prog)s 192.168.1.1 all
        """
    )

    parser.add_argument('target', help='目标 IP 地址 (IPv4 或 IPv6)')
    parser.add_argument('test_type', nargs='?', default='all',
                       help='测试类型 (默认: all)')
    parser.add_argument('-i', '--interface', help='网络接口 (如 eth0, ens33)')
    parser.add_argument('-c', '--count', type=int, default=1,
                       help='发送次数 (默认: 1)')

    args = parser.parse_args()

    gen = PacketGenerator(args.target, args.interface)

    # 定义所有测试类型
    ipv4_tests = [
        ('ipv4_normal', 'IPv4 正常包', gen.ipv4_normal),
        ('ipv4_frag_first', 'IPv4 首片分片', gen.ipv4_frag_first),
        ('ipv4_frag_subsequent', 'IPv4 后续分片', gen.ipv4_frag_subsequent),
    ]

    ipv6_tests = [
        ('ipv6_normal', 'IPv6 正常包', gen.ipv6_normal),
        ('ipv6_ext_hbh', 'IPv6 + Hop-by-Hop', gen.ipv6_ext_hbh),
        ('ipv6_ext_routing', 'IPv6 + Routing', gen.ipv6_ext_routing),
        ('ipv6_ext_dest', 'IPv6 + Destination', gen.ipv6_ext_dest),
        ('ipv6_ext_multiple', 'IPv6 + 多个扩展头', gen.ipv6_ext_multiple),
        ('ipv6_frag_first', 'IPv6 Fragment 首片', gen.ipv6_frag_first),
        ('ipv6_frag_subsequent', 'IPv6 Fragment 后续片', gen.ipv6_frag_subsequent),
    ]

    vlan_tests = [
        ('vlan_8021q', '802.1Q VLAN', gen.vlan_8021q),
        ('vlan_qinq', 'QinQ VLAN', gen.vlan_qinq),
    ]

    # 确定要运行的测试
    tests_to_run = []
    if args.test_type == 'all':
        tests_to_run = ipv4_tests + ipv6_tests + vlan_tests
    else:
        all_tests = ipv4_tests + ipv6_tests + vlan_tests
        for name, desc, func in all_tests:
            if name == args.test_type:
                tests_to_run = [(name, desc, func)]
                break

    if not tests_to_run:
        print(f"[ERROR] 未知的测试类型: {args.test_type}")
        print("\n可用的测试类型:")
        for name, desc, _ in ipv4_tests + ipv6_tests + vlan_tests:
            print(f"  - {name}: {desc}")
        sys.exit(1)

    # 运行测试
    print("=" * 50)
    print(f"XDP eBPF 测试数据包生成器")
    print(f"目标: {args.target}")
    print(f"接口: {args.interface or '默认'}")
    print("=" * 50)

    for _ in range(args.count):
        for name, desc, func in tests_to_run:
            try:
                func()
            except Exception as e:
                print(f"[ERROR] {desc}: {e}")

    print("=" * 50)
    print(f"测试完成! 共发送 {len(tests_to_run) * args.count} 个数据包")


if __name__ == '__main__':
    main()
