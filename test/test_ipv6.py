#!/usr/bin/env python3
"""
IPv6 eBPF 测试数据包生成器

使用 Scapy 构造 IPv6 相关的测试数据包，用于验证 XDP/TC 程序：
- IPv6 正常包
- IPv6 扩展头处理 (Hop-by-Hop, Routing, Destination)
- IPv6 分片处理
- IPv6 畸形包 (用于安全测试/模糊测试)

依赖: pip install scapy
"""

import sys
import argparse
from scapy.all import *

# 禁用 Scapy 的警告
conf.verb = 0


class IPv6PacketGenerator:
    """生成 IPv6 测试数据包"""

    def __init__(self, target_ip, interface=None, mtu=1500):
        """
        初始化数据包生成器
        :param target_ip: 目标 IPv6 地址
        :param interface: 网络接口名称 (如 eth0, ens33)
        :param mtu: 路径 MTU (默认 1500)
        """
        self.target_ip = target_ip
        self.interface = interface
        self.mtu = mtu
        self.fragsize = mtu - 14  # 减去以太网头 (14 字节)

    def sendp(self, pkt):
        """发送数据包"""
        if self.interface:
            sendp(pkt, iface=self.interface, verbose=0)
        else:
            sendp(pkt, verbose=0)

    # ========== IPv6 正常测试 ==========

    def ipv6_normal(self):
        """IPv6 正常 ICMPv6 包"""
        pkt = Ether() / IPv6(dst=self.target_ip) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 正常包 -> {self.target_ip}")
        return pkt

    def ipv6_ext_hbh(self):
        """IPv6 带 Hop-by-Hop 扩展头"""
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + Hop-by-Hop 扩展头 -> {self.target_ip}")
        return pkt

    def ipv6_ext_routing(self):
        """IPv6 带 Routing 扩展头"""
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrRouting() / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + Routing 扩展头 -> {self.target_ip}")
        return pkt

    def ipv6_ext_dest(self):
        """IPv6 带 Destination Options 扩展头"""
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrDestOpt() / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + Destination 扩展头 -> {self.target_ip}")
        return pkt

    def ipv6_ext_multiple(self):
        """IPv6 带多个扩展头 (Hop-by-Hop + Routing + Dest)"""
        pkt = (Ether() / IPv6(dst=self.target_ip) /
                IPv6ExtHdrHopByHop() /
                IPv6ExtHdrRouting() /
                IPv6ExtHdrDestOpt() /
                ICMPv6EchoRequest())
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + 多个扩展头 (3个) -> {self.target_ip}")
        return pkt

    # ========== IPv6 畸形包测试 ==========

    def ipv6_malformed_max_hop_limit(self):
        """
        IPv6 with maximum Hop Limit (255)
        测试 XDP 程序对边界值的处理
        """
        pkt = Ether() / IPv6(dst=self.target_ip, hlim=255) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 Hop Limit=255 包 -> {self.target_ip}")
        return pkt

    def ipv6_malformed_too_many_headers(self):
        """
        IPv6 with more than 8 extension headers
        eBPF 程序最多处理 8 个扩展头
        """
        pkt = (Ether() / IPv6(dst=self.target_ip) /
                IPv6ExtHdrHopByHop() /
                IPv6ExtHdrRouting() /
                IPv6ExtHdrDestOpt() /
                IPv6ExtHdrHopByHop() /
                IPv6ExtHdrRouting() /
                IPv6ExtHdrDestOpt() /
                IPv6ExtHdrHopByHop() /
                IPv6ExtHdrRouting() /  # 9th extension header
                ICMPv6EchoRequest())
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 + 9个扩展头 -> {self.target_ip}")
        print("[注意] eBPF 程序可能会丢弃超过 8 个扩展头的包")
        return pkt

    def ipv6_malformed_oversized(self):
        """
        IPv6 jumbo frame (超过配置的 MTU)
        此包可能在发送时被分片或被中间设备丢弃
        """
        payload_size = self.mtu + 500  # 超过 MTU 500 字节
        payload = b'X' * payload_size
        pkt = Ether() / IPv6(dst=self.target_ip) / ICMPv6EchoRequest() / Raw(payload)
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 超大包 ({payload_size} bytes, MTU={self.mtu}) -> {self.target_ip}")
        print("[注意] 此包可能在发送时被分片或被中间设备丢弃")
        return pkt

    def ipv6_malformed_zero_length(self):
        """
        IPv6 with zero payload length (invalid)
        """
        pkt = Ether() / IPv6(dst=self.target_ip, plen=0) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 零负载长度包 -> {self.target_ip}")
        return pkt

    def ipv6_malformed_bad_version(self):
        """
        IPv6 with incorrect version field
        IPv6 应该是版本 6，这里设置为 7
        """
        # Scapy 的 IPv6 类不支持直接设置 version，需要手动构造
        pkt = Ether() / IPv6(dst=self.target_ip) / ICMPv6EchoRequest()
        # 修改版本字段 (version 在前 4 位)
        pkt[IPv6].version = 7
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 错误版本包 (version=7) -> {self.target_ip}")
        return pkt

    def ipv6_malformed_fragment_offset(self):
        """
        IPv6 Fragment with invalid offset (not aligned to 8 bytes)
        Fragment offset 必须是 8 字节的倍数
        """
        # offset=3 不是 8 的倍数，无效
        pkt = Ether() / IPv6(dst=self.target_ip) / IPv6ExtHdrFragment(offset=3, m=1) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 Fragment 无效偏移包 (offset=3) -> {self.target_ip}")
        return pkt

    def ipv6_malformed_large_traffic_class(self):
        """
        IPv6 with maximum traffic class (used for QoS)
        测试 XDP 程序对 traffic class 字段的处理
        """
        pkt = Ether() / IPv6(dst=self.target_ip, tc=0xFF) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 Traffic Class=0xFF 包 -> {self.target_ip}")
        return pkt

    def ipv6_malformed_flow_label(self):
        """
        IPv6 with non-zero flow label
        测试 XDP 程序对 flow label 字段的处理
        """
        pkt = Ether() / IPv6(dst=self.target_ip, fl=0xFFFFF) / ICMPv6EchoRequest()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv6 Flow Label=0xFFFFF 包 -> {self.target_ip}")
        return pkt


def main():
    parser = argparse.ArgumentParser(
        description='IPv6 eBPF 测试数据包生成器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
测试场景示例:
  %(prog)s ::1 ipv6_normal                      # 发送 IPv6 正常包
  %(prog)s ::1 ipv6_ext_hbh                     # 发送 IPv6 + Hbh 扩展头
  %(prog)s ::1 ipv6_frag_first                  # 发送 IPv6 Fragment 首片
  %(prog)s ::1 ipv6_malformed_too_many_headers  # 发送 9 个扩展头
  %(prog)s 2001:db8::1 all --mtu 1492           # 公网测试 (PPPoE)

运行所有测试:
  %(prog)s ::1 all

MTU 参考:
  - 以太网默认: 1500 (默认值)
  - PPPoE: 1492 (--mtu 1492)
  - VPN/GRE: 1400 (--mtu 1400)
        """
    )

    parser.add_argument('target', help='目标 IPv6 地址')
    parser.add_argument('test_type', nargs='?', default='all',
                       help='测试类型 (默认: all)')
    parser.add_argument('-i', '--interface', default='ens33',
                       help='网络接口 (如 eth0, ens33)')
    parser.add_argument('--mtu', type=int, default=1500,
                       help='路径 MTU 用于分片计算 (默认: 1500). PPPoE使用1492, VPN使用1400')
    parser.add_argument('-c', '--count', type=int, default=1,
                       help='发送次数 (默认: 1)')

    args = parser.parse_args()

    gen = IPv6PacketGenerator(args.target, args.interface, args.mtu)

    # 定义所有测试类型
    normal_tests = [
        ('ipv6_normal', 'IPv6 正常包', gen.ipv6_normal),
        ('ipv6_ext_hbh', 'IPv6 + Hop-by-Hop', gen.ipv6_ext_hbh),
        ('ipv6_ext_routing', 'IPv6 + Routing', gen.ipv6_ext_routing),
        ('ipv6_ext_dest', 'IPv6 + Destination', gen.ipv6_ext_dest),
        ('ipv6_ext_multiple', 'IPv6 + 多个扩展头', gen.ipv6_ext_multiple),
    ]

    malformed_tests = [
        ('ipv6_malformed_max_hop_limit', 'IPv6 Hop Limit=255', gen.ipv6_malformed_max_hop_limit),
        ('ipv6_malformed_too_many_headers', 'IPv6 9个扩展头', gen.ipv6_malformed_too_many_headers),
        ('ipv6_malformed_oversized', 'IPv6 超大包', gen.ipv6_malformed_oversized),
        ('ipv6_malformed_zero_length', 'IPv6 零负载长度', gen.ipv6_malformed_zero_length),
        ('ipv6_malformed_bad_version', 'IPv6 错误版本', gen.ipv6_malformed_bad_version),
        ('ipv6_malformed_fragment_offset', 'IPv6 Fragment 无效偏移', gen.ipv6_malformed_fragment_offset),
        ('ipv6_malformed_large_traffic_class', 'IPv6 Traffic Class=0xFF', gen.ipv6_malformed_large_traffic_class),
        ('ipv6_malformed_flow_label', 'IPv6 Flow Label=0xFFFFF', gen.ipv6_malformed_flow_label),
    ]

    # 确定要运行的测试
    tests_to_run = []
    if args.test_type == 'all':
        tests_to_run = normal_tests + malformed_tests
    elif args.test_type == 'normal':
        tests_to_run = normal_tests
    elif args.test_type == 'malformed':
        tests_to_run = malformed_tests
    else:
        all_tests = normal_tests + malformed_tests
        for name, desc, func in all_tests:
            if name == args.test_type:
                tests_to_run = [(name, desc, func)]
                break

    if not tests_to_run:
        print(f"[ERROR] 未知的测试类型: {args.test_type}")
        print("\n可用的测试类型:")
        print("  组合:")
        print("    - all: 所有测试")
        print("    - normal: 正常测试")
        print("    - malformed: 畸形包测试")
        print("\n  单个测试:")
        for name, desc, _ in normal_tests + malformed_tests:
            print(f"    - {name}: {desc}")
        sys.exit(1)

    # 运行测试
    print("=" * 50)
    print(f"IPv6 eBPF 测试数据包生成器")
    print(f"目标: {args.target}")
    print(f"接口: {args.interface or '默认'}")
    print(f"MTU: {args.mtu} (分片大小: {args.mtu - 14})")
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
