#!/usr/bin/env python3
"""
IPv4 eBPF 测试数据包生成器

使用 Scapy 构造 IPv4 相关的测试数据包，用于验证 XDP/TC 程序：
- IPv4 正常包
- IPv4 分片处理
- VLAN 标签 (802.1Q / QinQ)
- IPv4 畸形包 (用于安全测试/模糊测试)

依赖: pip install scapy
"""

import sys
import argparse
from scapy.all import *

# 禁用 Scapy 的警告
conf.verb = 0


class IPv4PacketGenerator:
    """生成 IPv4 测试数据包"""

    def __init__(self, target_ip, interface=None, mtu=1500):
        """
        初始化数据包生成器
        :param target_ip: 目标 IPv4 地址
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

    # ========== IPv4 畸形包测试 ==========

    def ipv4_malformed_short_header(self):
        """
        IPv4 with truncated IHL (invalid header length)
        IHL=5 表示 20 字节 (最小值)，设置为 4 使其无效
        """
        pkt = Ether() / IP(dst=self.target_ip, ihl=4) / ICMP()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv4 截断头包 (IHL=4) -> {self.target_ip}")
        return pkt

    def ipv4_malformed_invalid_proto(self):
        """
        IPv4 with invalid protocol number
        255 是保留协议号
        """
        pkt = Ether() / IP(dst=self.target_ip, proto=255) / Raw(load=b'test')
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv4 无效协议包 (proto=255) -> {self.target_ip}")
        return pkt

    def ipv4_malformed_oversized(self):
        """
        IPv4 jumbo frame (超过配置的 MTU)
        使用 fragment() 分片后发送，测试 XDP 对分片的处理
        发送超大 IPv4 包的第一个分片
        """
        payload_size = self.mtu + 500  # 超过 MTU 500 字节
        payload = b'X' * payload_size
        pkt = Ether() / IP(dst=self.target_ip) / ICMP() / Raw(payload)

        # 分片并发送第一片
        frags = fragment(pkt, fragsize=self.fragsize)
        if len(frags) > 0:
            self.sendp(frags[0])
            print(f"[OK] 已发送 IPv4 超大包分片1 ({payload_size} bytes payload, MTU={self.mtu}) -> {self.target_ip}")
        return frags

    def ipv4_malformed_zero_length(self):
        """
        IPv4 with zero total length (invalid)
        """
        pkt = Ether() / IP(dst=self.target_ip, len=0) / Raw(load=b'test')
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv4 零长度包 -> {self.target_ip}")
        return pkt

    def ipv4_malformed_bad_version(self):
        """
        IPv4 with incorrect version field
        IPv4 应该是版本 4，这里设置为 5 (IPv5 从未存在)
        """
        pkt = Ether() / IP(dst=self.target_ip, version=5) / ICMP()
        self.sendp(pkt)
        print(f"[OK] 已发送 IPv4 错误版本包 (version=5) -> {self.target_ip}")
        return pkt


def main():
    parser = argparse.ArgumentParser(
        description='IPv4 eBPF 测试数据包生成器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
测试场景示例:
  %(prog)s 192.168.1.1 ipv4_normal                 # 发送 IPv4 正常包
  %(prog)s 192.168.1.1 ipv4_frag_first             # 发送 IPv4 首片分片
  %(prog)s 192.168.1.1 ipv4_malformed_oversized    # 发送 IPv4 超大包
  %(prog)s 192.168.1.1 vlan_8021q                  # 发送 VLAN 包
  %(prog)s 1.2.3.4 all --mtu 1492                  # 公网测试 (PPPoE)

运行所有测试:
  %(prog)s 192.168.1.1 all

MTU 参考:
  - 以太网默认: 1500 (默认值)
  - PPPoE: 1492 (--mtu 1492)
  - VPN/GRE: 1400 (--mtu 1400)
        """
    )

    parser.add_argument('target', help='目标 IPv4 地址')
    parser.add_argument('test_type', nargs='?', default='all',
                       help='测试类型 (默认: all)')
    parser.add_argument('-i', '--interface', default='ens33',
                       help='网络接口 (如 eth0, ens33)')
    parser.add_argument('--mtu', type=int, default=1500,
                       help='路径 MTU 用于分片计算 (默认: 1500). PPPoE使用1492, VPN使用1400')
    parser.add_argument('-c', '--count', type=int, default=1,
                       help='发送次数 (默认: 1)')

    args = parser.parse_args()

    gen = IPv4PacketGenerator(args.target, args.interface, args.mtu)

    malformed_tests = [
        ('ipv4_malformed_short_header', 'IPv4 截断头', gen.ipv4_malformed_short_header),
        ('ipv4_malformed_invalid_proto', 'IPv4 无效协议', gen.ipv4_malformed_invalid_proto),
        ('ipv4_malformed_oversized', 'IPv4 超大包', gen.ipv4_malformed_oversized),
        ('ipv4_malformed_zero_length', 'IPv4 零长度', gen.ipv4_malformed_zero_length),
        ('ipv4_malformed_bad_version', 'IPv4 错误版本', gen.ipv4_malformed_bad_version),
    ]
    # 运行测试
    print("=" * 50)
    print(f"IPv4 eBPF 测试数据包生成器")
    print(f"目标: {args.target}")
    print(f"接口: {args.interface or '默认'}")
    print(f"MTU: {args.mtu} (分片大小: {args.mtu - 14})")
    print("=" * 50)

    for _ in range(args.count):
        for name, desc, func in malformed_tests:
            try:
                func()
            except Exception as e:
                print(f"[ERROR] {desc}: {e}")

    print("=" * 50)
    print(f"测试完成! 共发送 {len(malformed_tests) * args.count} 个数据包")


if __name__ == '__main__':
    main()
