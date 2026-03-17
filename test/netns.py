#!/usr/bin/env python3
"""
Network Namespace 管理模块
用于创建和管理测试用的网络命名空间环境
"""

import subprocess
import time
import logging
from typing import Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetNS:
    """Network Namespace 管理类"""
    
    def __init__(self, name: str):
        self.name = name
        self._created = False
    
    def create(self) -> bool:
        """创建 network namespace"""
        # 先尝试删除可能存在的旧 namespace
        self._run_cmd(f"ip netns del {self.name}", check=False)
        
        result = self._run_cmd(f"ip netns add {self.name}")
        if result:
            self._created = True
            logger.info(f"Created network namespace: {self.name}")
        return result
    
    def delete(self) -> bool:
        """删除 network namespace"""
        if not self._created:
            return True
        result = self._run_cmd(f"ip netns del {self.name}")
        if result:
            self._created = False
            logger.info(f"Deleted network namespace: {self.name}")
        return result
    
    def exec_cmd(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """在 namespace 中执行命令"""
        full_cmd = f"ip netns exec {self.name} {cmd}"
        return self._run_cmd_with_output(full_cmd, timeout)
    
    def set_loopback_up(self) -> bool:
        """启用 loopback 接口"""
        return self._run_cmd(f"ip netns exec {self.name} ip link set lo up")
    
    def _run_cmd(self, cmd: str, check: bool = True) -> bool:
        """执行 shell 命令"""
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=30)
            return True
        except subprocess.CalledProcessError as e:
            if check:
                logger.error(f"Command failed: {cmd}, error: {e.stderr.decode()}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {cmd}")
            return False
    
    def _run_cmd_with_output(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """执行命令并返回输出"""
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=timeout)
            return True, result.stdout.decode()
        except subprocess.CalledProcessError as e:
            return False, e.stderr.decode()
        except subprocess.TimeoutExpired:
            return False, "Command timeout"


class VethPair:
    """Veth Pair 管理类"""
    
    def __init__(self, name: str, peer: str, netns: NetNS):
        self.name = name      # 主 namespace 中的设备名
        self.peer = peer      # 目标 namespace 中的设备名
        self.netns = netns
        self._created = False
    
    def create(self) -> bool:
        """创建 veth pair"""
        # 先删除可能存在的旧设备
        self._run_cmd(f"ip link del {self.name}", check=False)
        
        # 创建 veth pair
        if not self._run_cmd(f"ip link add {self.name} type veth peer name {self.peer}"):
            return False
        
        # 将 peer 移动到目标 namespace
        if not self._run_cmd(f"ip link set {self.peer} netns {self.netns.name}"):
            self._run_cmd(f"ip link del {self.name}", check=False)
            return False
        
        self._created = True
        logger.info(f"Created veth pair: {self.name} <-> {self.peer}@{self.netns.name}")
        return True
    
    def delete(self) -> bool:
        """删除 veth pair"""
        if not self._created:
            return True
        # 删除主 namespace 中的设备会自动删除另一端
        result = self._run_cmd(f"ip link del {self.name}", check=False)
        if result:
            self._created = False
            logger.info(f"Deleted veth pair: {self.name}")
        return result
    
    def set_ip(self, main_ip: str, peer_ip: str, prefix: int = 24) -> bool:
        """设置 IP 地址"""
        # 设置主 namespace 中设备的 IP
        if not self._run_cmd(f"ip addr add {main_ip}/{prefix} dev {self.name}"):
            return False
        
        # 设置 namespace 中设备的 IP
        if not self._run_cmd(f"ip netns exec {self.netns.name} ip addr add {peer_ip}/{prefix} dev {self.peer}"):
            return False
        
        logger.info(f"Set IP: {self.name}={main_ip}/{prefix}, {self.peer}={peer_ip}/{prefix}")
        return True
    
    def up(self) -> bool:
        """启用设备"""
        # 启用主 namespace 中的设备
        if not self._run_cmd(f"ip link set {self.name} up"):
            return False
        
        # 启用 namespace 中的设备
        if not self._run_cmd(f"ip netns exec {self.netns.name} ip link set {self.peer} up"):
            return False
        
        logger.info(f"Brought up veth pair: {self.name}")
        return True
    
    def _run_cmd(self, cmd: str, check: bool = True) -> bool:
        """执行 shell 命令"""
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=30)
            return True
        except subprocess.CalledProcessError as e:
            if check:
                logger.error(f"Command failed: {cmd}, error: {e.stderr.decode()}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {cmd}")
            return False


class TestEnvironment:
    """测试环境管理类"""
    
    def __init__(self, prefix: str = "rho_test"):
        self.prefix = prefix
        self.ns1: Optional[NetNS] = None
        self.ns2: Optional[NetNS] = None
        self.veth1: Optional[VethPair] = None
        self.veth2: Optional[VethPair] = None
    
    def setup(self) -> bool:
        """设置测试环境"""
        logger.info("Setting up test environment...")
        
        # 创建两个 namespace
        self.ns1 = NetNS(f"{self.prefix}_ns1")
        self.ns2 = NetNS(f"{self.prefix}_ns2")
        
        if not self.ns1.create():
            return False
        if not self.ns2.create():
            self.ns1.delete()
            return False
        
        # 启用 loopback
        self.ns1.set_loopback_up()
        self.ns2.set_loopback_up()
        
        # 创建 veth pair 连接主 namespace 和 ns1
        self.veth1 = VethPair(f"{self.prefix}_veth0", f"{self.prefix}_veth1", self.ns1)
        if not self.veth1.create():
            self.cleanup()
            return False
        
        if not self.veth1.set_ip("10.0.1.1", "10.0.1.2"):
            self.cleanup()
            return False
        
        if not self.veth1.up():
            self.cleanup()
            return False
        
        # 创建 veth pair 连接主 namespace 和 ns2
        self.veth2 = VethPair(f"{self.prefix}_veth2", f"{self.prefix}_veth3", self.ns2)
        if not self.veth2.create():
            self.cleanup()
            return False
        
        if not self.veth2.set_ip("10.0.2.1", "10.0.2.2"):
            self.cleanup()
            return False
        
        if not self.veth2.up():
            self.cleanup()
            return False
        
        logger.info("Test environment setup complete")
        return True
    
    def cleanup(self):
        """清理测试环境"""
        logger.info("Cleaning up test environment...")
        
        if self.veth1:
            self.veth1.delete()
        if self.veth2:
            self.veth2.delete()
        if self.ns1:
            self.ns1.delete()
        if self.ns2:
            self.ns2.delete()
        
        logger.info("Test environment cleaned up")
    
    def ping_from_ns(self, ns: NetNS, target_ip: str, count: int = 3, timeout: float = 2.0) -> Tuple[bool, str]:
        """从指定 namespace ping 目标 IP"""
        cmd = f"ping -c {count} -W {timeout} {target_ip}"
        success, output = ns.exec_cmd(cmd, timeout=int(count * timeout + 5))
        return success, output
    
    def ping_from_main(self, target_ip: str, count: int = 3, timeout: float = 2.0) -> Tuple[bool, str]:
        """从主 namespace ping 目标 IP"""
        cmd = f"ping -c {count} -W {timeout} {target_ip}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=int(count * timeout + 5))
            return result.returncode == 0, result.stdout.decode()
        except subprocess.TimeoutExpired:
            return False, "Ping timeout"
        except Exception as e:
            return False, str(e)


if __name__ == "__main__":
    # 测试 network namespace 功能
    env = TestEnvironment("test_rho")
    try:
        if env.setup():
            print("Environment setup successful!")
            
            # 测试连通性
            success, output = env.ping_from_ns(env.ns1, "10.0.1.1")
            print(f"Ping 10.0.1.1 from ns1: {'OK' if success else 'FAILED'}")
            
            success, output = env.ping_from_main("10.0.1.2")
            print(f"Ping 10.0.1.2 from main: {'OK' if success else 'FAILED'}")
            
            time.sleep(1)
    finally:
        env.cleanup()
