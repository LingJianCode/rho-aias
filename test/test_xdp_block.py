#!/usr/bin/env python3
"""
eBPF XDP IP 阻断功能集成测试
使用 network namespace 模拟网络环境测试 XDP 阻断效果

使用前需确保:
1. 已编译 rho-aias 程序
2. 以 root 权限运行
3. 系统支持 eBPF XDP

测试项目:
- IPv4 精确匹配阻断
- IPv4 CIDR 阻断
- 规则添加/删除 API
- 阻断效果验证
"""

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
import unittest
from typing import Optional, Tuple
from netns import NetNS, VethPair, TestEnvironment

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RhoAiasProcess:
    """rho-aias 进程管理类"""
    
    def __init__(self, binary_path: str, default_config_path: str, interface: str, api_port: int = 18080):
        self.binary_path = binary_path
        self.default_config_path = default_config_path
        self.interface = interface
        self.api_port = api_port
        self.process: Optional[subprocess.Popen] = None
        self.config_dir = "/tmp/rho_test"
        self.log_dir = "/tmp/rho_test_logs"
        self.log_file = None
        self.log_path = None
    
    def start(self) -> bool:
        """启动 rho-aias 进程"""
        if not os.path.exists(self.binary_path):
            logger.error(f"Binary not found: {self.binary_path}")
            return False

        # 创建临时配置目录
        os.makedirs(self.config_dir, exist_ok=True)
        config_file = os.path.join(self.config_dir, "config.yml")

        # 创建日志目录
        os.makedirs(self.log_dir, exist_ok=True)

        # 生成带时间戳的日志文件名
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(self.log_dir, f"rho-aias_{timestamp}.log")

        # 读取默认配置文件
        try:
            with open(self.default_config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load default config: {e}")
            return False

        # 覆盖测试所需的配置项
        config['server']['port'] = self.api_port
        config['ebpf']['interface_name'] = self.interface

        # 禁用外部数据源（测试环境）
        config['intel']['enabled'] = True
        config['geo_blocking']['enabled'] = True
        config['manual']['enabled'] = True  # 保留手动规则功能用于测试
        config['auth']['enabled'] = False

        # 写入临时配置文件
        try:
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            logger.error(f"Failed to write temp config: {e}")
            return False

        logger.info(f"Starting rho-aias on interface {self.interface}...")
        logger.info(f"Log will be saved to: {self.log_path}")

        try:
            # 打开日志文件
            self.log_file = open(self.log_path, 'w')
            # 在配置文件所在目录运行程序，输出到日志文件
            self.process = subprocess.Popen(
                [self.binary_path],
                cwd=self.config_dir,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,  # stderr 合并到 stdout
                preexec_fn=os.setsid
            )

            # 等待服务启动
            time.sleep(3)

            if self.process.poll() is not None:
                logger.error(f"Process exited unexpectedly. Check log: {self.log_path}")
                return False

            logger.info(f"rho-aias started (PID: {self.process.pid})")
            return True

        except Exception as e:
            logger.error(f"Failed to start rho-aias: {e}")
            if self.log_file:
                self.log_file.close()
            return False
    
    def stop(self):
        """停止 rho-aias 进程"""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
                logger.info("rho-aias stopped")
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                logger.info("rho-aias killed")
            except Exception as e:
                logger.error(f"Error stopping process: {e}")
            finally:
                self.process = None

        # 关闭日志文件
        if self.log_file:
            try:
                self.log_file.close()
                logger.info(f"Log saved to: {self.log_path}")
            except Exception as e:
                logger.error(f"Error closing log file: {e}")
            finally:
                self.log_file = None

        # 清理临时配置目录（但不删除日志目录）
        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)


class APIClient:
    """rho-aias API 客户端"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def add_rule(self, value: str) -> Tuple[bool, dict]:
        """添加阻断规则"""
        return self._request("POST", "/api/manual/rules", {"value": value})
    
    def delete_rule(self, value: str) -> Tuple[bool, dict]:
        """删除阻断规则"""
        return self._request("DELETE", "/api/manual/rules", {"value": value})
    
    def get_rules(self, source: str = None) -> Tuple[bool, dict]:
        """获取规则列表"""
        url = "/api/manual/rules"
        if source:
            url += f"?source={source}"
        return self._request("GET", url)
    
    def _request(self, method: str, path: str, data: dict = None) -> Tuple[bool, dict]:
        """发送 HTTP 请求"""
        import urllib.request
        import urllib.error
        
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        
        try:
            if method == "GET":
                req = urllib.request.Request(url, headers=headers)
            else:
                body = json.dumps(data).encode() if data else b""
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                return True, result
        except urllib.error.HTTPError as e:
            try:
                result = json.loads(e.read().decode())
                return False, result
            except:
                return False, {"error": str(e)}
        except Exception as e:
            return False, {"error": str(e)}


class TestXDPIpBlocking(unittest.TestCase):
    """XDP IP 阻断功能测试"""
    
    @classmethod
    def setUpClass(cls):
        """测试类初始化"""
        # 检查 root 权限
        if os.geteuid() != 0:
            raise unittest.SkipTest("This test requires root privileges")
        
        cls.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.binary_path = os.path.join(cls.project_root, "rho-aias")
        cls.default_config_path = os.path.join(cls.project_root, "config.yml")
        cls.api_port = 18080
        cls.api_client = APIClient(f"http://127.0.0.1:{cls.api_port}")
        
        # 检查二进制文件
        if not os.path.exists(cls.binary_path):
            raise unittest.SkipTest(f"Binary not found: {cls.binary_path}. Run 'make build' first.")
        
        # 检查默认配置文件
        if not os.path.exists(cls.default_config_path):
            raise unittest.SkipTest(f"Default config not found: {cls.default_config_path}")
    
    def setUp(self):
        """每个测试前的准备工作"""
        self.env = TestEnvironment("rho_xdt")  # 短前缀以避免接口名超过15字符限制
        self.rho_process: Optional[RhoAiasProcess] = None
        
        # 设置网络环境
        if not self.env.setup():
            self.skipTest("Failed to setup test environment")
        
        logger.info(f"Test environment ready: ns1={self.env.ns1.name}, ns2={self.env.ns2.name}")
    
    def tearDown(self):
        """每个测试后的清理工作"""
        # 停止 rho-aias
        if self.rho_process:
            self.rho_process.stop()
        
        # 清理网络环境
        self.env.cleanup()
        
        # 等待资源释放
        time.sleep(1)
    
    def _start_rho_on_veth(self, veth_name: str) -> bool:
        """在指定 veth 上启动 rho-aias"""
        self.rho_process = RhoAiasProcess(
            self.binary_path,
            self.default_config_path,
            veth_name,
            self.api_port
        )
        return self.rho_process.start()
    
    def test_01_ipv4_exact_block(self):
        """测试 IPv4 精确匹配阻断"""
        # 启动 rho-aias (绑定到 veth0)
        self.assertTrue(
            self._start_rho_on_veth("rho_xdt_veth0"),
            "Failed to start rho-aias"
        )
        
        # 验证初始连通性
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertTrue(success, "Initial connectivity check failed")
        logger.info("Initial connectivity OK")
        
        # 添加阻断规则
        success, resp = self.api_client.add_rule("10.0.1.2")
        self.assertTrue(success, f"Failed to add rule: {resp}")
        logger.info("Added block rule for 10.0.1.2")
        
        # 等待规则生效
        time.sleep(1)
        
        # 验证阻断效果
        success, output = self.env.ping_from_main("10.0.1.2", count=3)
        self.assertFalse(success, f"Block rule not effective, ping succeeded: {output}")
        logger.info("Block rule effective - packets dropped")
        
        # 删除阻断规则
        success, resp = self.api_client.delete_rule("10.0.1.2")
        self.assertTrue(success, f"Failed to delete rule: {resp}")
        logger.info("Deleted block rule for 10.0.1.2")
        
        # 等待规则删除生效
        time.sleep(1)
        
        # 验证连通性恢复
        success, _ = self.env.ping_from_main("10.0.1.2", count=3)
        self.assertTrue(success, "Connectivity not restored after deleting rule")
        logger.info("Connectivity restored")
    
    def test_02_ipv4_cidr_block(self):
        """测试 IPv4 CIDR 阻断"""
        # 启动 rho-aias
        self.assertTrue(
            self._start_rho_on_veth("rho_xdt_veth0"),
            "Failed to start rho-aias"
        )
        
        # 验证初始连通性
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertTrue(success, "Initial connectivity check failed")
        
        # 添加 CIDR 阻断规则 (10.0.1.0/24)
        success, resp = self.api_client.add_rule("10.0.1.0/24")
        self.assertTrue(success, f"Failed to add CIDR rule: {resp}")
        logger.info("Added block rule for 10.0.1.0/24")
        
        # 等待规则生效
        time.sleep(1)
        
        # 验证阻断效果
        success, output = self.env.ping_from_main("10.0.1.2", count=3)
        self.assertFalse(success, f"CIDR block not effective: {output}")
        logger.info("CIDR block effective")
        
        # 删除规则
        success, resp = self.api_client.delete_rule("10.0.1.0/24")
        self.assertTrue(success, f"Failed to delete CIDR rule: {resp}")
        
        # 验证连通性恢复
        time.sleep(1)
        success, _ = self.env.ping_from_main("10.0.1.2", count=3)
        self.assertTrue(success, "Connectivity not restored after CIDR rule deletion")
    
    def test_03_multiple_rules(self):
        """测试多条规则"""
        # 启动 rho-aias
        self.assertTrue(
            self._start_rho_on_veth("rho_xdt_veth0"),
            "Failed to start rho-aias"
        )
        
        # 添加多条规则
        rules = ["10.0.1.2", "10.0.2.2", "192.168.100.1"]
        for rule in rules:
            success, resp = self.api_client.add_rule(rule)
            self.assertTrue(success, f"Failed to add rule {rule}: {resp}")
        
        logger.info(f"Added {len(rules)} rules")
        
        # 查询规则
        success, resp = self.api_client.get_rules()
        self.assertTrue(success, f"Failed to get rules: {resp}")
        
        # 验证规则数量
        if "data" in resp and "total" in resp["data"]:
            self.assertGreaterEqual(resp["data"]["total"], len(rules))
        
        logger.info(f"Current rule count: {resp}")
        
        # 验证阻断效果
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertFalse(success, "Block rule for 10.0.1.2 not effective")
        
        # 删除所有规则
        for rule in rules:
            self.api_client.delete_rule(rule)
        
        logger.info("All rules deleted")
    
    def test_04_rule_persistence(self):
        """测试规则 API 持久性"""
        # 启动 rho-aias
        self.assertTrue(
            self._start_rho_on_veth("rho_xdt_veth0"),
            "Failed to start rho-aias"
        )
        
        # 添加规则
        test_ip = "10.0.1.100"
        success, resp = self.api_client.add_rule(test_ip)
        self.assertTrue(success, f"Failed to add rule: {resp}")
        
        # 验证规则存在
        success, resp = self.api_client.get_rules()
        self.assertTrue(success, f"Failed to get rules: {resp}")
        
        # 尝试重复添加同一规则
        success, resp = self.api_client.add_rule(test_ip)
        # 重复添加应该成功（更新操作）
        self.assertTrue(success, f"Duplicate add failed: {resp}")
        
        # 删除不存在的规则
        success, resp = self.api_client.delete_rule("1.2.3.4")
        # 删除不存在的规则可能返回错误或静默成功
        logger.info(f"Delete non-existent rule result: {resp}")
    
    def test_05_invalid_rule(self):
        """测试无效规则处理"""
        # 启动 rho-aias
        self.assertTrue(
            self._start_rho_on_veth("rho_xdt_veth0"),
            "Failed to start rho-aias"
        )
        
        # 尝试添加无效规则
        invalid_rules = [
            "invalid-ip",
            "999.999.999.999",
            "",
            "not.an.ip.address"
        ]
        
        for rule in invalid_rules:
            success, resp = self.api_client.add_rule(rule)
            self.assertFalse(success, f"Invalid rule '{rule}' should be rejected")
            logger.info(f"Invalid rule '{rule}' correctly rejected: {resp}")


class TestEnvironmentSetup(unittest.TestCase):
    """测试环境设置测试（不需要 rho-aias）"""
    
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("This test requires root privileges")
        self.env = TestEnvironment("rho_et")  # 短前缀以避免接口名超过15字符限制
    
    def tearDown(self):
        self.env.cleanup()
    
    def test_namespace_creation(self):
        """测试 namespace 创建和删除"""
        ns = NetNS("test_ns_temp")
        self.assertTrue(ns.create(), "Failed to create namespace")
        self.assertTrue(ns.delete(), "Failed to delete namespace")
    
    def test_veth_pair_creation(self):
        """测试 veth pair 创建"""
        ns = NetNS("test_ns_veth")
        self.assertTrue(ns.create(), "Failed to create namespace")
        
        veth = VethPair("test_veth0", "test_veth1", ns)
        self.assertTrue(veth.create(), "Failed to create veth pair")
        self.assertTrue(veth.set_ip("192.168.100.1", "192.168.100.2"), "Failed to set IP")
        self.assertTrue(veth.up(), "Failed to bring up veth")
        
        # 清理
        veth.delete()
        ns.delete()
    
    def test_full_environment(self):
        """测试完整环境设置"""
        self.assertTrue(self.env.setup(), "Failed to setup test environment")
        
        # 测试连通性
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertTrue(success, "Cannot reach ns1")
        
        success, _ = self.env.ping_from_main("10.0.2.2", count=2)
        self.assertTrue(success, "Cannot reach ns2")


def run_tests(test_pattern: str = None):
    """运行测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    if test_pattern:
        suite.addTests(loader.loadTestsFromName(f"__main__.{test_pattern}"))
    else:
        suite.addTests(loader.loadTestsFromModule(sys.modules[__name__]))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="eBPF XDP IP Blocking Integration Tests")
    parser.add_argument(
        "-t", "--test",
        help="Run specific test (e.g., TestXDPIpBlocking.test_01_ipv4_exact_block)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--env-only",
        action="store_true",
        help="Only run environment setup tests (no rho-aias required)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.env_only:
        sys.exit(run_tests("TestEnvironmentSetup"))
    elif args.test:
        sys.exit(run_tests(args.test))
    else:
        sys.exit(run_tests())
