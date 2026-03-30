#!/usr/bin/env python3
"""
DDoS 检测功能集成测试
使用 network namespace 模拟 DDoS 攻击场景

测试项目:
- TCP SYN Flood 检测
- UDP Flood 检测
- ICMP Flood 检测
- ACK Flood 检测

运行示例:
    python3 test_ddos_detection.py
    python3 test_ddos_detection.py --test TestDDoSDetection.test_tcp_syn_flood
"""

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
import threading
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

    def __init__(self, binary_path: str, default_config_path: str, interface: str,
                 api_port: int = 18080, enable_anomaly: bool = True):
        self.binary_path = binary_path
        self.default_config_path = default_config_path
        self.interface = interface
        self.api_port = api_port
        self.enable_anomaly = enable_anomaly
        self.process: Optional[subprocess.Popen] = None
        self.config_dir = "/tmp/rho_ddos_test"
        self.log_dir = "/tmp/rho_ddos_test_logs"
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
        self.log_path = os.path.join(self.log_dir, f"rho-aias_ddos_{timestamp}.log")

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
        config['intel']['enabled'] = False
        config['geo_blocking']['enabled'] = False
        config['manual']['enabled'] = True
        config['waf']['enabled'] = False

        # 配置异常检测
        config['anomaly_detection']['enabled'] = self.enable_anomaly
        config['anomaly_detection']['sample_rate'] = 1  # 100% 采样用于测试
        config['anomaly_detection']['check_interval'] = 1  # 1秒检测一次
        config['anomaly_detection']['min_packets'] = 10  # 降低最小包数阈值，适配测试环境
        config['anomaly_detection']['block_duration'] = 60  # 60秒封禁

        # 配置各种攻击检测
        config['anomaly_detection']['attacks']['syn_flood']['enabled'] = True
        config['anomaly_detection']['attacks']['syn_flood']['ratio_threshold'] = 0.5
        config['anomaly_detection']['attacks']['syn_flood']['min_packets'] = 50
        config['anomaly_detection']['attacks']['syn_flood']['block_duration'] = 60

        config['anomaly_detection']['attacks']['udp_flood']['enabled'] = True
        config['anomaly_detection']['attacks']['udp_flood']['ratio_threshold'] = 0.7
        config['anomaly_detection']['attacks']['udp_flood']['min_packets'] = 50
        config['anomaly_detection']['attacks']['udp_flood']['block_duration'] = 60

        config['anomaly_detection']['attacks']['icmp_flood']['enabled'] = True
        config['anomaly_detection']['attacks']['icmp_flood']['ratio_threshold'] = 0.5
        config['anomaly_detection']['attacks']['icmp_flood']['min_packets'] = 30
        config['anomaly_detection']['attacks']['icmp_flood']['block_duration'] = 60

        config['anomaly_detection']['attacks']['ack_flood']['enabled'] = True
        config['anomaly_detection']['attacks']['ack_flood']['ratio_threshold'] = 0.7
        config['anomaly_detection']['attacks']['ack_flood']['min_packets'] = 50
        config['anomaly_detection']['attacks']['ack_flood']['block_duration'] = 60

        # 固定基线配置（与 config.yml 保持一致）
        config['anomaly_detection']['baseline']['min_sample_count'] = 10
        config['anomaly_detection']['baseline']['sigma_multiplier'] = 3.0
        config['anomaly_detection']['baseline']['min_threshold'] = 100
        config['anomaly_detection']['baseline']['max_age'] = 1800

        # 禁用认证
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
        logger.info(f"Anomaly detection enabled: {self.enable_anomaly}")

        try:
            # 打开日志文件
            self.log_file = open(self.log_path, 'w')
            # 在配置文件所在目录运行程序，输出到日志文件
            self.process = subprocess.Popen(
                [self.binary_path],
                cwd=self.config_dir,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )

            # 等待服务启动
            time.sleep(3)

            if self.process.poll() is not None:
                logger.error(f"Process exited unexpectedly. Check log: {self.log_path}")
                return False

            logger.info(f"rho-ariyas started (PID: {self.process.pid})")
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

        # 清理临时配置目录
        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)


class APIClient:
    """rho-aias API 客户端"""

    def __init__(self, base_url: str):
        self.base_url = base_url

    def get_rules(self, source: str = None) -> Tuple[bool, dict]:
        """获取规则列表"""
        url = "/api/rules"
        if source:
            url += f"?source={source}"
        return self._request("GET", url)

    def _request(self, method: str, path: str, data: dict = None) -> Tuple[bool, dict]:
        """发送 HTTP 请求

        统一响应格式：
        - 成功: {"code": 0, "message": "ok", "data": {...}}
        - 失败: {"code": 4xxxx, "message": "错误描述"}
        """
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
                # 检查业务响应码，code=0 表示成功
                if isinstance(result, dict) and "code" in result:
                    return result.get("code") == 0, result
                return True, result
        except urllib.error.HTTPError as e:
            try:
                result = json.loads(e.read().decode())
                # HTTP 错误时返回 False 和响应体
                return False, result
            except:
                return False, {"code": -1, "message": str(e)}
        except Exception as e:
            return False, {"code": -1, "message": str(e)}


class TrafficGenerator:
    """流量生成器类"""

    def __init__(self, env: TestEnvironment):
        self.env = env
        self.stop_event = threading.Event()
        self.thread = None

    def generate_tcp_syn_flood(self, target_ip: str, target_port: int = 80, pps: int = 100):
        """生成 TCP SYN Flood 流量"""
        logger.info(f"Starting TCP SYN flood: {target_ip}:{target_port} @ flood mode")

        def flood():
            while not self.stop_event.is_set():
                try:
                    cmd = f"hping3 -c 10000 -d 120 -S -w 64 -p {target_port} --flood {target_ip} 2>/dev/null || true"
                    self.env.ns1.exec_cmd(cmd, timeout=10)
                except Exception as e:
                    logger.debug(f"Flood error (expected): {e}")

        self.thread = threading.Thread(target=flood, daemon=True)
        self.thread.start()

    def generate_udp_flood(self, target_ip: str, target_port: int = 53, pps: int = 100):
        """生成 UDP Flood 流量"""
        logger.info(f"Starting UDP flood: {target_ip}:{target_port} @ flood mode")

        def flood():
            while not self.stop_event.is_set():
                try:
                    cmd = f"hping3 -c 10000 -d 120 --udp -w 64 -p {target_port} --flood {target_ip} 2>/dev/null || true"
                    self.env.ns1.exec_cmd(cmd, timeout=10)
                except Exception as e:
                    logger.debug(f"Flood error (expected): {e}")

        self.thread = threading.Thread(target=flood, daemon=True)
        self.thread.start()

    def generate_icmp_flood(self, target_ip: str, pps: int = 100):
        """生成 ICMP Flood 流量"""
        logger.info(f"Starting ICMP flood: {target_ip} @ flood mode")

        def flood():
            while not self.stop_event.is_set():
                try:
                    cmd = f"hping3 -c 10000 -d 120 --icmp -w 64 -p 80 --flood {target_ip} 2>/dev/null || true"
                    self.env.ns1.exec_cmd(cmd, timeout=10)
                except Exception as e:
                    logger.debug(f"Flood error (expected): {e}")

        self.thread = threading.Thread(target=flood, daemon=True)
        self.thread.start()

    def generate_tcp_ack_flood(self, target_ip: str, target_port: int = 80, pps: int = 100):
        """生成 TCP ACK Flood 流量"""
        logger.info(f"Starting TCP ACK flood: {target_ip}:{target_port} @ flood mode")

        def flood():
            while not self.stop_event.is_set():
                try:
                    cmd = f"hping3 -c 10000 -d 120 -A -w 64 -p {target_port} --flood {target_ip} 2>/dev/null || true"
                    self.env.ns1.exec_cmd(cmd, timeout=10)
                except Exception as e:
                    logger.debug(f"Flood error (expected): {e}")

        self.thread = threading.Thread(target=flood, daemon=True)
        self.thread.start()

    def stop(self):
        """停止流量生成"""
        logger.info("Stopping traffic generation")
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self.stop_event.clear()


class TestDDoSDetection(unittest.TestCase):
    """DDoS 检测功能测试"""

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
        self.env = TestEnvironment("rho_dd")
        self.rho_process: Optional[RhoAiasProcess] = None
        self.traffic_gen: Optional[TrafficGenerator] = None

        # 设置网络环境
        if not self.env.setup():
            self.skipTest("Failed to setup test environment")

        logger.info(f"Test environment ready: ns1={self.env.ns1.name}, ns2={self.env.ns2.name}")

    def tearDown(self):
        """每个测试后的清理工作"""
        # 停止流量生成
        if self.traffic_gen:
            self.traffic_gen.stop()

        # 停止 rho-aias
        if self.rho_process:
            self.rho_process.stop()

        # 清理网络环境
        self.env.cleanup()

        # 等待资源释放
        time.sleep(1)

    def _start_rho_with_anomaly(self) -> bool:
        """启动 rho-aias 并启用异常检测（使用正确接口名）"""
        self.rho_process = RhoAiasProcess(
            self.binary_path,
            self.default_config_path,
            "rho_dd_veth0",  # 与 TestEnvironment 创建的接口名匹配
            self.api_port,
            enable_anomaly=True
        )
        return self.rho_process.start()

    def _start_rho_without_anomaly(self) -> bool:
        """启动 rho-aias 不启用异常检测（对照组）"""
        self.rho_process = RhoAiasProcess(
            self.binary_path,
            self.default_config_path,
            "rho_dd_veth0",  # 与 TestEnvironment 创建的接口名匹配
            self.api_port,
            enable_anomaly=False
        )
        return self.rho_process.start()

    def _verify_ip_blocked(self, attack_type: str) -> bool:
        """验证攻击源 IP 是否被 anomaly 规则封禁

        统一响应格式: {"code": 0, "message": "ok", "data": {"rules": [...], "total": N}}
        """
        if not self.api_client:
            return False
        try:
            success, result = self.api_client.get_rules(source="anomaly")
            if success and result:
                # 新格式: data 字段包含 rules 列表
                data = result.get('data', result) if isinstance(result, dict) else {}
                if isinstance(data, dict):
                    rules = data.get('rules', [])
                elif isinstance(data, list):
                    rules = data
                else:
                    rules = []

                if isinstance(rules, list):
                    for rule in rules:
                        ip = rule.get('Key', rule.get('key', rule.get('ip', rule.get('cidr', ''))))
                        if ip == '10.0.1.2':
                            reason = rule.get('reason', rule.get('sources', ''))
                            logger.info(f"IP 10.0.1.2 blocked by anomaly rule: {reason}")
                            return True
                logger.warning(f"No anomaly rule found for IP 10.0.1.2 after {attack_type}")
                return False
            else:
                error_msg = result.get('message', result) if isinstance(result, dict) else result
                logger.warning(f"Failed to query anomaly rules: {error_msg}")
                return False
        except Exception as e:
            logger.warning(f"Error verifying IP block: {e}")
            return False

    def _run_flood_test(self, attack_type: str, flood_method_name: str, *args, **kwargs):
        """通用的 flood 测试流程：启动服务 -> 发送流量 -> 验证封禁"""
        # 启动 rho-aias
        self.assertTrue(
            self._start_rho_with_anomaly(),
            f"Failed to start rho-aias for {attack_type} test"
        )

        # 等待初始化完成
        time.sleep(3)

        # 创建流量生成器
        self.traffic_gen = TrafficGenerator(self.env)

        # 通过方法名调用对应的流量生成方法，确保在同一个实例上操作
        flood_func = getattr(self.traffic_gen, flood_method_name)
        flood_func(*args, **kwargs)

        # 持续一段时间让检测系统工作
        logger.info(f"Running {attack_type} for 10 seconds...")
        time.sleep(10)

        # 停止流量
        self.traffic_gen.stop()

        # 等待检测生效
        time.sleep(3)

        # 验证封禁
        blocked = self._verify_ip_blocked(attack_type)
        self.assertTrue(
            blocked,
            f"{attack_type}: attack source IP 10.0.1.2 should be blocked by anomaly detection"
        )

        logger.info(f"{attack_type} test completed successfully")

    def test_01_tcp_syn_flood(self):
        """测试 TCP SYN Flood 检测"""
        self._run_flood_test("TCP SYN Flood", "generate_tcp_syn_flood", "10.0.1.1", 80, 200)

    def test_02_udp_flood(self):
        """测试 UDP Flood 检测"""
        self._run_flood_test("UDP Flood", "generate_udp_flood", "10.0.1.1", 53, 200)

    def test_03_icmp_flood(self):
        """测试 ICMP Flood 检测"""
        self._run_flood_test("ICMP Flood", "generate_icmp_flood", "10.0.1.1", 200)

    def test_04_ack_flood(self):
        """测试 ACK Flood 检测"""
        self._run_flood_test("ACK Flood", "generate_tcp_ack_flood", "10.0.1.1", 80, 200)

    def test_05_control_without_detection(self):
        """对照组：不启用检测时系统应正常运行"""
        # 启动 rho-aias（不启用异常检测）
        self.assertTrue(
            self._start_rho_without_anomaly(),
            "Failed to start rho-aias"
        )

        # 验证基本连通性
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertTrue(success, "Basic connectivity test failed")

        logger.info("Control test completed (no anomaly detection)")


class TestDDoSDetectionEnvironment(unittest.TestCase):
    """DDoS 测试环境设置测试"""

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("This test requires root privileges")
        self.env = TestEnvironment("rho_de")

    def tearDown(self):
        self.env.cleanup()

    def test_namespace_communication(self):
        """测试 namespace 间通信"""
        self.assertTrue(self.env.setup(), "Failed to setup test environment")

        # 测试从主 namespace 到 ns1 的连通性
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertTrue(success, "Cannot reach ns1 from main namespace")

        # 测试从 ns1 到主 namespace 的连通性
        success, _ = self.env.ping_from_ns(self.env.ns1, "10.0.1.1", count=2)
        self.assertTrue(success, "Cannot reach main namespace from ns1")


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

    parser = argparse.ArgumentParser(
        description="DDoS Detection Integration Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
测试运行示例:
  # 运行所有测试
  python3 %(prog)s

  # 运行特定测试
  python3 %(prog)s --test TestDDoSDetection.test_tcp_syn_flood

  # 只测试 SYN Flood
  python3 %(prog)s --test TestDDoSDetection.test_01_tcp_syn_flood
        """
    )
    parser.add_argument(
        "-t", "--test",
        help="Run specific test (e.g., TestDDoSDetection.test_01_tcp_syn_flood)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--env-only",
        action="store_true",
        help="Only run environment setup tests"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.env_only:
        sys.exit(run_tests("TestDDoSDetectionEnvironment"))
    elif args.test:
        sys.exit(run_tests(args.test))
    else:
        sys.exit(run_tests())
