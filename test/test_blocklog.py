#!/usr/bin/env python3
"""
BlockLog 阻断日志集成测试
验证阻断采样、记录查询和统计聚合功能

测试项目:
- 阻断采样基本功能
- 记录字段完整性
- 统计一致性：发包阻断数量与 total_blocked 对得上
- IP 聚合准确性
- 按来源过滤
- 多 IP 独立记录
- SQLite 统计持久化

运行示例:
    # 基本测试
    python3 test_blocklog.py

    # 运行特定测试
    python3 test_blocklog.py -t TestBlockLog.test_01_sampling_basic

    # 使用 API Key 认证
    python3 test_blocklog.py --use-api-key --api-key sk_live_your-key-here
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

# 默认 API Key（与其他测试脚本保持一致）
DEFAULT_API_KEY = "sk_live_test-admin-key-1234567890abcdef"

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RhoAiasProcess:
    """rho-aias 进程管理类"""

    def __init__(self, binary_path: str, default_config_path: str, interface: str,
                 api_port: int = 18080, use_auth: bool = True, api_key: str = DEFAULT_API_KEY):
        self.binary_path = binary_path
        self.default_config_path = default_config_path
        self.interface = interface
        self.api_port = api_port
        self.use_auth = use_auth
        self.api_key = api_key
        self.process: Optional[subprocess.Popen] = None
        self.config_dir = "/tmp/rho_bl_test"
        self.log_dir = "/tmp/rho_bl_test_logs"
        self.log_file = None
        self.log_path = None

    def start(self) -> bool:
        """启动 rho-aias 进程"""
        if not os.path.exists(self.binary_path):
            logger.error(f"Binary not found: {self.binary_path}")
            return False

        os.makedirs(self.config_dir, exist_ok=True)
        config_file = os.path.join(self.config_dir, "config.yml")
        os.makedirs(self.log_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(self.log_dir, f"rho-aias_{timestamp}.log")

        try:
            with open(self.default_config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load default config: {e}")
            return False

        config['server']['port'] = self.api_port
        config['ebpf']['interface_name'] = self.interface

        # blocklog 始终持久化，无需额外配置

        # 禁用不必要功能
        config['intel']['enabled'] = False
        config['geo_blocking']['enabled'] = False
        config['waf']['enabled'] = False
        config['rate_limit']['enabled'] = False
        config['failguard']['enabled'] = False
        config['anomaly_detection']['enabled'] = False
        
        # 保留手动规则功能
        config['manual']['enabled'] = True

        # 认证配置（注意：Go AuthConfig 无 enabled 字段，认证始终初始化；
        # use_auth 控制的是是否写入 jwt_secret 和 api_keys）
        if self.use_auth:
            config['auth']['jwt_secret'] = 'test-jwt-secret-key-for-testing'
            config['auth']['database_path'] = os.path.join(self.config_dir, 'auth.db')
            if self.api_key:
                config['auth']['api_keys'] = [
                    {'name': 'Test Admin Key', 'key': self.api_key, 'permissions': ['*']}
                ]
        else:
            # 不启用认证：保留空 auth 段（Go 端会使用默认值）
            pass

        try:
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            logger.error(f"Failed to write temp config: {e}")
            return False

        logger.info(f"Starting rho-aias on interface {self.interface} (blocklog enabled)")
        logger.info(f"Log will be saved to: {self.log_path}")

        try:
            self.log_file = open(self.log_path, 'w')
            self.process = subprocess.Popen(
                [self.binary_path, "--config", config_file],
                cwd=self.config_dir,
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )
            # 轮询等待服务就绪（端口可连），替代固定 sleep
            if not self._wait_for_ready(timeout=15):
                logger.error("Service did not become ready within 15s. Check log: %s", self.log_path)
                return False

            logger.info(f"rho-aias started (PID: {self.process.pid})")
            return True

        except Exception as e:
            logger.error(f"Failed to start rho-aias: {e}")
            if self.log_file:
                self.log_file.close()
            return False

    def _wait_for_ready(self, timeout: int = 15) -> bool:
        """轮询等待 HTTP 服务端口就绪"""
        import urllib.request
        health_url = f"http://127.0.0.1:{self.api_port}/api/rules"
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                logger.error("Process exited unexpectedly (code=%s). Check log: %s", self.process.returncode, self.log_path)
                return False
            try:
                req = urllib.request.Request(health_url, headers=headers)
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
            time.sleep(0.3)
        logger.error("Timeout (%ds): service not ready on port %d", timeout, self.api_port)
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

        if self.log_file:
            try:
                self.log_file.close()
                logger.info(f"Log saved to: {self.log_path}")
            except Exception as e:
                logger.error(f"Error closing log file: {e}")
            finally:
                self.log_file = None

        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)


class BlockLogAPIClient:
    """BlockLog API 客户端"""

    def __init__(self, base_url: str, api_key: str = DEFAULT_API_KEY):
        self.base_url = base_url
        self.api_key = api_key

    def _request(self, method: str, path: str, data: dict = None) -> Tuple[bool, dict]:
        """发送 HTTP 请求"""
        import urllib.request
        import urllib.error

        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        try:
            if method == "GET":
                req = urllib.request.Request(url, headers=headers)
            else:
                body = json.dumps(data).encode() if data else b""
                req = urllib.request.Request(url, data=body, headers=headers, method=method)

            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                if isinstance(result, dict) and "code" in result:
                    return result.get("code") == 0, result
                return True, result
        except urllib.error.HTTPError as e:
            try:
                result = json.loads(e.read().decode())
                return False, result
            except:
                return False, {"code": -1, "message": str(e)}
        except Exception as e:
            return False, {"code": -1, "message": str(e)}

    def enable_event_reporting(self, sample_rate: int = 1) -> Tuple[bool, dict]:
        """启用 eBPF 事件上报（ringbuf 输出）
        
        eBPF 内核程序的 event_config map 默认 enabled=0，
        必须通过此 API 显式启用才能向 ringbuf 写入阻断事件。
        sample_rate=1 表示每个丢弃包都上报（100% 采样）。
        """
        return self._request("PUT", "/api/config/xdp_events",
                             {"enabled": True, "sample_rate": sample_rate})

    def add_rule(self, value: str) -> Tuple[bool, dict]:
        """添加阻断规则"""
        return self._request("POST", "/api/manual/blacklist/rules", {"value": value})

    def delete_rule(self, value: str) -> Tuple[bool, dict]:
        """删除阻断规则"""
        return self._request("DELETE", "/api/manual/blacklist/rules", {"value": value})

    def get_records(self, params: dict = None) -> Tuple[bool, dict]:
        """获取阻断记录"""
        path = "/api/blocklog/records"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items() if v)
            if query:
                path += f"?{query}"
        return self._request("GET", path)

    def get_stats(self) -> Tuple[bool, dict]:
        """获取阻断统计"""
        return self._request("GET", "/api/blocklog/stats")

    def get_blocked_ips(self, limit: int = None) -> Tuple[bool, dict]:
        """获取被阻断 IP 聚合列表"""
        path = "/api/blocklog/blocked-top-ips"
        if limit:
            path += f"?limit={limit}"
        return self._request("GET", path)

    def get_hourly_trend(self, hours: int = 24) -> Tuple[bool, dict]:
        """获取小时趋势"""
        return self._request("GET", f"/api/blocklog/hourly-trend?hours={hours}")


class TestBlockLog(unittest.TestCase):
    """BlockLog 阻断日志功能测试

    网络拓扑:
        main namespace          ns1 (rho_bl_ns1)
       ┌──────────────┐      ┌──────────────┐
       │ rho_bl_veth0 │<────>│ rho_bl_veth1 │
       │ 10.0.1.1/24  │      │ 10.0.1.2/24  │
       └──────────────┘      └──────────────┘

    XDP 绑定在 rho_bl_veth0 上。
    触发阻断时，必须从主 namespace ping ns1 的 IP（10.0.1.2），
    这样数据包才会经过 veth0 被 XDP 拦截。
    """

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest("This test requires root privileges")

        cls.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.binary_path = os.path.join(cls.project_root, "rho-aias")
        cls.default_config_path = os.path.join(cls.project_root, "config/config.yml")
        cls.api_port = 18080
        cls.api_client = BlockLogAPIClient(f"http://127.0.0.1:{cls.api_port}",
                                            api_key=DEFAULT_API_KEY)

        if not os.path.exists(cls.binary_path):
            raise unittest.SkipTest(f"Binary not found: {cls.binary_path}. Run 'make build' first.")
        if not os.path.exists(cls.default_config_path):
            raise unittest.SkipTest(f"Default config not found: {cls.default_config_path}")

    def setUp(self):
        self.env = TestEnvironment("rho_bl")
        self.rho_process: Optional[RhoAiasProcess] = None

        if not self.env.setup():
            self.skipTest("Failed to setup test environment")

        logger.info(f"Test environment ready: ns1={self.env.ns1.name}, ns2={self.env.ns2.name}")

    def tearDown(self):
        if self.rho_process:
            self.rho_process.stop()
        self.env.cleanup()
        time.sleep(1)

    def _start_rho(self, veth_name: str, use_auth: bool = True, api_key: str = DEFAULT_API_KEY) -> bool:
        self.rho_process = RhoAiasProcess(
            self.binary_path,
            self.default_config_path,
            veth_name,
            self.api_port,
            use_auth,
            api_key
        )
        return self.rho_process.start()

    def _safe_records(self, resp: dict) -> list:
        """安全提取 records 列表，处理 Go 可能返回 null 的场景"""
        data = resp.get("data") or {}
        records = data.get("records")
        return records if isinstance(records, list) else []

    def _ping_and_expect_blocked(self, target_ip: str, count: int = 3, timeout: float = 2.0) -> Tuple[bool, str]:
        """从主 namespace 发送 ping，期望被 XDP 阻断
        
        注意：必须使用 ping_from_main，因为主 namespace 是发包方，
        数据包经过 veth0（绑定 XDP）到达目标 IP 时才会被拦截。
        
        Returns:
            (is_blocked, output): is_blocked=True 表示 ping 失败（被正确阻断）
        """
        success, output = self.env.ping_from_main(target_ip, count=count, timeout=timeout)
        blocked = not success  # ping 失败 = 阻断成功
        return blocked, output

    def _add_rule_and_wait(self, ip: str, wait_sec: float = 1.5):
        """添加阻断规则并等待生效"""
        success, resp = self.api_client.add_rule(ip)
        self.assertTrue(success, f"Failed to add rule for {ip}: {resp}")
        logger.info(f"Added block rule for {ip}")
        time.sleep(wait_sec)

    def _do_block_cycle(self, target_ip: str, ping_count: int = 3,
                        wait_before_ping: float = 1.5,
                        wait_after_block: float = 2.0) -> Tuple[bool, list]:
        """执行完整的「添加规则 → 触发阻断 → 等待 → 查询记录」周期
        
        Returns:
            (blocked_successfully, records_list)
        """
        # 确保 eBPF 事件上报已启用（ringbuf 输出）
        success, resp = self.api_client.enable_event_reporting(sample_rate=1)
        self.assertTrue(success, f"Failed to enable event reporting: {resp}")
        
        self._add_rule_and_wait(target_ip, wait_sec=wait_before_ping)
        blocked, output = self._ping_and_expect_blocked(target_ip, count=ping_count)
        self.assertTrue(blocked, f"Block not effective for {target_ip}: {output}")
        logger.info(f"Block triggered successfully for {target_ip}")
        time.sleep(wait_after_block)

        success, resp = self.api_client.get_records({"limit": 200})
        self.assertTrue(success, f"Failed to get records: {resp}")
        return blocked, self._safe_records(resp)

    # ====================================================================
    # 测试用例
    # ====================================================================

    def test_01_sampling_basic(self):
        """测试阻断采样基本功能：封禁 IP → 发包 → API 查到记录"""
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        # 验证初始连通性：未封禁时应能 ping 通
        success, _ = self.env.ping_from_main("10.0.1.2", count=2)
        self.assertTrue(success, "Initial connectivity check failed")

        # 执行完整阻断周期
        _, records = self._do_block_cycle("10.0.1.2", ping_count=4)

        # 验证 blocklog 有记录
        self.assertGreater(len(records), 0, "No blocklog records found after blocking")
        logger.info(f"Found {len(records)} blocklog record(s)")

        # 清理
        self.api_client.delete_rule("10.0.1.2")

    def test_02_record_fields_detail(self):
        """测试记录字段完整性和正确性"""
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        _, records = self._do_block_cycle("10.0.1.2", ping_count=3)

        self.assertGreater(len(records), 0, "No records found")

        record = records[0]
        # 验证必填字段存在且非空
        required_fields = ["src_ip", "dst_ip", "match_type", "rule_source", "packet_size", "timestamp"]
        for field in required_fields:
            self.assertIn(field, record, f"Missing field: {field}")
            logger.info(f"  {field} = {record[field]}")

        # 验证字段值合理性
        self.assertEqual(record["src_ip"], "10.0.1.2", "src_ip mismatch")
        self.assertEqual(record["dst_ip"], "10.0.1.1", "dst_ip mismatch")
        self.assertEqual(record["match_type"], "ip4_exact",
                         "match_type should be ip4_exact for manual block")
        self.assertEqual(record["rule_source"], "manual",
                         "rule_source should be manual")
        self.assertGreater(record["packet_size"], 0, "packet_size should be positive")
        # countryCode 在 manual 阻断时为空字符串
        self.assertIn("country_code", record)
        self.assertEqual(record["country_code"], "",
                         "country_code should be empty for manual block")

        logger.info("All record fields validated successfully")
        self.api_client.delete_rule("10.0.1.2")

    def test_03_stats_consistency(self):
        """测试统计一致性：发包阻断数量与 stats.total_blocked 对得上"""
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        ping_count = 3
        self._do_block_cycle("10.0.1.2", ping_count=ping_count)

        # 获取 stats 并验证 total_blocked 与发包数量对得上
        success, resp = self.api_client.get_stats()
        self.assertTrue(success, f"Failed to get stats: {resp}")
        stats = resp.get("data", {})
        total_blocked = stats.get("total_blocked", 0)

        logger.info(f"Sent pings: {ping_count}, stats.total_blocked: {total_blocked}")
        self.assertGreaterEqual(total_blocked, ping_count,
                                f"stats.total_blocked ({total_blocked}) should >= {ping_count} (sent pings)")

        # 验证 by_rule_source 中 manual 类型数量与发包数量对得上
        by_source = stats.get("by_rule_source", {})
        manual_count = by_source.get("manual", 0)
        self.assertGreaterEqual(manual_count, ping_count,
                                f"by_rule_source.manual ({manual_count}) should >= {ping_count} (sent pings)")

        logger.info("Stats consistency validated")
        self.api_client.delete_rule("10.0.1.2")

    def test_04_blocked_ips_aggregation(self):
        """测试 IP 聚合功能准确性"""
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        # 确保 eBPF 事件上报已启用（ringbuf 输出）
        success, resp = self.api_client.enable_event_reporting(sample_rate=1)
        self.assertTrue(success, f"Failed to enable event reporting: {resp}")

        # 封禁并多次触发（累积阻断计数）
        self._add_rule_and_wait("10.0.1.2")
        for i in range(5):
            blocked, _ = self._ping_and_expect_blocked("10.0.1.2", count=1)
            self.assertTrue(blocked, f"Iteration {i+1}: Block not effective")
        time.sleep(2)

        # 获取 blocked-top-ips 聚合
        success, resp = self.api_client.get_blocked_ips(limit=10)
        self.assertTrue(success, f"Failed to get blocked-top-ips: {resp}")

        data = resp.get("data", {}) or {}
        top_ips = data.get("top_blocked_ips") or []
        self.assertGreater(len(top_ips), 0, "No blocked IPs found")

        # 找到 10.0.1.2 的聚合记录
        target_record = next((item for item in top_ips if item.get("ip") == "10.0.1.2"), None)
        self.assertIsNotNone(target_record, "10.0.1.2 not found in blocked-top-ips aggregation")
        self.assertGreaterEqual(target_record.get("count", 0), 1,
                                "IP block count >= 1 expected")
        logger.info(f"IP aggregation validated: 10.0.1.2 count={target_record.get('count')}")

        self.api_client.delete_rule("10.0.1.2")

    def test_05_filter_by_source(self):
        """测试按 rule_source 过滤功能"""
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        self._do_block_cycle("10.0.1.2", ping_count=3)

        # 按 rule_source=manual 过滤
        success, resp = self.api_client.get_records({"rule_source": "manual", "limit": 100})
        self.assertTrue(success, f"Failed to filter by rule_source: {resp}")

        records = self._safe_records(resp)
        self.assertGreater(len(records), 0, "No records found with rule_source=manual")

        # 验证所有记录的 rule_source 都是 manual
        for record in records:
            self.assertEqual(record.get("rule_source"), "manual",
                             f"Expected rule_source=manual, got {record.get('rule_source')}")

        logger.info(f"rule_source filter validated: {len(records)} manual records")

        # 交叉验证：stats.by_rule_source.manual 应与过滤记录数一致
        success, resp = self.api_client.get_stats()
        self.assertTrue(success, f"Failed to get stats: {resp}")
        stats = resp.get("data", {})
        by_source = stats.get("by_rule_source", {})
        manual_stats = by_source.get("manual", 0)
        self.assertGreater(manual_stats, 0,
                           "stats.by_rule_source.manual should be > 0 after blocking")
        logger.info(f"Stats cross-validation: by_rule_source.manual={manual_stats}")

        # 验证过滤非法来源返回空
        success, resp = self.api_client.get_records({"rule_source": "nonexistent_source", "limit": 100})
        self.assertTrue(success)
        records_empty = self._safe_records(resp)
        self.assertEqual(len(records_empty), 0,
                         "Filter with invalid source should return empty")

        self.api_client.delete_rule("10.0.1.2")

    def test_06_multi_ip_records(self):
        """测试多 IP 独立记录：同时封禁同一子网多个 IP，各自记录独立

        注意：XDP 只绑定在 veth0（10.0.1.x 子网），因此只能封禁该子网的 IP。
        本用例通过在 veth0 同一 /24 子网内配置额外 IP 来模拟多 IP 场景。
        """
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        # 确保 eBPF 事件上报已启用（ringbuf 输出）
        success, resp = self.api_client.enable_event_reporting(sample_rate=1)
        self.assertTrue(success, f"Failed to enable event reporting: {resp}")

        # 在 veth1 (ns1 内) 上添加第二个 IP 地址
        # 这样两个 IP 都在同一子网且都经过 veth0/XDP
        extra_ip = "10.0.1.100"
        cmd_add = f"ip netns exec {self.env.ns1.name} ip addr add {extra_ip}/24 dev rho_bl_veth1"
        ret = subprocess.run(cmd_add, shell=True, capture_output=True)
        if ret.returncode != 0:
            self.skipTest(f"Cannot add extra IP {extra_ip} to veth1: {ret.stderr.decode()}")

        # 同时封禁两个 IP
        self._add_rule_and_wait("10.0.1.2")
        self._add_rule_and_wait(extra_ip)
        time.sleep(1)

        # 分别触发两个 IP 的阻断
        blocked1, _ = self._ping_and_expect_blocked("10.0.1.2", count=3)
        self.assertTrue(blocked1, "10.0.1.2 should be blocked")

        blocked2, _ = self._ping_and_expect_blocked(extra_ip, count=3)
        self.assertTrue(blocked2, f"{extra_ip} should be blocked")
        time.sleep(2)

        # 验证总记录数
        success, resp = self.api_client.get_records({"limit": 200})
        self.assertTrue(success)
        all_records = self._safe_records(resp)
        total_count = len(all_records)

        self.assertGreaterEqual(total_count, 2, "Should have records for both IPs")
        logger.info(f"Total records: {total_count}")

        # 验证各自 IP 有独立记录
        src_ips = set(r.get("src_ip") for r in all_records)
        self.assertIn("10.0.1.2", src_ips, "10.0.1.2 should have records")
        self.assertIn(extra_ip, src_ips, f"{extra_ip} should have records")

        # 验证 total_blocked 与发包阻断数量一致（3+3=6）
        success, resp = self.api_client.get_stats()
        self.assertTrue(success)
        total_blocked = (resp.get("data") or {}).get("total_blocked", 0)
        expected_blocked = 3 + 3  # 两个 IP 各发 3 个 ping
        self.assertGreaterEqual(total_blocked, expected_blocked,
                                f"stats.total_blocked ({total_blocked}) should >= {expected_blocked} (sent pings)")

        logger.info(f"Multi-IP records validated: {src_ips}")

        # 清理额外 IP
        subprocess.run(
            f"ip netns exec {self.env.ns1.name} ip addr del {extra_ip}/24 dev rho_bl_veth1",
            shell=True, capture_output=True
        )
        self.api_client.delete_rule("10.0.1.2")
        self.api_client.delete_rule(extra_ip)

    def test_07_sqlite_stats_persistence(self):
        """测试统计持久化：hourly-trend 和 stats 联合验证"""
        self.assertTrue(
            self._start_rho("rho_bl_veth0"),
            "Failed to start rho-aias"
        )

        # 触发阻断
        self._do_block_cycle("10.0.1.2", ping_count=3, wait_after_block=3)

        # 查询 hourly-trend（最近 1 小时）
        success, resp = self.api_client.get_hourly_trend(hours=1)
        self.assertTrue(success, f"Failed to get hourly-trend: {resp}")

        hourly_data = (resp.get("data") or {}).get("hourly_data")
        logger.info(f"hourly-trend data: {hourly_data}")

        # 查询 stats 验证融合查询
        success, resp = self.api_client.get_stats()
        self.assertTrue(success, f"Failed to get stats: {resp}")

        stats = resp.get("data", {})
        total_blocked = stats.get("total_blocked", 0)
        by_source = stats.get("by_rule_source", {})
        manual_count = by_source.get("manual", 0)

        # 验证 total_blocked 与发包阻断数量一致
        self.assertGreater(total_blocked, 0, "stats.total_blocked should be > 0 after blocking")
        self.assertGreaterEqual(total_blocked, 3,
                                f"stats.total_blocked ({total_blocked}) should >= 3 (sent pings)")
        self.assertGreaterEqual(manual_count, 3,
                                f"by_rule_source.manual ({manual_count}) should >= 3 (sent pings)")

        # 查询 blocked-top-ips
        success, resp = self.api_client.get_blocked_ips(limit=10)
        self.assertTrue(success, f"Failed to get blocked-top-ips: {resp}")
        top_ips = (resp.get("data") or {}).get("top_blocked_ips") or []
        self.assertGreater(len(top_ips), 0, "blocked-top-ips should have results after blocking")

        logger.info(f"Stats persistence validated: total_blocked={total_blocked}, manual={manual_count}")
        self.api_client.delete_rule("10.0.1.2")


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
        description="BlockLog 阻断日志集成测试",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
测试运行示例:
  # 基本测试
  python3 test_blocklog.py

  # 运行特定测试
  python3 test_blocklog.py -t TestBlockLog.test_01_sampling_basic

  # 使用 API Key 认证
  python3 test_blocklog.py --use-api-key --api-key sk_live_your-key-here
        """
    )
    parser.add_argument(
        "-t", "--test",
        help="Run specific test (e.g., TestBlockLog.test_01_sampling_basic)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--use-api-key",
        action="store_true",
        help="Enable API Key authentication for tests"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="API Key to use for authentication"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.use_api_key:
        if args.api_key:
            os.environ["TEST_API_KEY"] = args.api_key
            logger.info(f"Using provided API Key: {args.api_key[:20]}...")
        elif "TEST_API_KEY" in os.environ:
            logger.info(f"Using API Key from environment")
        else:
            default_key = "sk_live_test-admin-key-1234567890abcdef"
            os.environ["TEST_API_KEY"] = default_key

    sys.exit(run_tests(args.test) if args.test else run_tests())
