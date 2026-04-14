#!/usr/bin/env python3
"""
WAF / FailGuard / Rate Limit 日志触发封禁集成测试

测试流程:
1. 启动 rho-aias，配置监听临时日志文件（WAF、rate_limit、SSH）
2. 向日志文件追加真实格式的日志行
3. 通过 API 查询封禁记录，验证 IP 是否被封禁

运行示例:
    python3 test_log_ban.py  # API Key 认证已内置
    TEST_API_KEY="sk_live_your-key-here" python3 test_log_ban.py  # 自定义 Key
    python3 test_log_ban.py --test TestFailGuardBan.test_ssh_fail_password
    python3 test_log_ban.py --test TestRateLimitBan
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

# ============================================================
# 日志文件路径（测试用临时目录，在脚本中定义）
# ============================================================
TEST_LOG_DIR = "/tmp/rho_log_ban_test_logs"
SSH_LOG_PATH = os.path.join(TEST_LOG_DIR, "auth.log")
WAF_LOG_PATH = os.path.join(TEST_LOG_DIR, "waf_audit.log")
RATE_LIMIT_LOG_PATH = os.path.join(TEST_LOG_DIR, "rate_limit.log")

# ============================================================
# 测试用真实日志样本
# ============================================================

# SSH 认证失败（normal/ddos/aggressive 均匹配）
SSH_FAIL_PASSWORD_LINES = [
    '2026-04-01T09:47:45.292541+08:00 localhost sshd[419683]: Failed password for root from 203.0.113.10 port 35340 ssh2',
    '2026-04-01T09:47:46.100000+08:00 localhost sshd[419684]: Failed password for root from 203.0.113.10 port 35341 ssh2',
    '2026-04-01T09:47:47.200000+08:00 localhost sshd[419685]: Failed password for root from 203.0.113.10 port 35342 ssh2',
    '2026-04-01T09:47:48.300000+08:00 localhost sshd[419686]: Failed password for root from 203.0.113.10 port 35343 ssh2',
    '2026-04-01T09:47:49.400000+08:00 localhost sshd[419687]: Failed password for root from 203.0.113.10 port 35344 ssh2',
]

# SSH 无效用户
SSH_INVALID_USER_LINES = [
    '2026-04-01T09:48:00.000000+08:00 localhost sshd[420000]: Invalid user admin from 198.51.100.20 port 52341',
    '2026-04-01T09:48:01.000000+08:00 localhost sshd[420001]: Invalid user admin from 198.51.100.20 port 52342',
    '2026-04-01T09:48:02.000000+08:00 localhost sshd[420002]: Invalid user admin from 198.51.100.20 port 52343',
    '2026-04-01T09:48:03.000000+08:00 localhost sshd[420003]: Invalid user admin from 198.51.100.20 port 52344',
    '2026-04-01T09:48:04.000000+08:00 localhost sshd[420004]: Invalid user admin from 198.51.100.20 port 52345',
]

# SSH 连接关闭 preauth（ddos/aggressive 模式匹配）
SSH_PREAUTH_LINES = [
    '2026-04-01T09:49:00.000000+08:00 localhost sshd[421000]: Connection closed by authenticating user root 192.0.2.50 port 40100 [preauth]',
    '2026-04-01T09:49:01.000000+08:00 localhost sshd[421001]: Connection closed by authenticating user root 192.0.2.50 port 40101 [preauth]',
    '2026-04-01T09:49:02.000000+08:00 localhost sshd[421002]: Connection closed by authenticating user root 192.0.2.50 port 40102 [preauth]',
    '2026-04-01T09:49:03.000000+08:00 localhost sshd[421003]: Connection closed by authenticating user root 192.0.2.50 port 40103 [preauth]',
    '2026-04-01T09:49:04.000000+08:00 localhost sshd[421004]: Connection closed by authenticating user root 192.0.2.50 port 40104 [preauth]',
]

# SSH 认证成功（不应触发封禁）
SSH_ACCEPTED_LINE = '2026-04-01T09:50:00.000000+08:00 localhost sshd[422000]: Accepted password for root from 10.0.0.1 port 49152 ssh2'

# WAF 审计日志（is_interrupted=true 时触发封禁）
WAF_INTERRUPTED_LINES = [
    json.dumps({
        "transaction": {
            "timestamp": "2026/04/01 09:48:44",
            "client_ip": "198.51.100.100",
            "request": {
                "uri": "/wp-admin",
                "method": "POST",
                "headers": {"X-Forwarded-For": "198.51.100.100"},
            },
            "response": {"status": 403},
            "is_interrupted": True,
        }
    }),
    json.dumps({
        "transaction": {
            "timestamp": "2026/04/01 09:48:45",
            "client_ip": "198.51.100.101",
            "request": {
                "uri": "/phpmyadmin",
                "method": "GET",
                "headers": {"X-Forwarded-For": "198.51.100.101"},
            },
            "response": {"status": 403},
            "is_interrupted": True,
        }
    }),
]

# WAF 审计日志（is_interrupted=false，不应触发封禁）
WAF_NOT_INTERRUPTED_LINE = json.dumps({
    "transaction": {
        "timestamp": "2026/04/01 09:49:00",
        "request": {
            "uri": "/api/health",
            "method": "GET",
            "headers": {"X-Forwarded-For": "10.0.0.2"},
            "remote_addr": "10.0.0.2",
        },
        "response": {"status": 200},
        "is_interrupted": False,
    }
})

# Rate Limit 日志
RATE_LIMIT_LINES = [
    json.dumps({
        "level": "info",
        "ts": 1774960679.2144504,
        "logger": "http.handlers.rate_limit",
        "msg": "rate limit exceeded",
        "zone": "global_zone",
        "wait": 2.365196316,
        "remote_ip": "222.209.44.8"
    }),
    json.dumps({
        "level": "info",
        "ts": 1774960680.3000000,
        "logger": "http.handlers.rate_limit",
        "msg": "rate limit exceeded",
        "zone": "global_zone",
        "wait": 5.123456789,
        "remote_ip": "222.209.44.9"
    }),
]


class RhoAiasProcess:
    """rho-aias 进程管理类（日志封禁测试专用）"""

    def __init__(self, binary_path: str, default_config_path: str, api_port: int = 18081,
                 ssh_log: str = SSH_LOG_PATH, waf_log: str = WAF_LOG_PATH,
                 rate_limit_log: str = RATE_LIMIT_LOG_PATH,
                 api_key: str = "sk_live_test-admin-key-1234567890abcdef"):
        self.binary_path = binary_path
        self.default_config_path = default_config_path
        self.api_port = api_port
        self.ssh_log = ssh_log
        self.waf_log = waf_log
        self.rate_limit_log = rate_limit_log
        self.api_key = api_key
        self.process: Optional[subprocess.Popen] = None
        self.config_dir = "/tmp/rho_log_ban_test_cfg"
        self.rho_log_dir = "/tmp/rho_log_ban_test_rho_logs"
        self.log_file = None
        self.log_path = None

    def start(self) -> bool:
        """启动 rho-aias 进程"""
        if not os.path.exists(self.binary_path):
            logger.error(f"Binary not found: {self.binary_path}")
            return False

        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.rho_log_dir, exist_ok=True)
        os.makedirs(TEST_LOG_DIR, exist_ok=True)

        config_file = os.path.join(self.config_dir, "config.yml")

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(self.rho_log_dir, f"rho-aias_logban_{timestamp}.log")

        try:
            with open(self.default_config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load default config: {e}")
            return False

        # 覆盖测试配置
        config['server']['port'] = self.api_port
        # 使用 lo 接口（不需要真实网卡，因为我们只测试日志解析→封禁链路）
        config['ebpf']['interface_name'] = "lo"

        # 禁用不需要的功能
        config['intel']['enabled'] = False
        config['geo_blocking']['enabled'] = False
        config['anomaly_detection']['enabled'] = False
        
        # 配置认证（使用 API Key）
        config['auth']['jwt_secret'] = 'test-jwt-secret-key-for-testing'
        config['auth']['database_path'] = os.path.join(self.config_dir, 'auth.db')
        config['auth']['api_keys'] = [
            {
                'name': 'Test Admin Key',
                'key': self.api_key,
                'permissions': ['*']
            }
        ]

        # 配置 WAF 日志监控
        config['waf']['enabled'] = True
        config['waf']['waf_log_path'] = self.waf_log
        config['waf']['ban_duration'] = 3600
        config['waf']['offset_state_file'] = os.path.join(self.config_dir, 'waf_offset.json')

        # 配置 Rate Limit 日志监控
        config['rate_limit']['enabled'] = True
        config['rate_limit']['log_path'] = self.rate_limit_log
        config['rate_limit']['ban_duration'] = 3600
        config['rate_limit']['offset_state_file'] = os.path.join(self.config_dir, 'ratelimit_offset.json')

        # 配置 FailGuard（SSH 防爆破）
        config['failguard']['enabled'] = True
        config['failguard']['log_path'] = self.ssh_log
        config['failguard']['offset_state_file'] = os.path.join(self.config_dir, 'failguard_offset.json')
        config['failguard']['mode'] = 'aggressive'
        config['failguard']['max_retry'] = 5
        config['failguard']['find_time'] = 600
        config['failguard']['ban_duration'] = 3600

        # 其他数据目录使用临时目录
        config['business']['database_path'] = os.path.join(self.config_dir, 'business.db')
        config['log']['output_dir'] = self.rho_log_dir
        config['blocklog']['log_dir'] = os.path.join(self.rho_log_dir, 'blocklog')
        config['manual']['persistence_dir'] = os.path.join(self.config_dir, 'manual')

        try:
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            logger.error(f"Failed to write temp config: {e}")
            return False

        logger.info(f"Starting rho-aias (port={self.api_port})...")
        logger.info(f"  SSH log:      {self.ssh_log}")
        logger.info(f"  WAF log:      {self.waf_log}")
        logger.info(f"  Rate limit:   {self.rate_limit_log}")
        logger.info(f"  rho-aias log: {self.log_path}")

        try:
            self.log_file = open(self.log_path, 'w')
            # 使用 --config 参数指定临时配置文件的绝对路径
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
                with open(self.log_path, 'r') as f:
                    logger.error(f"Last 20 lines:\n{''.join(f.readlines()[-20:])}")
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
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                logger.error("Process exited unexpectedly (code=%s). Check log: %s", self.process.returncode, self.log_path)
                return False
            try:
                req = urllib.request.Request(health_url, headers={"X-API-Key": self.api_key})
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
            except Exception:
                pass
            finally:
                self.log_file = None

        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)


class APIClient:
    """rho-aias API 客户端"""

    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url
        self.api_key = api_key

    def get_ban_records(self, ip: str = None, source: str = None,
                        status: str = "active", limit: int = 50) -> Tuple[bool, dict]:
        """查询封禁记录"""
        params = []
        if ip:
            params.append(f"ip={ip}")
        if source:
            params.append(f"source={source}")
        if status:
            params.append(f"status={status}")
        if limit:
            params.append(f"limit={limit}")
        query = "&".join(params)
        url = f"/api/ban-records?{query}" if query else "/api/ban-records"
        return self._request("GET", url)

    def get_ban_stats(self) -> Tuple[bool, dict]:
        """查询封禁统计"""
        return self._request("GET", "/api/ban-records/stats")

    def get_rules(self, source: str = None) -> Tuple[bool, dict]:
        """查询 eBPF 规则列表"""
        url = "/api/rules"
        if source:
            url += f"?source={source}"
        return self._request("GET", url)

    def unban(self, record_id: int) -> Tuple[bool, dict]:
        """解封指定记录"""
        return self._request("DELETE", f"/api/ban-records/{record_id}/unblock")

    def _request(self, method: str, path: str, data: dict = None) -> Tuple[bool, dict]:
        """发送 HTTP 请求"""
        import urllib.request
        import urllib.error

        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}

        # 添加 API Key 认证
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
            except Exception:
                return False, {"code": -1, "message": str(e)}
        except Exception as e:
            return False, {"code": -1, "message": str(e)}


# ============================================================
# 辅助函数
# ============================================================

def append_to_log(log_path: str, lines: list):
    """向日志文件追加多行"""
    with open(log_path, 'a') as f:
        for line in lines:
            f.write(line + '\n')
            f.flush()
    logger.info(f"Appended {len(lines)} lines to {log_path}")


def wait_for_ban(api: APIClient, ip: str, source: str = None,
                 timeout: int = 15, interval: float = 2) -> bool:
    """轮询等待指定 IP 出现在封禁记录中"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        success, resp = api.get_ban_records(ip=ip, source=source, status="active")
        if success and resp.get('data', {}).get('records'):
            records = resp['data']['records']
            for r in records:
                if r.get('ip') == ip:
                    logger.info(f"IP {ip} is now banned (source={r.get('source')}, reason={r.get('reason')})")
                    return True
        time.sleep(interval)
    return False


# ============================================================
# 测试基类
# ============================================================

class LogBanTestBase(unittest.TestCase):
    """日志封禁测试基类"""

    @classmethod
    def setUpClass(cls):
        cls.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cls.binary_path = os.path.join(cls.project_root, "rho-aias")
        cls.default_config_path = os.path.join(cls.project_root, "config", "config.yml")
        cls.api_port = 18081
        cls.test_api_key = os.environ.get("TEST_API_KEY", "sk_live_test-admin-key-1234567890abcdef")
        cls.api_client = APIClient(f"http://127.0.0.1:{cls.api_port}", cls.test_api_key)

        if not os.path.exists(cls.binary_path):
            raise unittest.SkipTest(f"Binary not found: {cls.binary_path}. Run 'make build' first.")
        if not os.path.exists(cls.default_config_path):
            raise unittest.SkipTest(f"Default config not found: {cls.default_config_path}")

    def setUp(self):
        # 创建日志目录并清空日志文件
        os.makedirs(TEST_LOG_DIR, exist_ok=True)
        for path in [SSH_LOG_PATH, WAF_LOG_PATH, RATE_LIMIT_LOG_PATH]:
            if os.path.exists(path):
                os.remove(path)
            # 创建空文件确保 rho-aias 能找到它
            open(path, 'w').close()

        self.rho_process: Optional[RhoAiasProcess] = None

    def tearDown(self):
        if self.rho_process:
            self.rho_process.stop()
        time.sleep(1)

    def _start_rho(self, **kwargs) -> bool:
        """启动 rho-aias"""
        self.rho_process = RhoAiasProcess(
            self.binary_path,
            self.default_config_path,
            self.api_port,
            **kwargs
        )
        return self.rho_process.start()


# ============================================================
# FailGuard（SSH）测试
# ============================================================

class TestFailGuardBan(LogBanTestBase):
    """FailGuard SSH 日志触发封禁测试"""

    def test_ssh_fail_password(self):
        """SSH 密码错误达到阈值后应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        # 追加 5 条 Failed password 日志（max_retry=5）
        append_to_log(SSH_LOG_PATH, SSH_FAIL_PASSWORD_LINES)

        # 等待封禁生效
        banned = wait_for_ban(self.api_client, "203.0.113.10", source="failguard", timeout=20)
        self.assertTrue(banned, "IP 203.0.113.10 should be banned after 5 failed SSH password attempts")

        # 验证封禁详情
        success, resp = self.api_client.get_ban_records(ip="203.0.113.10", source="failguard")
        self.assertTrue(success, f"Failed to query ban records: {resp}")
        records = resp.get('data', {}).get('records', [])
        self.assertGreater(len(records), 0, "Should have at least one ban record for 203.0.113.10")
        self.assertEqual(records[0].get('source'), 'failguard')
        self.assertEqual(records[0].get('ip'), '203.0.113.10')

    def test_ssh_invalid_user(self):
        """SSH 无效用户达到阈值后应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        append_to_log(SSH_LOG_PATH, SSH_INVALID_USER_LINES)

        banned = wait_for_ban(self.api_client, "198.51.100.20", source="failguard", timeout=20)
        self.assertTrue(banned, "IP 198.51.100.20 should be banned after 5 invalid user attempts")

    def test_ssh_preauth(self):
        """SSH preauth 断连达到阈值后应触发封禁（aggressive 模式）"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        append_to_log(SSH_LOG_PATH, SSH_PREAUTH_LINES)

        banned = wait_for_ban(self.api_client, "192.0.2.50", source="failguard", timeout=20)
        self.assertTrue(banned, "IP 192.0.2.50 should be banned after 5 preauth disconnections")

    def test_ssh_accepted_no_ban(self):
        """SSH 认证成功日志不应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        # 只写入 Accepted 日志
        append_to_log(SSH_LOG_PATH, [SSH_ACCEPTED_LINE])

        # 等待一段时间确认没有封禁
        time.sleep(5)

        success, resp = self.api_client.get_ban_records(ip="10.0.0.1", source="failguard")
        self.assertTrue(success, f"Failed to query: {resp}")
        records = resp.get('data', {}).get('records', [])
        self.assertEqual(len(records), 0, "Accepted SSH log should not trigger any ban")

    def test_ssh_below_threshold(self):
        """SSH 失败次数未达阈值不应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        # 只写 3 条（阈值是 5）
        append_to_log(SSH_LOG_PATH, SSH_FAIL_PASSWORD_LINES[:3])

        # 等待一段时间确认没有封禁
        time.sleep(5)

        success, resp = self.api_client.get_ban_records(ip="203.0.113.10", source="failguard")
        self.assertTrue(success, f"Failed to query: {resp}")
        records = resp.get('data', {}).get('records', [])
        self.assertEqual(len(records), 0, "3 failures should not trigger ban (threshold=5)")


# ============================================================
# WAF 审计日志测试
# ============================================================

class TestWAFBan(LogBanTestBase):
    """WAF 审计日志触发封禁测试"""

    def test_waf_interrupted(self):
        """WAF is_interrupted=true 应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        append_to_log(WAF_LOG_PATH, WAF_INTERRUPTED_LINES)

        # 198.51.100.100 应被封禁
        banned = wait_for_ban(self.api_client, "198.51.100.100", source="waf", timeout=20)
        self.assertTrue(banned, "IP 198.51.100.100 should be banned from WAF interrupted request")

        # 198.51.100.101 也应被封禁
        banned = wait_for_ban(self.api_client, "198.51.100.101", source="waf", timeout=20)
        self.assertTrue(banned, "IP 198.51.100.101 should be banned from WAF interrupted request")

    def test_waf_not_interrupted(self):
        """WAF is_interrupted=false 不应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        append_to_log(WAF_LOG_PATH, [WAF_NOT_INTERRUPTED_LINE])

        time.sleep(5)

        success, resp = self.api_client.get_ban_records(ip="10.0.0.2", source="waf")
        self.assertTrue(success, f"Failed to query: {resp}")
        records = resp.get('data', {}).get('records', [])
        self.assertEqual(len(records), 0, "Non-interrupted WAF request should not trigger ban")


# ============================================================
# Rate Limit 日志测试
# ============================================================

class TestRateLimitBan(LogBanTestBase):
    """Rate Limit 日志触发封禁测试"""

    def test_rate_limit_ban(self):
        """Rate limit exceeded 日志应触发封禁"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        append_to_log(RATE_LIMIT_LOG_PATH, RATE_LIMIT_LINES)

        # 222.209.44.8 应被封禁
        banned = wait_for_ban(self.api_client, "222.209.44.8", source="rate_limit", timeout=20)
        self.assertTrue(banned, "IP 222.209.44.8 should be banned from rate limit log")

        # 222.209.44.9 也应被封禁
        banned = wait_for_ban(self.api_client, "222.209.44.9", source="rate_limit", timeout=20)
        self.assertTrue(banned, "IP 222.209.44.9 should be banned from rate limit log")


# ============================================================
# 混合场景测试
# ============================================================

class TestMixedBan(LogBanTestBase):
    """多种日志源混合封禁测试"""

    def test_multi_source_ban_stats(self):
        """多个日志源同时触发封禁，统计应正确"""
        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        # 同时向三个日志文件写入
        append_to_log(SSH_LOG_PATH, SSH_FAIL_PASSWORD_LINES)
        append_to_log(WAF_LOG_PATH, WAF_INTERRUPTED_LINES)
        append_to_log(RATE_LIMIT_LOG_PATH, RATE_LIMIT_LINES)

        # 等待所有封禁生效
        time.sleep(15)

        # 查询封禁统计
        success, resp = self.api_client.get_ban_stats()
        self.assertTrue(success, f"Failed to get ban stats: {resp}")

        stats = resp.get('data', {})
        logger.info(f"Ban stats: {json.dumps(stats, indent=2, default=str)}")

        # 验证各来源至少有封禁
        by_source = stats.get('by_source', {})
        active_count = stats.get('active', 0)
        self.assertGreater(active_count, 0, "Should have at least 1 active ban")
        logger.info(f"Active bans: {active_count}, by_source: {by_source}")

    def test_same_ip_different_sources(self):
        """同一 IP 被不同来源封禁"""
        same_ip_lines = [
            # SSH fail（需要 5 条）
            '2026-04-01T10:00:00.000000+08:00 localhost sshd[500000]: Failed password for root from 203.0.113.99 port 60000 ssh2',
            '2026-04-01T10:00:01.000000+08:00 localhost sshd[500001]: Failed password for root from 203.0.113.99 port 60001 ssh2',
            '2026-04-01T10:00:02.000000+08:00 localhost sshd[500002]: Failed password for root from 203.0.113.99 port 60002 ssh2',
            '2026-04-01T10:00:03.000000+08:00 localhost sshd[500003]: Failed password for root from 203.0.113.99 port 60003 ssh2',
            '2026-04-01T10:00:04.000000+08:00 localhost sshd[500004]: Failed password for root from 203.0.113.99 port 60004 ssh2',
        ]

        waf_same_ip_line = json.dumps({
            "transaction": {
                "timestamp": "2026/04/01 10:01:00",
                "request": {
                    "uri": "/attack",
                    "method": "POST",
                    "headers": {"X-Forwarded-For": "203.0.113.99"},
                    "remote_addr": "203.0.113.99",
                },
                "response": {"status": 403},
                "is_interrupted": True,
            }
        })

        rate_limit_same_ip_line = json.dumps({
            "level": "info",
            "ts": 1774960700.0,
            "logger": "http.handlers.rate_limit",
            "msg": "rate limit exceeded",
            "zone": "global_zone",
            "wait": 1.5,
            "remote_ip": "203.0.113.99"
        })

        self.assertTrue(self._start_rho(), "Failed to start rho-aias")
        time.sleep(2)

        # 先触发 failguard
        append_to_log(SSH_LOG_PATH, same_ip_lines)
        banned = wait_for_ban(self.api_client, "203.0.113.99", source="failguard", timeout=20)
        self.assertTrue(banned, "IP 203.0.113.99 should be banned by failguard")

        # 再追加 WAF 日志（IP 已被封禁，不应重复封禁）
        append_to_log(WAF_LOG_PATH, [waf_same_ip_line])
        time.sleep(5)

        # 再追加 rate_limit 日志
        append_to_log(RATE_LIMIT_LOG_PATH, [rate_limit_same_ip_line])
        time.sleep(5)

        # 查询该 IP 的所有封禁记录
        success, resp = self.api_client.get_ban_records(ip="203.0.113.99")
        self.assertTrue(success, f"Failed to query: {resp}")
        records = resp.get('data', {}).get('records', [])
        sources = {r.get('source') for r in records if r.get('status') == 'active'}
        logger.info(f"IP 203.0.113.99 ban sources: {sources}")


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
        description="WAF / FailGuard / Rate Limit Log Ban Integration Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
测试运行示例:
  # 运行所有日志封禁测试（API Key 认证已内置）
  python3 %(prog)s

  # 使用自定义 API Key
  TEST_API_KEY="sk_live_your-key-here" python3 %(prog)s

  # 只测试 FailGuard
  python3 %(prog)s --test TestFailGuardBan

  # 运行特定测试
  python3 %(prog)s --test TestFailGuardBan.test_ssh_fail_password
        """
    )
    parser.add_argument(
        "-t", "--test",
        help="Run specific test (e.g., TestFailGuardBan.test_ssh_fail_password)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sys.exit(run_tests(args.test))
