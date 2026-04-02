# eBPF XDP IP 阻断功能集成测试

本测试套件使用 Python 编写，通过 Linux Network Namespace 模拟网络环境，测试 rho-aias 的核心功能：
- eBPF XDP IP 阻断功能
- DDoS 异常流量检测功能

## 前置条件

1. **Root 权限** - 创建 network namespace 和加载 eBPF 程序需要 root 权限
2. **Linux 内核 5.8+** - 支持 BPF CO-RE (Compile Once, Run Everywhere)
3. **Python 3.6+** - 测试脚本运行环境
4. **已编译的 rho-aias** - 运行 `make build` 编译

## 快速开始

### 基本测试（不使用认证）

```bash
# 运行所有测试
./test/run_tests.sh

# 仅运行环境测试（验证 network namespace 功能，不需要编译 rho-aias）
./test/run_tests.sh --env-only

# 运行特定测试
./test/run_tests.sh -t TestXDPIpBlocking.test_01_ipv4_exact_block

# 详细输出模式
./test/run_tests.sh -v
```

### API Key 认证测试

```bash
# 使用 API Key 认证运行测试（使用默认测试 Key）
./test/run_tests.sh --use-api-key

# 使用指定的 API Key
./test/run_tests.sh --use-api-key --api-key sk_live_your-key-here

# 使用环境变量中的 API Key
export TEST_API_KEY="sk_live_your-key-here"
./test/run_tests.sh --use-api-key

# 运行特定的 API Key 认证测试
./test/run_tests.sh --use-api-key -t TestAPIKeyAuth.test_01_api_key_auth
```

### DDoS 异常流量检测测试

```bash
# 运行所有 DDoS 检测测试
./test/run_tests.sh --ddos

# 仅运行环境测试（验证 network namespace 功能）
./test/run_tests.sh --ddos --env-only

# 运行特定 DDoS 测试
./test/run_tests.sh --ddos --test TestDDoSDetection.test_01_tcp_syn_flood
./test/run_tests.sh --ddos --test TestDDoSDetection.test_02_udp_flood
./test/run_tests.sh --ddos --test TestDDoSDetection.test_03_icmp_flood
./test/run_tests.sh --ddos --test TestDDoSDetection.test_04_ack_flood
./test/run_tests.sh --ddos --test TestDDoSDetection.test_05_control_without_detection
```
### 日志监控集成测试

```bash
./test/run_tests.sh --log-ban
```

**注意事项：**
- `--use-api-key` 参数启用 API Key 认证测试
- `--api-key` 参数指定测试用的 API Key（可选，优先级高于环境变量）
- 环境变量 `TEST_API_KEY` 也可以设置 API Key
- 不指定时使用默认测试 Key：`sk_live_test-admin-key-1234567890abcdef`

## 测试用例

### TestXDPIpBlocking - XDP 阻断功能测试

| 测试用例 | 描述 |
|---------|------|
| `test_01_ipv4_exact_block` | IPv4 精确匹配阻断 - 添加规则后验证阻断效果，删除后验证恢复 |
| `test_02_ipv4_cidr_block` | IPv4 CIDR 阻断 - 测试子网掩码匹配 |
| `test_03_multiple_rules` | 多条规则管理 - 添加/查询/删除多条规则 |
| `test_04_rule_persistence` | 规则 API 持久性 - 重复添加、删除不存在的规则 |
| `test_05_invalid_rule` | 无效规则处理 - 验证非法 IP 格式被拒绝 |

### TestEnvironmentSetup - 环境测试

| 测试用例 | 描述 |
|---------|------|
| `test_namespace_creation` | Network namespace 创建和删除 |
| `test_veth_pair_creation` | Veth pair 创建和 IP 配置 |
| `test_full_environment` | 完整环境连通性测试 |

### TestAPIKeyAuth - API Key 认证测试

| 测试用例 | 描述 |
|---------|------|
| `test_01_api_key_auth` | API Key 认证功能测试 - 使用 API Key 添加规则并验证生效 |
| `test_02_invalid_api_key` | 无效 API Key 测试 - 验证无效 Key 被拒绝 |
| `test_03_api_key_permissions` | API Key 权限测试 - 验证读写权限控制 |
| `test_04_api_key_without_auth` | 不启用认证时的 API Key 测试 - 验证 Key 在认证关闭时仍能工作 |

### TestDDoSDetection - DDoS 检测功能测试

| 测试用例 | 描述 |
|---------|------|
| `test_01_tcp_syn_flood` | TCP SYN Flood 检测 - 生成 SYN SYN 泛洪流量验证检测 |
| `test_02_udp_flood` | UDP Flood 检测 - 生成 UDP 泛洪流量验证检测 |
| `test_03_icmp_flood` | ICMP Flood 检测 - 生成 ICMP 泛洪流量验证检测 |
| `test_04_ack_flood` | ACK Flood 检测 - 生成 TCP ACK 泛洪流量验证检测 |
| `test_05_control_without_detection` | 对照组测试 - 不启用检测时系统正常运行 |

## 测试环境架构

```
+------------------+     +------------------+
|   主 Namespace   |     |   rho_test_ns1   |
|                  |     |                  |
| rho_xdp_test_veth0 <-------> rho_xdp_test_veth1 |
|  10.0.1.1       |     |  10.0.1.2        |
+------------------+     +------------------+
        |
        |  rho-aias 绑定到 veth0
        |  (XDP 程序在此加载)
        |
+------------------+     +------------------+
|   主 Namespace   |     |   rho_test_ns2   |
|                  |     |                  |
| rho_xdp_test_veth2 <-------> rho_xdp_test_veth3 |
|  10.0.2.1       |     |  10.0.2.2        |
+------------------+     +------------------+
```

## 测试脚本说明

| 文件 | 说明 |
|------|------|
| `run_tests.sh` | **推荐使用的测试入口脚本**，包含环境检查和清理逻辑 |
| `test_xdp_block.py` | XDP IP 阻断功能测试脚本（由 run_tests.sh 调用） |
| `test_ddosser_detection.py` | DDoS 检测功能测试脚本（由 run_tests.sh 调用） |
| `netns.py` | Network Namespace 管理模块 |

## 常见问题

###  Network Namespace 残留

如果上次测试异常退出，可能有残留的 namespace：

```bash
# 手动清理
ip netns list | grep rho_ | awk '{print $1}' | xargs -I {} ip netns del {}
```

## 测试配置

### XDP IP 阻断测试配置

测试使用临时配置文件，每次运行时自动生成：

- **API 端口**: 18080（避免与生产端口冲突）
- **认证**: 关闭
- **情报源**: 关闭
- **地域封禁**: 关闭
- **手动规则持久化**: 关闭

### DDoS 检测测试配置

- **API 端口**: 18080（避免与生产端口冲突）
- **异常检测**: 启用
- **采样率**: 100%（1:1）
- **检测间隔**: 1 秒
- **最小包数**: 50（测试用低阈值）
- **封禁时长**: 60 秒
- **攻击检测配置**:
  - SYN Flood: ratio_threshold=0.5, block_duration=60s
  - UDP Flood: ratio_threshold=0.7, block_duration=60s
  - ICMP Flood: ratio_threshold=0.5, block_duration=60s
  - ACK Flood: ratio_threshold=0.7, block_duration=60s

# 手动测试

- UDP ddos攻击：
```bash
hping3 -c 10000 -d 120 --udp -w 64 -p 80 --flood x.x.x.x
```

- ICMP ddos攻击：
```bash
hping3 -c 10000 -d 120 --icmp -w 64 -p 80 --flood x.x.x.x
```

- SYN ddos攻击：
```bash
hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood x.x.x.x
```

- ACK ddos攻击：
```bash
hping3 -c 10000 -d 120 -A -w 64 -p 80 --flood x.x.x.x
 ```