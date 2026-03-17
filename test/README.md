# eBPF XDP IP 阻断功能集成测试

本测试套件使用 Python 编写，通过 Linux Network Namespace 模拟网络环境，测试 rho-aias 的 eBPF XDP IP 阻断核心功能。

## 前置条件

1. **Root 权限** - 创建 network namespace 和加载 eBPF 程序需要 root 权限
2. **Linux 内核 5.8+** - 支持 BPF CO-RE (Compile Once, Run Everywhere)
3. **Python 3.6+** - 测试脚本运行环境
4. **已编译的 rho-aias** - 运行 `make build` 编译

## 快速开始

```bash
# 运行所有测试
sudo ./test/run_tests.sh

# 仅运行环境测试（验证 network namespace 功能，不需要编译 rho-aias）
sudo ./test/run_tests.sh --env-only

# 运行特定测试
sudo ./test/run_tests.sh -t TestXDPIpBlocking.test_01_ipv4_exact_block

# 详细输出模式
sudo ./test/run_tests.sh -v
```

## 测试文件说明

| 文件 | 说明 |
|------|------|
| `run_tests.sh` | 测试运行脚本，包含环境检查和清理逻辑 |
| `test_xdp_block.py` | 主测试脚本，包含所有测试用例 |
| `netns.py` | Network Namespace 管理模块 |

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

## 单独运行 Python 测试

```bash
# 直接运行 Python 测试脚本
cd test
sudo python3 test_xdp_block.py

# 运行特定测试类
sudo python3 test_xdp_block.py TestEnvironmentSetup

# 运行特定测试方法
sudo python3 test_xdp_block.py TestXDPIpBlocking.test_01_ipv4_exact_block
```

## 常见问题

### 1. 权限错误

```
ERROR: This test requires root privileges
```

**解决方法**: 使用 `sudo` 运行测试脚本。

### 2. 二进制文件未找到

```
Binary not found: /workspace/rho-aias
```

**解决方法**: 先编译程序
```bash
make build
```

### 3. 内核版本不支持

```
WARN: 内核版本 4.x 可能不支持 BPF CO-RE
```

**解决方法**: 升级内核到 5.8 或更高版本。

### 4. Network Namespace 残留

如果上次测试异常退出，可能有残留的 namespace：

```bash
# 手动清理
ip netns list | grep rho_ | awk '{print $1}' | xargs -I {} ip netns del {}
```

## 测试配置

测试使用临时配置文件，每次运行时自动生成：

- **API 端口**: 18080（避免与生产端口冲突）
- **认证**: 关闭
- **情报源**: 关闭
- **地域封禁**: 关闭
- **手动规则持久化**: 关闭

## 注意事项

1. **阻断事件上报已关闭** - 测试配置中 `bpf_perf_event_output` 被注释，不会产生大量事件数据
2. **端口冲突** - 如果 18080 端口被占用，修改 `test_xdp_block.py` 中的 `api_port`
3. **测试隔离** - 每个测试用例都会创建独立的环境，测试结束后自动清理
