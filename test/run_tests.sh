#!/bin/bash
#
# eBPF XDP IP 阻断功能集成测试运行脚本
#
# 使用方法:
#   ./run_tests.sh              # 运行所有测试（不使用认证）
#   ./run_tests.sh --use-api-key # 使用 API Key 认证运行测试
#   ./run_tests.sh --use-api-key --api-key sk_live_your-key-here # 使用指定 API Key
#   ./run_tests.sh --env-only   # 仅运行环境测试（不需要编译 rho-aias）
#   ./run_tests.sh -t TestXDPIpBlocking.test_01_ipv4_exact_block  # 运行特定测试
#
# 前置条件:
#   1. Root 权限
#   2. 已编译 rho-aias (运行 make build)
#   3. Python 3.6+
#   4. Linux 内核 5.8+ (支持 BPF CO-RE)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此测试脚本需要 root 权限"
        log_info "请使用: sudo $0 $@"
        exit 1
    fi
}

# 检查 Python
check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "未找到 Python3，请先安装 Python 3.6+"
        exit 1
    fi
    log_info "Python 版本: $(python3 --version)"
}

# 检查二进制文件
check_binary() {
    if [[ ! -f "$PROJECT_ROOT/rho-aias" ]]; then
        log_warn "未找到 rho-aias 二进制文件"
        log_info "正在编译..."
        cd "$PROJECT_ROOT"
        make build
        cd "$SCRIPT_DIR"
    fi
    log_info "二进制文件: $PROJECT_ROOT/rho-aias"
}

# 检查内核版本
check_kernel() {
    kernel_version=$(uname -r | cut -d. -f1-2)
    required_version="5.8"
    
    if [[ $(echo -e "$kernel_version\n$required_version" | sort -V | head -n1) != "$required_version" ]]; then
        log_warn "内核版本 $kernel_version 可能不支持 BPF CO-RE，建议 5.8+"
    else
        log_info "内核版本: $(uname -r)"
    fi
}

# 清理函数
cleanup() {
    log_info "清理测试环境..."
    
    # 删除可能的残留 namespace
    for ns in $(ip netns list | grep "rho_" | cut -d' ' -f1); do
        ip netns del "$ns" 2>/dev/null || true
    done
    
    # 删除可能的残留 veth
    for veth in $(ip link show | grep -oE "rho_[^:]+"); do
        ip link del "$veth" 2>/dev/null || true
    done
    
    # 删除临时配置
    rm -f /tmp/rho_test_config.yml
    rm -f /tmp/config.yml
    
    log_info "清理完成"
}

# 运行测试
run_tests() {
    local use_api_key=false
    local api_key=""
    local other_args=()
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --use-api-key)
                use_api_key=true
                shift
                ;;
            --api-key)
                api_key="$2"
                shift 2
                ;;
            *)
                other_args+=("$1")
                shift
                ;;
        esac
    done
    
    cd "$SCRIPT_DIR"
    
    # 如果使用 API Key 认证
    if [ "$use_api_key" = true ]; then
        log_info "启用 API Key 认证测试"
        
        # 如果指定了 API Key，传递给 Python 脚本
        if [ -n "$api_key" ]; then
            log_info "使用指定的 API Key"
            python3 test_xdp_block.py --use-api-key --api-key "$api_key" "${other_args[@]}"
        elif [ -n "$TEST_API_KEY" ]; then
            log_info "使用环境变量 TEST_API_KEY"
            python3 test_xdp_block.py --use-api-key "${other_args[@]}"
        else
            log_info "使用默认测试 API Key"
            python3 test_xdp_block.py --use-api-key "${other_args[@]}"
        fi
    else
        # 不使用 API Key 认证，只运行 TestXDPIpBlocking 测试
        python3 test_xdp_block.py -t TestXDPIpBlocking "${other_args[@]}"
    fi
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo "========================================"
        log_info "测试完成"
        return 0
    else
        echo "========================================"
        log_error "测试失败"
        return 1
    fi
}

# 主函数
main() {
    log_info "=========================================="
    log_info "eBPF XDP IP 阻断功能集成测试"
    log_info "=========================================="
    
    # 环境检查
    check_root "$@"
    check_python
    check_kernel
    
    # 如果不是仅环境测试，检查二进制文件
    if [[ "$*" != *"--env-only"* ]]; then
        check_binary
    fi
    
    # 设置清理 trap
    trap cleanup EXIT
    
    # 清理之前可能的残留
    cleanup
    
    # 运行测试
    run_tests "$@"
}

main "$@"
