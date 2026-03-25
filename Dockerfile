# ---------- 构建阶段 ----------
FROM golang:1.25-alpine AS builder
ENV GOPRIVATE="cnb.cool"
ENV GOPROXY="https://goproxy.cn,direct"

# 安装构建依赖（包含 LLVM、bpftool 和 libbpf 用于 eBPF）
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache git build-base linux-headers clang llvm lld bpftool libbpf-dev

# 设置工作目录
WORKDIR /build

# 复制依赖文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 生成 vmlinux.h（CO-RE 头文件）
# 方法1: 尝试从内核 BTF 生成（如果宿主机支持）
# 方法2: 使用 linux-headers 中的头文件创建符号链接
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h; \
    elif [ -f /usr/src/linux-headers-$(uname -r)/include/uapi/linux/vmlinux.h ]; then \
        ln -s /usr/src/linux-headers-$(uname -r)/include/uapi/linux/vmlinux.h ebpfs/vmlinux.h; \
    else \
        # 创建最小化的 vmlinux.h（用于编译时类型检查）\
        echo "/* CO-RE stub vmlinux.h - generated for build */" > ebpfs/vmlinux.h; \
        echo "#include <linux/types.h>" >> ebpfs/vmlinux.h; \
        echo "#include <linux/pkt_cls.h>" >> ebpfs/vmlinux.h; \
    fi

# 生成 eBPF 字节码
RUN go generate ./internal/ebpfs/...

# 构建二进制文件
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o rho-aias ./main.go

# ---------- 运行阶段 ----------
FROM alpine:3.20

# 安装运行依赖和时区数据
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache ca-certificates tzdata

# 创建必要目录
RUN mkdir -p /app/config /app/logs /app/data

# 拷贝二进制文件
COPY --from=builder /build/rho-aias /usr/bin/rho-aias

# 工作目录
WORKDIR /app

# 默认端口
EXPOSE 8081

# 启动命令
ENTRYPOINT ["/usr/bin/rho-aias"]
