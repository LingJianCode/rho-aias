# ============================================================
#  阶段 1: 前端构建 (frontend-builder)
#  - 安装 Node.js 依赖
#  - 使用 Vite 打包 Vue 前端项目，生成 dist 目录
# ============================================================
FROM node:24-alpine AS frontend-builder

WORKDIR /web

# 复制前端依赖定义文件（利用 Docker 缓存层）
COPY web/package.json web/package-lock.json ./

# 安装依赖
RUN npm install --registry=https://registry.npmmirror.com

# 复制前端源码
COPY web/ ./

# 构建前端产物到 dist 目录
RUN npm run build


# ============================================================
#  阶段 2: 后端构建 (backend-builder)
#  - 复制前端构建产物 (dist) 到 Go 项目中
#  - 利用 Go embed 将前端资源嵌入二进制
#  - 编译 eBPF 字节码并构建最终可执行文件
# ============================================================
FROM golang:1.25-alpine AS backend-builder
ENV GOPRIVATE="cnb.cool"
ENV GOPROXY="https://goproxy.cn,direct"

# 安装构建依赖（包含 LLVM、bpftool 和 libbpf 用于 eBPF）
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache git build-base linux-headers clang llvm lld bpftool libbpf-dev

WORKDIR /build

# 复制 Go 依赖文件（利用 Docker 缓存层）
COPY go.mod go.sum ./

# 下载 Go 依赖
RUN go mod download

# 复制源代码（不含 web 目录中的 node_modules 等冗余文件）
COPY . .

# 将前一阶段前端产物内容复制到 internal/frontend/dist/（供 go:embed 引用）
COPY --from=frontend-builder /web/dist/. ./internal/frontend/dist/

# 生成 vmlinux.h（CO-RE 头文件）
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h; \
    elif [ -f /usr/src/linux-headers-$(uname -r)/include/uapi/linux/vmlinux.h ]; then \
        ln -s /usr/src/linux-headers-$(uname -r)/include/uapi/linux/vmlinux.h ebpfs/vmlinux.h; \
    else \
        echo "/* CO-RE stub vmlinux.h - generated for build */" > ebpfs/vmlinux.h; \
        echo "#include <linux/types.h>" >> ebpfs/vmlinux.h; \
        echo "#include <linux/pkt_cls.h>" >> ebpfs/vmlinux.h; \
    fi

# 生成 eBPF 字节码
RUN go generate ./internal/ebpfs/...

# 构建二进制文件（前端已通过 embed 嵌入其中）
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o rho-aias ./cmd/server


# ============================================================
#  阶段 3: 运行阶段 (runtime)
#  - 仅包含最终编译好的 Go 二进制文件
#  - 精简镜像体积，提升安全性和启动速度
# ============================================================
FROM alpine:3.20

# 安装运行时依赖和时区数据
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache ca-certificates tzdata

# 创建必要目录
RUN mkdir -p /app/config /app/logs /app/data

# 拷贝最终二进制文件
COPY --from=backend-builder /build/rho-aias /usr/bin/rho-aias

# 工作目录
WORKDIR /app

# 默认端口
EXPOSE 8081

# 启动命令
ENTRYPOINT ["/usr/bin/rho-aias"]
