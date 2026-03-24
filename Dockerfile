# ---------- 构建阶段 ----------
FROM golang:1.25-alpine AS builder
ENV GOPRIVATE="cnb.cool"
ENV GOPROXY="https://goproxy.cn,direct"

# 安装构建依赖
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache git build-base linux-headers

# 设置工作目录
WORKDIR /build

# 复制依赖文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建二进制文件
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o rho-aias ./main.go

# ---------- 运行阶段 ----------
FROM alpine:3.20

# 安装运行依赖和时区数据
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && \
    apk add --no-cache ca-certificates tzdata

# 创建必要目录
RUN mkdir -p /app/config /app/logs /app/data /app/bpf

# 拷贝二进制文件
COPY --from=builder /build/rho-aias /usr/bin/rho-aias

# 工作目录
WORKDIR /app

# 默认端口
EXPOSE 8080

# 挂载点
VOLUME ["/app/config", "/app/logs", "/app/data", "/app/bpf"]

# 启动命令
ENTRYPOINT ["/usr/bin/rho-aias"]
