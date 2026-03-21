# ---------- 构建阶段 ----------
FROM golang:1.25-alpine AS builder
ENV GOPRIVATE="cnb.cool"
ENV GOPROXY="https://goproxy.cn,direct"
# 安装必要工具
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && apk add --no-cache git build-base

# 安装 xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# 构建带插件的 caddy
RUN xcaddy build \
    --with github.com/mholt/caddy-ratelimit \
    --with github.com/corazawaf/coraza-caddy/v2 \
    --output /caddy

# ---------- 运行阶段 ----------
FROM alpine:3.20

# 安装运行依赖
RUN sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories && apk add --no-cache ca-certificates tzdata

# 创建非 root 用户（安全最佳实践）
RUN addgroup -S caddy && adduser -S -G caddy caddy

# 创建目录
RUN mkdir -p /etc/caddy /data /config /logs

# 拷贝 Caddy 二进制
COPY --from=builder /caddy /usr/bin/caddy

# 赋权
RUN chown -R caddy:caddy /etc/caddy /data /config /logs

# 切换用户
USER caddy

# 工作目录
WORKDIR /etc/caddy

# 默认端口
EXPOSE 80 443 8080

VOLUME ["/etc/caddy", "/data", "/config", "/logs"]

# 启动命令
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
