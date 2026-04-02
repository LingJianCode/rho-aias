# 运行

## 直接运行

```bash
docker run --rm \
  --name caddy \
  -p 8080:8080 \
  -v $(pwd)/config:/etc/caddy \
  -v $(pwd)/logs:/logs \
  my-caddy:001
```

## Docker Compose 运行

直接启动服务：

```bash
docker-compose up -d
```

# 压测

```bash
ab -n 100 -c 50 http://localhost:8080/
```

# waf防护测试

```bash
curl -i "http://localhost:8080/?q=<script>alert('XSS')</script>"
```

# caddy配置示例

## 返回字符串

```caddy
:8080 {
        import rate_limit_policy
        import waf
        respond "Hello World!" 200
}
```

## 返回客户端ip

```caddy
:8080, :8443 {
        import rate_limit_policy
        import waf
        respond "您的IP地址是: {remote_host}
"
}
```
