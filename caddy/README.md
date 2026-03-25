# 运行

## 直接运行

```bash
docker run --rm \
  --name caddy \
  -p 8080:8080 \
  -v $(pwd)/Caddyfile:/etc/caddy/Caddyfile \
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
