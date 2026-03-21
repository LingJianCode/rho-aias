# 运行

> 注意：由于caddy运行为非root用户，logs目录的权限需要修改一下。使用命令`docker run --rm my-caddy:001 id caddy`查看caddy的uid，然后`chown uid:uid logs`

```bash
docker run --rm \
  --name caddy \
  -p 8080:8080 \
  -v $(pwd)/Caddyfile:/etc/caddy/Caddyfile \
  -v $(pwd)/logs:/logs \
  my-caddy:001
```

# 压测

```bash
ab -n 100 -c 50 http://localhost:8080/
```

# waf防护测试

```bash
curl -i "http://localhost:8080/?q=<script>alert('XSS')</script>"
```
