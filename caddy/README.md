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

> 注意：由于 Caddy 运行为非 root 用户，logs 目录的权限需要修改。

使用如下命令确定UID和GID
```bash
$ docker run --rm docker.cnb.cool/makecnbgreatagain/rho-aias/rho-aias-caddy:latest  id caddy
uid=100(caddy) gid=101(caddy) groups=101(caddy),101(caddy)
```

Caddy 容器中的用户 UID/GID 为 `100:101`，需要修改宿主机日志目录权限：


```bash
# 修改日志目录权限给 Caddy 用户
sudo chown -R 100:101 logs/caddy
```

然后启动服务：

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
