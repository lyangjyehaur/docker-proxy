# docker-proxy

轻量 Docker Hub 代理服务，纯 Python 实现，零依赖。

## 功能

- **Registry API 代理** — 自动为官方镜像添加 `library/` 前缀，无需手动指定
- **Token 自动换取** — 透明处理 Docker Hub 认证流程
- **浏览器透传** — 访问首页直接展示 Docker Hub 页面
- **重定向透传** — blob 下载的 CDN 签名 URL 直接传回客户端
- **零磁碟占用** — 纯代理，不做本地缓存
- **低内存** — 运行仅占 ~9MB 内存

## 使用

```bash
# 直接运行
python3 server.py

# 指定端口
PORT=8080 python3 server.py
```

## 部署（systemd）

```bash
# 复制文件
mkdir -p /opt/docker-proxy
cp server.py /opt/docker-proxy/

# 创建 systemd 服务
cat > /etc/systemd/system/docker-proxy.service << 'EOF'
[Unit]
Description=Docker Hub Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/docker-proxy
ExecStart=/usr/bin/python3 /opt/docker-proxy/server.py
Restart=always
RestartSec=5
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now docker-proxy
```

## 配合 Docker 使用

在需要使用代理的服务器上配置 `/etc/docker/daemon.json`：

```json
{
  "registry-mirrors": ["https://your-domain.com"]
}
```

重启 Docker 后即可直接拉取：

```bash
docker pull python:alpine3.23        # 自动走代理
docker pull nginx:latest             # 自动走代理
docker pull your-namespace/repo:tag  # 第三方镜像也支持
```

## 反向代理

建议使用 nginx/Caddy 反代并配置 HTTPS：

```nginx
server {
    listen 443 ssl;
    server_name docker.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
    }
}
```

## 工作原理

```
客户端请求                    代理服务
  │                            │
  ├─ /v2/                      → 返回 registry 2.0 handshake
  ├─ /v2/python/manifests/...  → 补 library/ + 换 token → registry-1.docker.io
  ├─ /v2/nginx/blobs/...       → 换 token → 重定向透传到 CDN
  └─ / (浏览器)                → 透传 hub.docker.com
```
