# docker-proxy

轻量多 Registry Docker 代理服务，纯 Python 实现，零依赖。

## 支持的 Registry

| 前缀 | 上游 Registry |
|------|-------------|
| 默认 | Docker Hub (registry-1.docker.io) |
| `ghcr.` | GitHub Container Registry (ghcr.io) |
| `quay.` | Quay.io |
| `gcr.` | Google Container Registry (gcr.io) |
| `k8s-gcr.` | K8s GCR (k8s.gcr.io) |
| `k8s.` | K8s Registry (registry.k8s.io) |
| `nvcr.` | NVIDIA Container Registry (nvcr.io) |
| `cloudsmith.` | Cloudsmith (docker.cloudsmith.io) |

## 功能

- **多 Registry 代理** — 一个端口代理所有主流 Registry
- **官方镜像自动 library/ 前缀** — `docker pull python:3.12` 直接可用
- **Token 自动换取** — 透明处理认证流程，支持多 Registry 认证服务器
- **浏览器透传** — 访问首页展示 Docker Hub 页面
- **DSM/群晖兼容** — `/v1/search` 搜索 API 正确转发
- **%3A 编码修复** — 兼容各种 Docker 客户端
- **CORS 预检** — OPTIONS 请求正确响应
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
mkdir -p /opt/docker-proxy
cp server.py /opt/docker-proxy/

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

`/etc/docker/daemon.json`：

```json
{
  "registry-mirrors": ["https://your-domain.com"]
}
```

重启 Docker 后直接拉取：

```bash
# Docker Hub 官方镜像
docker pull python:alpine3.23
docker pull nginx:latest

# Docker Hub 用户镜像
docker pull cloudflare/cloudflared:latest

# GitHub Container Registry
docker pull ghcr.io/owner/repo:tag
```

## 高级用法

通过 `ns=` 参数动态指定 Registry（不依赖子域名）：

```bash
# 通过 ns 参数访问 GHCR
curl https://your-domain.com/v2/owner/repo/manifests/latest?ns=ghcr.io
```

## 反向代理

nginx 配置：

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
客户端请求                      代理服务
  │                              │
  ├─ /v2/                        → registry 2.0 handshake
  ├─ /v2/python/manifests/...    → 补 library/ + 换 token → Docker Hub
  ├─ /v2/ghcr/owner/repo/...     → 转发 ghcr.io + 换 GHCR token
  ├─ /v2/nginx/blobs/...         → 换 token → 重定向透传 CDN
  ├─ /v1/search?q=nginx          → index.docker.io 搜索 API
  ├─ /token                      → auth.docker.io 认证
  ├─ / (浏览器)                  → 透传 hub.docker.com
  └─ OPTIONS                     → CORS 预检 204
```
