# docker-proxy

轻量多 Registry Docker Hub 代理服务，纯 Python 实现，零依赖。

## 功能

### 代理核心
- **多 Registry 代理** — 一个端口代理 Docker Hub、GHCR、Quay、GCR、K8s GCR、NVCR、Cloudsmith
- **官方镜像自动 library/ 前缀** — `docker pull python:alpine3.23` 直接可用
- **Token 自动换取** — 透明处理认证流程，支持多 Registry 认证服务器
- **浏览器透传** — 访问首页展示 Docker Hub 页面（可切换为 nginx 伪装页）
- **DSM/群晖兼容** — `/v1/search`、`/v2/search/repositories` 正确转发
- **%3A 编码修复** — 兼容各种 Docker 客户端
- **CORS 预检** — OPTIONS 请求正确响应
- **CDN 307 重定向透传** — blob 下载直接由客户端跟 CDN
- **X-Amz-Content-Sha256 头转发** — 支持 AWS S3 签名的 blob 请求
- **零磁碟占用** — 纯代理，不做本地缓存
- **低内存** — 运行仅占 ~10MB 内存

### 用户系统
- **匿名访问** — 按 IP 限速，配额可配置（默认 100/天）
- **注册用户** — `docker login` 登入，每用户独立配额和用量追踪
- **密码安全** — pbkdf2_hmac 10万次迭代哈希
- **401 挑战** — manifest 请求无 auth 返回 401，触发 Docker 客户端认证
- **429 限速** — 配额耗尽返回 429 + Retry-After

### Dashboard
- **深色主题 Web 面板** — 统计卡片、健康检查、用户管理、日志
- **认证保护** — token + cookie，可在面板直接修改
- **用户管理** — CRUD、配额调整、启用/停用、用量查看
- **Docker Hub 帐号管理** — 添加上游认证帐号，避免匿名限速
- **设置面板** — 匿名配额、Dashboard Token
- **健康检查** — auth.docker.io、registry-1.docker.io、hub.docker.com 连通性
- **日志面板** — 最近 50 条日志，带颜色分级
- **自动刷新** — 每 5 秒更新，正在编辑的输入框不会被覆盖

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | `3000` | 监听端口 |
| `MODE` | `transparent` | 首页模式：`transparent` 透传 Hub / `disguise` nginx 伪装页 |
| `BLOCK_UA` | `netcraft` | 屏蔽的爬虫 UA（逗号分隔） |
| `DASHBOARD_TOKEN` | (空) | Dashboard 访问令牌（可在面板修改） |
| `USERS_FILE` | `/opt/docker-proxy/users.json` | 用户数据文件 |
| `SETTINGS_FILE` | `/opt/docker-proxy/settings.json` | 设置文件 |
| `USAGE_FILE` | `/opt/docker-proxy/usage.json` | 用量数据文件 |
| `ACCOUNTS_FILE` | `/opt/docker-proxy/accounts.json` | Docker Hub 帐号文件 |

## 快速开始

```bash
# 直接运行
python3 server.py

# 指定端口和 Token
PORT=8080 DASHBOARD_TOKEN=mysecret python3 server.py
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
ExecStart=/usr/bin/python3 -u /opt/docker-proxy/server.py
Restart=always
RestartSec=5
Environment=PORT=3000
Environment=MODE=disguise
Environment=BLOCK_UA=netcraft
Environment=USERS_FILE=/opt/docker-proxy/users.json
Environment=SETTINGS_FILE=/opt/docker-proxy/settings.json
Environment=USAGE_FILE=/opt/docker-proxy/usage.json
Environment=ACCOUNTS_FILE=/opt/docker-proxy/accounts.json
StandardOutput=append:/var/log/docker-proxy.log
StandardError=append:/var/log/docker-proxy.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now docker-proxy
```

## Docker 客户端使用

```bash
# 注册用户登录
docker login your-domain.com
# 输入用户名和密码

# 拉取镜像
docker pull your-domain.com/python:alpine3.23
docker pull your-domain.com/nginx:latest
docker pull your-domain.com/cloudflare/cloudflared:latest

# GitHub Container Registry（通过子域名）
docker pull ghcr.your-domain.com/owner/repo:tag
```

## Dashboard

访问 `https://your-domain.com/dashboard` 管理代理：

- **Health** — 上游服务连通性和延迟
- **Hub Accounts** — Docker Hub 帐号（避免上游限速）
- **Users** — 注册用户管理（配额、用量、状态）
- **Settings** — 匿名配额、Dashboard Token
- **Logs** — 最近日志

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/api/status` | GET | 代理状态、统计、内存 |
| `/api/users` | GET/POST/PUT/DELETE | 用户 CRUD |
| `/api/users/<name>/usage` | GET | 用户用量详情 |
| `/api/accounts` | GET/POST/DELETE | Docker Hub 帐号管理 |
| `/api/settings` | GET/PUT | 代理设置 |
| `/api/logs` | GET | 最近日志 |

## 高级用法

### 动态 Registry 选择

通过 `ns=` 参数指定上游 Registry：

```bash
curl https://your-domain.com/v2/owner/repo/manifests/latest?ns=ghcr.io
```

### nginx 反向代理

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
客户端请求                         代理服务
  │                                 │
  ├─ /v2/ (无 auth)                 → 401 挑战，触发 docker login
  ├─ /v2/ (有 auth)                 → 验证用户 → 200
  ├─ /v2/python/manifests/latest    → 补 library/ + 换 token → Docker Hub
  ├─ /v2/nginx/blobs/sha256:...     → 307 CDN 重定向透传
  ├─ /v2/ghcr/owner/repo/...        → 转发 ghcr.io + 换 GHCR token
  ├─ /v1/search?q=nginx             → index.docker.io 搜索 API
  ├─ /v2/search/repositories        → hub.docker.com 搜索 API (DSM)
  ├─ / (浏览器)                     → 透传 hub.docker.com / nginx 伪装页
  ├─ /dashboard                     → 深色主题管理面板
  └─ OPTIONS                        → CORS 预检 204
```

## 文件结构

```
/opt/docker-proxy/
├── server.py           # 代理服务（单文件，零依赖）
├── users.json          # 注册用户数据
├── settings.json       # 代理设置
├── usage.json          # 用量追踪数据
└── accounts.json       # Docker Hub 帐号（上游认证）
```
