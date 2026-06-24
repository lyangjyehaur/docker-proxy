#!/usr/bin/env python3
"""Lightweight multi-registry Docker proxy.

Supports: Docker Hub, GHCR, Quay, GCR, K8s GCR, NVCR, Cloudsmith.
Transparent browser view, auto library/ prefix, token exchange, CORS.
Includes web dashboard, Docker Hub account management, and full user
management with per-user quotas and anonymous rate limiting.
"""

import http.server
import urllib.request
import urllib.error
import json
import re
import os
import ssl
import time
import base64
import hashlib
import threading
import resource
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(os.environ.get('PORT', 3000))

# MODE: transparent = real Docker Hub page, disguise = nginx-like page
MODE = os.environ.get('MODE', 'transparent')

# Block known crawler User-Agents
BLOCKED_UAS = ['netcraft']

# Extra UAs to block (comma-separated via env)
_extra_uas = os.environ.get('BLOCK_UA', '')
if _extra_uas:
    BLOCKED_UAS.extend([u.strip().lower() for u in _extra_uas.split(',') if u.strip()])

# Dashboard auth token (env var is fallback, settings file takes priority)
DASHBOARD_TOKEN = os.environ.get('DASHBOARD_TOKEN', '')

# Registry routing table
REGISTRY_ROUTES = {
    'quay':      'quay.io',
    'gcr':       'gcr.io',
    'k8s-gcr':   'k8s.gcr.io',
    'k8s':       'registry.k8s.io',
    'ghcr':      'ghcr.io',
    'cloudsmith': 'docker.cloudsmith.io',
    'nvcr':      'nvcr.io',
}

# Default upstream for Docker Hub
HUB_HOST = 'registry-1.docker.io'
AUTH_URL = 'https://auth.docker.io'

# Token cache: (auth_url, repo) -> { token, expires }
_token_cache = {}

# CORS preflight response
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS, POST, PUT, DELETE',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Max-Age': '1728000',
}

# ============================================================
# Request statistics tracking
# ============================================================
STATS = {
    'total_requests': 0,
    'success_count': 0,
    'error_count': 0,
    'start_time': time.time(),
    'authenticated_pulls': 0,
    'anonymous_pulls': 0,
}
_stats_lock = threading.Lock()

def stats_increment(key):
    with _stats_lock:
        STATS[key] = STATS.get(key, 0) + 1

# ============================================================
# Log buffer (ring buffer, last 200 entries)
# ============================================================
LOG_BUFFER = []
_log_lock = threading.Lock()
MAX_LOG_ENTRIES = 200

def add_log(level, message):
    entry = {
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'level': level,
        'message': message,
    }
    with _log_lock:
        LOG_BUFFER.append(entry)
        if len(LOG_BUFFER) > MAX_LOG_ENTRIES:
            LOG_BUFFER.pop(0)

# ============================================================
# Proxy Settings (stored in settings.json)
# ============================================================
SETTINGS_FILE = os.environ.get('SETTINGS_FILE', '/opt/docker-proxy/settings.json')
_settings_lock = threading.Lock()

DEFAULT_SETTINGS = {
    'anonymous_daily_pulls': 100,
    'dashboard_token': os.environ.get('DASHBOARD_TOKEN', ''),
}

def _load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    merged = dict(DEFAULT_SETTINGS)
                    merged.update(data)
                    return merged
    except Exception as e:
        print(f'[WARN] Failed to load settings: {e}')
    return dict(DEFAULT_SETTINGS)

def _save_settings(settings):
    try:
        dirname = os.path.dirname(SETTINGS_FILE)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f'[WARN] Failed to save settings: {e}')

def get_settings():
    with _settings_lock:
        return _load_settings()

def update_settings(patch):
    with _settings_lock:
        settings = _load_settings()
        settings.update(patch)
        _save_settings(settings)
        return settings

# ============================================================
# Password hashing (pbkdf2_hmac, 100k iterations, sha256)
# ============================================================
PBKDF2_ITERATIONS = 100000
PBKDF2_SALT_BYTES = 16

def hash_password(password):
    """Hash a password with pbkdf2_hmac. Returns 'iterations:salt_hex:hash_hex'."""
    salt = os.urandom(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS)
    return f'{PBKDF2_ITERATIONS}:{salt.hex()}:{dk.hex()}'

def verify_password(password, stored_hash):
    """Verify a password against a stored hash."""
    try:
        parts = stored_hash.split(':')
        if len(parts) != 3:
            return False
        iterations = int(parts[0])
        salt = bytes.fromhex(parts[1])
        expected = bytes.fromhex(parts[2])
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        return dk == expected
    except Exception:
        return False

# ============================================================
# User management (users.json)
# ============================================================
USERS_FILE = os.environ.get('USERS_FILE', '/opt/docker-proxy/users.json')
_users_lock = threading.Lock()

def _load_users():
    """Load users from JSON file."""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
    except Exception as e:
        print(f'[WARN] Failed to load users: {e}')
    return []

def _save_users(users):
    """Save users to JSON file."""
    try:
        dirname = os.path.dirname(USERS_FILE)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        print(f'[WARN] Failed to save users: {e}')

def get_users():
    """Get list of users (thread-safe)."""
    with _users_lock:
        return _load_users()

def get_user(username):
    """Get a single user by username."""
    with _users_lock:
        for u in _load_users():
            if u['username'] == username:
                return u
    return None

def add_user(username, password, daily_pull_quota=500):
    """Add a new user. Returns the user dict or None on error."""
    with _users_lock:
        users = _load_users()
        for u in users:
            if u['username'] == username:
                return None  # already exists
        today = time.strftime('%Y-%m-%d')
        new_user = {
            'username': username,
            'password_hash': hash_password(password),
            'daily_pull_quota': daily_pull_quota,
            'pull_count_today': 0,
            'last_reset_date': today,
            'created_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'last_pull': None,
            'is_active': True,
        }
        users.append(new_user)
        _save_users(users)
        return new_user

def update_user(username, **kwargs):
    """Update user fields. Returns updated user or None."""
    with _users_lock:
        users = _load_users()
        for u in users:
            if u['username'] == username:
                for k, v in kwargs.items():
                    if k == 'password' and v:
                        u['password_hash'] = hash_password(v)
                    elif k in ('daily_pull_quota', 'is_active'):
                        u[k] = v
                _save_users(users)
                return u
    return None

def delete_user(username):
    """Delete a user. Returns True if deleted."""
    with _users_lock:
        users = _load_users()
        new_users = [u for u in users if u['username'] != username]
        if len(new_users) < len(users):
            _save_users(new_users)
            return True
    return False

def authenticate_user(username, password):
    """Authenticate a user by username/password. Returns user dict or None."""
    with _users_lock:
        users = _load_users()
        for u in users:
            if u['username'] == username:
                if not u.get('is_active', True):
                    return 'disabled'
                if verify_password(password, u['password_hash']):
                    return u
                return None
    return None

# ============================================================
# Usage tracking (anonymous IPs and authenticated users)
# ============================================================
USAGE_FILE = os.environ.get('USAGE_FILE', '/opt/docker-proxy/usage.json')
_usage_lock = threading.Lock()
_anonymous_usage = {}   # ip -> { 'pull_count': N, 'last_reset_date': 'YYYY-MM-DD' }
_user_usage = {}        # username -> { 'pull_count': N, 'last_reset_date': 'YYYY-MM-DD', 'last_pull': '...' }
_last_usage_flush = time.time()

def _load_usage():
    """Load usage stats from disk."""
    global _anonymous_usage, _user_usage
    try:
        if os.path.exists(USAGE_FILE):
            with open(USAGE_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    _anonymous_usage = data.get('anonymous', {})
                    _user_usage = data.get('users', {})
    except Exception as e:
        print(f'[WARN] Failed to load usage: {e}')

def _flush_usage():
    """Flush usage stats to disk."""
    global _last_usage_flush
    try:
        dirname = os.path.dirname(USAGE_FILE)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(USAGE_FILE, 'w') as f:
            json.dump({
                'anonymous': _anonymous_usage,
                'users': _user_usage,
            }, f, indent=2)
        _last_usage_flush = time.time()
    except Exception as e:
        print(f'[WARN] Failed to flush usage: {e}')

def _maybe_flush_usage():
    """Flush usage to disk every 5 minutes."""
    global _last_usage_flush
    if time.time() - _last_usage_flush > 300:
        _flush_usage()

def _today():
    return time.strftime('%Y-%m-%d')

def check_and_increment_anonymous(ip):
    """Check anonymous IP quota and increment if allowed. Returns (allowed, remaining, quota)."""
    settings = get_settings()
    quota = settings.get('anonymous_daily_pulls', 100)
    today = _today()

    with _usage_lock:
        entry = _anonymous_usage.get(ip)
        if not entry:
            entry = {'pull_count': 0, 'last_reset_date': today}
            _anonymous_usage[ip] = entry

        # Daily reset
        if entry['last_reset_date'] != today:
            entry['pull_count'] = 0
            entry['last_reset_date'] = today

        if entry['pull_count'] >= quota:
            return False, 0, quota

        entry['pull_count'] += 1
        _maybe_flush_usage()
        return True, max(0, quota - entry['pull_count']), quota

def check_and_increment_user(username):
    """Check user quota and increment if allowed. Returns (allowed, remaining, quota)."""
    user = get_user(username)
    if not user:
        return False, 0, 0

    today = _today()
    quota = user.get('daily_pull_quota', 500)

    with _usage_lock:
        entry = _user_usage.get(username)
        if not entry:
            entry = {'pull_count': 0, 'last_reset_date': today, 'last_pull': None}
            _user_usage[username] = entry

        # Daily reset
        if entry['last_reset_date'] != today:
            entry['pull_count'] = 0
            entry['last_reset_date'] = today

        if entry['pull_count'] >= quota:
            return False, 0, quota

        entry['pull_count'] += 1
        entry['last_pull'] = time.strftime('%Y-%m-%d %H:%M:%S')

        # Also update the user's pull_count_today and last_pull in users.json
        with _users_lock:
            users = _load_users()
            for u in users:
                if u['username'] == username:
                    u['pull_count_today'] = entry['pull_count']
                    u['last_reset_date'] = today
                    u['last_pull'] = entry['last_pull']
                    _save_users(users)
                    break

        _maybe_flush_usage()
        return True, max(0, quota - entry['pull_count']), quota

def get_user_usage(username):
    """Get usage details for a user."""
    with _usage_lock:
        entry = _user_usage.get(username, {'pull_count': 0, 'last_reset_date': _today(), 'last_pull': None})
        # Check if needs reset
        if entry['last_reset_date'] != _today():
            entry['pull_count'] = 0
            entry['last_reset_date'] = _today()
        return entry

def get_anonymous_usage(ip):
    """Get usage details for an IP."""
    with _usage_lock:
        entry = _anonymous_usage.get(ip, {'pull_count': 0, 'last_reset_date': _today()})
        if entry['last_reset_date'] != _today():
            entry['pull_count'] = 0
            entry['last_reset_date'] = _today()
        return entry

def get_anonymous_usage_all():
    """Get all anonymous usage entries (for dashboard)."""
    today = _today()
    with _usage_lock:
        result = {}
        for ip, entry in _anonymous_usage.items():
            if entry['last_reset_date'] != today:
                entry = {'pull_count': 0, 'last_reset_date': today}
            result[ip] = entry
        return result

# Load usage on startup
_load_usage()

# ============================================================
# Docker Hub account management
# ============================================================
ACCOUNTS_FILE = os.environ.get('ACCOUNTS_FILE', '/opt/docker-proxy/accounts.json')
_accounts_lock = threading.Lock()
_account_rr_index = 0  # round-robin index

def _load_accounts():
    """Load accounts from JSON file."""
    try:
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
    except Exception as e:
        print(f'[WARN] Failed to load accounts: {e}')
    return []

def _save_accounts(accounts):
    """Save accounts to JSON file."""
    try:
        dirname = os.path.dirname(ACCOUNTS_FILE)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(ACCOUNTS_FILE, 'w') as f:
            json.dump(accounts, f, indent=2)
    except Exception as e:
        print(f'[WARN] Failed to save accounts: {e}')

def get_accounts():
    """Get list of accounts (thread-safe)."""
    with _accounts_lock:
        return _load_accounts()

def add_account(username, token, label=''):
    """Add a new account. Returns the account dict or None on error."""
    with _accounts_lock:
        accounts = _load_accounts()
        # Check for duplicate username
        for acct in accounts:
            if acct['username'] == username:
                return None  # already exists
        new_acct = {
            'username': username,
            'token': token,
            'label': label or username,
            'last_used': None,
            'pull_count': 0,
            'rate_limit_remaining': None,
        }
        accounts.append(new_acct)
        _save_accounts(accounts)
        return new_acct

def remove_account(username):
    """Remove an account by username. Returns True if removed."""
    with _accounts_lock:
        accounts = _load_accounts()
        new_accounts = [a for a in accounts if a['username'] != username]
        if len(new_accounts) < len(accounts):
            _save_accounts(new_accounts)
            return True
    return False

def update_account_stats(username, pull_count=None, rate_limit_remaining=None):
    """Update stats for an account."""
    with _accounts_lock:
        accounts = _load_accounts()
        for acct in accounts:
            if acct['username'] == username:
                acct['last_used'] = time.strftime('%Y-%m-%d %H:%M:%S')
                if pull_count is not None:
                    acct['pull_count'] = pull_count
                if rate_limit_remaining is not None:
                    acct['rate_limit_remaining'] = rate_limit_remaining
                _save_accounts(accounts)
                return

def get_next_account():
    """Get next account using round-robin. Returns (username, token) or (None, None)."""
    global _account_rr_index
    with _accounts_lock:
        accounts = _load_accounts()
        if not accounts:
            return None, None
        idx = _account_rr_index % len(accounts)
        _account_rr_index += 1
        acct = accounts[idx]
        return acct['username'], acct['token']

def get_account_credentials():
    """Get base64-encoded credentials for Docker Hub Basic auth from next account."""
    username, token = get_next_account()
    if username and token:
        creds = base64.b64encode(f'{username}:{token}'.encode()).decode()
        return username, creds
    return None, None


# Nginx disguise page
NGINX_PAGE = b"""<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>"""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects - return them to the client."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_token(repo, auth_url=AUTH_URL, service='registry.docker.io'):
    """Get a pull token for the given repo, with caching. Uses accounts if available."""
    cache_key = (auth_url, repo)
    now = time.time()
    cached = _token_cache.get(cache_key)
    if cached and cached['expires'] > now:
        return cached['token']

    url = f'{auth_url}/token?service={service}&scope=repository:{repo}:pull'

    # Try with stored account credentials first (Docker Hub only)
    if auth_url == AUTH_URL:
        username, creds = get_account_credentials()
        if creds:
            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'docker-proxy/1.0',
                    'Authorization': f'Basic {creds}',
                })
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    token = data.get('token')
                    if token:
                        _token_cache[cache_key] = {
                            'token': token,
                            'expires': now + data.get('expires_in', 300) - 60,
                        }
                        # Update account stats from response headers
                        rl = resp.headers.get('X-RateLimit-Remaining')
                        update_account_stats(
                            username,
                            pull_count=None,
                            rate_limit_remaining=int(rl) if rl else None,
                        )
                        add_log('INFO', f'Token fetched with account {username} for {repo}')
                    return token
            except Exception as e:
                add_log('WARN', f'Authenticated token fetch failed for {repo} ({username}): {e}')
                # Fall through to anonymous

    # Anonymous token fetch
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'docker-proxy/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            token = data.get('token')
            if token:
                _token_cache[cache_key] = {
                    'token': token,
                    'expires': now + data.get('expires_in', 300) - 60,
                }
            return token
    except Exception as e:
        print(f'[WARN] Token fetch failed for {repo}: {e}')
        add_log('WARN', f'Token fetch failed for {repo}: {e}')
        return None


def is_official_image(path):
    """Check if path is /v2/<name>/... where <name> has no namespace."""
    m = re.match(r'^/v2/([^/]+)/(manifests|blobs|tags|referrers)/', path)
    if not m:
        m = re.match(r'^/v2/([^/]+)/tags/list', path)
    if not m:
        return False
    return '/' not in m.group(1)


def resolve_upstream(host_top, ns_param=None):
    """Determine upstream registry from subdomain or ns= parameter."""
    if ns_param:
        if ns_param == 'docker.io':
            return HUB_HOST
        return ns_param
    if host_top in REGISTRY_ROUTES:
        return REGISTRY_ROUTES[host_top]
    return HUB_HOST


def is_blocked_ua(user_agent):
    """Check if the User-Agent is a known crawler."""
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(blocked in ua_lower for blocked in BLOCKED_UAS)


# ============================================================
# Login page HTML (shown when DASHBOARD_TOKEN is set)
# ============================================================
LOGIN_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Docker Proxy Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.login-box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:360px;text-align:center}
h1{font-size:1.4em;margin-bottom:8px}
p{color:#8b949e;font-size:.9em;margin-bottom:24px}
input{width:100%;padding:12px 16px;border:1px solid #30363d;border-radius:8px;background:#0d1117;color:#e6edf3;font-size:1em;margin-bottom:16px;outline:none}
input:focus{border-color:#58a6ff}
button{width:100%;padding:12px;background:#238636;color:#fff;border:none;border-radius:8px;font-size:1em;cursor:pointer;font-weight:600}
button:hover{background:#2ea043}
.err{color:#f85149;font-size:.85em;margin-top:12px;display:none}
</style></head><body>
<div class="login-box">
<h1>&#128674; Docker Proxy</h1>
<p>輸入存取令牌以繼續</p>
<form id="f"><input id="token" type="password" placeholder="Access Token" autofocus>
<button type="submit">登入</button></form>
<div class="err" id="err">令牌無效</div>
</div>
<script>
document.getElementById('f').onsubmit=function(e){
e.preventDefault();
var t=document.getElementById('token').value;
if(t){window.location.href='/dashboard?token='+encodeURIComponent(t)}
else{document.getElementById('err').style.display='block'}
};
</script></body></html>"""

# ============================================================
# Dashboard HTML (embedded, dark theme, no external deps)
# Includes: stats, health, accounts, users, settings, logs
# ============================================================
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Docker Proxy Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;
--text-dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;
--yellow:#d29922;--purple:#bc8cff}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--text);min-height:100vh;padding:20px}
.header{display:flex;align-items:center;justify-content:space-between;
padding:16px 24px;background:var(--card);border:1px solid var(--border);
border-radius:8px;margin-bottom:20px}
.header h1{font-size:1.4em;color:#fff}
.header .status{display:flex;align-items:center;gap:8px;font-size:.9em}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.dot.green{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.red{background:var(--red);box-shadow:0 0 6px var(--red)}
.dot.yellow{background:var(--yellow)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px}
.card h3{color:var(--text-dim);font-size:.85em;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}
.card .value{font-size:2em;font-weight:700;color:#fff}
.card .sub{color:var(--text-dim);font-size:.85em;margin-top:4px}
.section{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}
.section h2{font-size:1.1em;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.section h2 span{font-size:1.2em}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);font-size:.9em}
th{color:var(--text-dim);font-weight:600;text-transform:uppercase;font-size:.75em;letter-spacing:.5px;cursor:pointer;user-select:none}
th:hover{color:var(--accent)}
td{color:var(--text)}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75em;font-weight:600}
.badge.ok{background:rgba(63,185,80,.15);color:var(--green)}
.badge.fail{background:rgba(248,81,73,.15);color:var(--red)}
.badge.warn{background:rgba(210,153,34,.15);color:var(--yellow)}
.form-row{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.form-row input,.form-row select{flex:1;min-width:120px;padding:8px 12px;background:#0d1117;border:1px solid var(--border);
border-radius:6px;color:var(--text);font-size:.9em}
.form-row input::placeholder{color:var(--text-dim)}
.btn{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:.85em;font-weight:600;transition:.15s}
.btn.primary{background:var(--accent);color:#fff}
.btn.primary:hover{background:#79c0ff}
.btn.danger{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.btn.danger:hover{background:rgba(248,81,73,.3)}
.btn.success{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.btn.success:hover{background:rgba(63,185,80,.3)}
.btn.warn{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.btn.sm{padding:4px 10px;font-size:.78em}
.log-entries{max-height:300px;overflow-y:auto;font-family:'SF Mono',SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:.82em}
.log-entries .entry{padding:4px 8px;border-bottom:1px solid rgba(48,54,61,.5)}
.log-entries .entry:hover{background:rgba(88,166,255,.05)}
.log-entries .time{color:var(--text-dim);margin-right:8px}
.log-entries .level{margin-right:8px;font-weight:600;width:45px;display:inline-block;text-align:center;border-radius:3px;padding:1px 4px}
.log-entries .level.INFO{color:var(--accent)}
.log-entries .level.WARN{color:var(--yellow)}
.log-entries .level.ERROR{color:var(--red)}
.log-entries .msg{color:var(--text)}
.refresh-info{text-align:center;color:var(--text-dim);font-size:.8em;padding:10px}
.progress-bar{width:100%;height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin-top:4px}
.progress-bar .fill{height:100%;border-radius:4px;transition:width .3s}
.progress-bar .fill.ok{background:var(--green)}
.progress-bar .fill.warn{background:var(--yellow)}
.progress-bar .fill.danger{background:var(--red)}
.tab-bar{display:flex;gap:0;margin-bottom:16px;border-bottom:1px solid var(--border)}
.tab-bar .tab{padding:10px 20px;cursor:pointer;font-size:.9em;color:var(--text-dim);border-bottom:2px solid transparent;transition:.15s}
.tab-bar .tab:hover{color:var(--text)}
.tab-bar .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none}.tab-content.active{display:block}
.inline-edit{background:#0d1117;border:1px solid var(--border);border-radius:4px;color:var(--text);
padding:4px 8px;width:80px;font-size:.85em;text-align:center}
.inline-edit:focus{border-color:var(--accent);outline:none}
.msg{font-size:.85em;margin-top:4px;padding:4px 8px;border-radius:4px}
.msg.ok{color:var(--green)}.msg.err{color:var(--red)}
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;
background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;width:400px;max-width:90vw}
.modal h3{margin-bottom:16px;font-size:1.1em}
.modal .form-row{margin-bottom:12px}
.modal .actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
@media(max-width:600px){body{padding:10px}.header{flex-direction:column;gap:10px;text-align:center}
.grid{grid-template-columns:1fr}.form-row{flex-direction:column}}
</style>
</head>
<body>
<div class="header">
  <h1>&#128674; Docker Proxy Dashboard</h1>
  <div class="status">
    <span class="dot green" id="statusDot"></span>
    <span id="statusText">Connecting...</span>
    <span style="margin-left:12px;color:var(--text-dim);font-size:.8em" id="uptimeText"></span>
  </div>
</div>

<div class="grid" id="statsGrid">
  <div class="card"><h3>Total Requests</h3><div class="value" id="totalReqs">--</div><div class="sub">since startup</div></div>
  <div class="card"><h3>Authenticated Pulls</h3><div class="value" style="color:var(--accent)" id="authPulls">--</div><div class="sub">users logged in</div></div>
  <div class="card"><h3>Anonymous Pulls</h3><div class="value" style="color:var(--yellow)" id="anonPulls">--</div><div class="sub">no login</div></div>
  <div class="card"><h3>Memory Usage</h3><div class="value" id="memUsage">--</div><div class="sub">RSS</div></div>
</div>

<div class="tab-bar" id="tabBar">
  <div class="tab active" data-tab="health" onclick="switchTab('health')">&#128268; Health</div>
  <div class="tab" data-tab="accounts" onclick="switchTab('accounts')">&#128100; Hub Accounts</div>
  <div class="tab" data-tab="users" onclick="switchTab('users')">&#128101; Users</div>
  <div class="tab" data-tab="settings" onclick="switchTab('settings')">&#9881; Settings</div>
  <div class="tab" data-tab="logs" onclick="switchTab('logs')">&#128196; Logs</div>
</div>

<!-- Health Tab -->
<div class="tab-content active" id="tab-health">
<div class="section">
  <h2><span>&#128268;</span> Upstream Health Checks</h2>
  <table>
    <thead><tr><th>Service</th><th>Status</th><th>Latency</th><th>Detail</th></tr></thead>
    <tbody id="healthBody"><tr><td colspan="4" style="text-align:center;color:var(--text-dim)">Loading...</td></tr></tbody>
  </table>
</div>
</div>

<!-- Accounts Tab -->
<div class="tab-content" id="tab-accounts">
<div class="section">
  <h2><span>&#128100;</span> Docker Hub Accounts</h2>
  <div style="margin-bottom:16px">
    <div class="form-row">
      <input type="text" id="acctUser" placeholder="Username">
      <input type="text" id="acctToken" placeholder="Access Token">
      <input type="text" id="acctLabel" placeholder="Label (optional)">
      <button class="btn primary" onclick="addAccount()">Add Account</button>
    </div>
    <div id="addAcctMsg" class="msg"></div>
  </div>
  <table>
    <thead><tr><th>Label</th><th>Username</th><th>Pull Count</th><th>Rate Limit</th><th>Last Used</th><th>Action</th></tr></thead>
    <tbody id="accountsBody"><tr><td colspan="6" style="text-align:center;color:var(--text-dim)">Loading...</td></tr></tbody>
  </table>
</div>
</div>

<!-- Users Tab -->
<div class="tab-content" id="tab-users">
<div class="section">
  <h2><span>&#128101;</span> Registered Users</h2>
  <div style="margin-bottom:16px">
    <div class="form-row">
      <input type="text" id="newUsername" placeholder="Username">
      <input type="password" id="newPassword" placeholder="Password">
      <input type="number" id="newQuota" placeholder="Daily Quota (default 500)" min="1">
      <button class="btn primary" onclick="addUser()">Add User</button>
    </div>
    <div id="addUserMsg" class="msg"></div>
  </div>
  <table>
    <thead><tr><th onclick="sortUsers('username')">Username</th>
    <th onclick="sortUsers('daily_pull_quota')">Daily Quota</th>
    <th onclick="sortUsers('pull_count_today')">Pulls Today</th>
    <th>Usage</th>
    <th onclick="sortUsers('last_pull')">Last Pull</th>
    <th onclick="sortUsers('is_active')">Status</th>
    <th>Created</th>
    <th>Actions</th></tr></thead>
    <tbody id="usersBody"><tr><td colspan="8" style="text-align:center;color:var(--text-dim)">Loading...</td></tr></tbody>
  </table>
</div>
</div>

<!-- Settings Tab -->
<div class="tab-content" id="tab-settings">
<div class="section">
  <h2><span>&#9881;</span> Proxy Settings</h2>
  <div style="max-width:500px">
    <div class="form-row">
      <label style="flex:0 0 200px;color:var(--text-dim);line-height:36px">Anonymous Daily Pulls</label>
      <input type="number" id="settAnonPulls" min="0" placeholder="100">
    </div>
    <div class="form-row">
      <label style="flex:0 0 200px;color:var(--text-dim);line-height:36px">Dashboard Token</label>
      <input type="text" id="settDashToken" placeholder="留空則無需認證">
    </div>
    <div class="form-row">
      <button class="btn primary" onclick="saveSettings()">Save Settings</button>
    </div>
    <div id="settingsMsg" class="msg"></div>
  </div>
</div>
<div class="section">
  <h2><span>&#127760;</span> Anonymous Usage (by IP)</h2>
  <table>
    <thead><tr><th>IP Address</th><th>Pulls Today</th><th>Quota</th><th>Usage</th></tr></thead>
    <tbody id="anonUsageBody"><tr><td colspan="4" style="text-align:center;color:var(--text-dim)">No anonymous pulls recorded</td></tr></tbody>
  </table>
</div>
</div>

<!-- Logs Tab -->
<div class="tab-content" id="tab-logs">
<div class="section">
  <h2><span>&#128196;</span> Recent Logs</h2>
  <div class="log-entries" id="logsBody"><div class="entry" style="color:var(--text-dim)">Loading...</div></div>
</div>
</div>

<!-- User Usage Modal -->
<div class="modal-overlay" id="usageModal">
  <div class="modal">
    <h3 id="usageModalTitle">User Usage</h3>
    <div id="usageModalBody"></div>
    <div class="actions"><button class="btn primary" onclick="closeModal()">Close</button></div>
  </div>
</div>

<!-- Edit User Modal -->
<div class="modal-overlay" id="editModal">
  <div class="modal">
    <h3 id="editModalTitle">Edit User</h3>
    <div class="form-row">
      <label style="flex:0 0 120px;color:var(--text-dim);line-height:36px">Username</label>
      <input type="text" id="editUsername" disabled style="opacity:.6">
    </div>
    <div class="form-row">
      <label style="flex:0 0 120px;color:var(--text-dim);line-height:36px">New Password</label>
      <input type="password" id="editPassword" placeholder="Leave blank to keep current">
    </div>
    <div class="form-row">
      <label style="flex:0 0 120px;color:var(--text-dim);line-height:36px">Daily Quota</label>
      <input type="number" id="editQuota" min="1">
    </div>
    <div class="actions">
      <button class="btn" onclick="closeEditModal()" style="color:var(--text-dim)">Cancel</button>
      <button class="btn primary" onclick="saveEditUser()">Save</button>
    </div>
  </div>
</div>

<div class="refresh-info">Auto-refresh every 5 seconds &middot; <span id="lastRefresh"></span></div>

<script>
var sortField=null,sortAsc=true;
function tk(){return new URLSearchParams(window.location.search).get('token')||''}
function fmt(n){return n==null?'--':n.toLocaleString()}
function uptime(s){
  var d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60),sec=Math.floor(s%60);
  var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');if(m)p.push(m+'m');p.push(sec+'s');return p.join(' ');
}
function memFmt(b){
  if(b>1073741824)return(b/1073741824).toFixed(1)+' GB';
  if(b>1048576)return(b/1048576).toFixed(1)+' MB';
  return(b/1024).toFixed(0)+' KB';
}
function progressPct(used,total){
  if(!total)return 0;return Math.min(100,Math.round(used/total*100));
}
function progressClass(pct){
  if(pct>=90)return 'danger';if(pct>=70)return 'warn';return 'ok';
}
function switchTab(name){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('active',t.dataset.tab===name)});
  document.querySelectorAll('.tab-content').forEach(function(c){c.classList.toggle('active',c.id==='tab-'+name)});
}
async function fetchJSON(url){
  try{
    var tk2=tk();
    var sep=url.includes('?')?'&':'?';
    var r=await fetch(tk2?url+sep+'token='+encodeURIComponent(tk2):url);
    if(r.status===401){document.body.innerHTML='<h1 style="color:#f85149;text-align:center;margin-top:40vh">Session expired</h1>';return null}
    return await r.json()
  }catch(e){return null}
}
async function apiCall(url,method,body){
  try{
    var tk2=tk();
    var sep=url.includes('?')?'&':'?';
    var fullUrl=tk2?url+sep+'token='+encodeURIComponent(tk2):url;
    var opts={method:method,headers:{'Content-Type':'application/json'}};
    if(body)opts.body=JSON.stringify(body);
    var r=await fetch(fullUrl,opts);
    return await r.json();
  }catch(e){return {error:'Request failed'};}
}
async function refresh(){
  var s=await fetchJSON('/api/status');
  if(s){
    document.getElementById('totalReqs').textContent=fmt(s.total_requests);
    document.getElementById('authPulls').textContent=fmt(s.authenticated_pulls);
    document.getElementById('anonPulls').textContent=fmt(s.anonymous_pulls);
    document.getElementById('memUsage').textContent=memFmt(s.memory_rss);
    document.getElementById('uptimeText').textContent='Uptime: '+uptime(s.uptime_seconds);
    document.getElementById('statusDot').className='dot green';
    document.getElementById('statusText').textContent='Running on :'+s.port;
  }else{
    document.getElementById('statusDot').className='dot red';
    document.getElementById('statusText').textContent='Unreachable';
  }
  // Health
  var h=await fetchJSON('/api/health');
  if(h&&h.checks){
    var tb='';
    h.checks.forEach(function(c){
      var cls=c.detail==='OK'?'ok':'fail';
      tb+='<tr><td>'+c.name+'</td><td><span class="badge '+cls+'">'+c.status+'</span></td><td>'+c.latency+'</td><td>'+c.detail+'</td></tr>';
    });
    document.getElementById('healthBody').innerHTML=tb;
  }
  // Accounts
  var a=await fetchJSON('/api/accounts');
  if(a&&a.accounts){
    var tb='';
    if(a.accounts.length===0){
      tb='<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No accounts configured. Add one above to use authenticated pulls.</td></tr>';
    }
    a.accounts.forEach(function(ac){
      var rl=ac.rate_limit_remaining!=null?ac.rate_limit_remaining:'--';
      var lu=ac.last_used||'Never';
      var pc=ac.pull_count!=null?fmt(ac.pull_count):'0';
      tb+='<tr><td>'+ac.label+'</td><td>'+ac.username+'</td><td>'+pc+'</td><td>'+rl+'</td><td>'+lu+'</td>';
      tb+='<td><button class="btn danger sm" onclick="delAccount(\''+ac.username+'\')">Remove</button></td></tr>';
    });
    document.getElementById('accountsBody').innerHTML=tb;
  }
  // Users
  var u=await fetchJSON('/api/users');
  if(u&&u.users){
    var tb='';
    if(u.users.length===0){
      tb='<tr><td colspan="8" style="text-align:center;color:var(--text-dim)">No registered users. Anonymous mode only.</td></tr>';
    }
    var users=u.users;
    if(sortField){
      users.sort(function(a,b){
        var va=a[sortField],vb=b[sortField];
        if(typeof va==='string')va=va.toLowerCase();
        if(typeof vb==='string')vb=vb.toLowerCase();
        if(va<vb)return sortAsc?-1:1;
        if(va>vb)return sortAsc?1:-1;
        return 0;
      });
    }
    users.forEach(function(usr){
      var pct=progressPct(usr.pull_count_today,usr.daily_pull_quota);
      var cls=progressClass(pct);
      var status=usr.is_active?'<span class="badge ok">Active</span>':'<span class="badge fail">Inactive</span>';
      var lp=usr.last_pull||'Never';
      var created=usr.created_at||'--';
      tb+='<tr>';
      tb+='<td><strong>'+usr.username+'</strong></td>';
      tb+='<td>'+fmt(usr.daily_pull_quota)+'</td>';
      tb+='<td>'+fmt(usr.pull_count_today)+'</td>';
      tb+='<td style="min-width:120px"><div class="progress-bar"><div class="fill '+cls+'" style="width:'+pct+'%"></div></div><span style="font-size:.75em;color:var(--text-dim)">'+pct+'%</span></td>';
      tb+='<td>'+lp+'</td>';
      tb+='<td>'+status+'</td>';
      tb+='<td style="font-size:.8em;color:var(--text-dim)">'+created+'</td>';
      tb+='<td style="white-space:nowrap">';
      tb+='<button class="btn sm" style="color:var(--accent);border:1px solid rgba(88,166,255,.3);background:transparent;margin-right:4px" onclick="viewUsage(\''+usr.username+'\')">Usage</button>';
      tb+='<button class="btn sm" style="color:var(--purple);border:1px solid rgba(188,140,255,.3);background:transparent;margin-right:4px" onclick="editUser(\''+usr.username+'\')">Edit</button>';
      tb+='<button class="btn sm '+(usr.is_active?'warn':'success')+'" onclick="toggleUser(\''+usr.username+'\','+(!usr.is_active)+')">'+(usr.is_active?'Disable':'Enable')+'</button> ';
      tb+='<button class="btn danger sm" onclick="delUser(\''+usr.username+'\')">Delete</button>';
      tb+='</td></tr>';
    });
    document.getElementById('usersBody').innerHTML=tb;
  }
  // Settings
  var st=await fetchJSON('/api/settings');
  if(st&&st.settings){
    var ae=document.activeElement;
    if(ae.id!=='settAnonPulls')document.getElementById('settAnonPulls').value=st.settings.anonymous_daily_pulls||100;
    if(ae.id!=='settDashToken')document.getElementById('settDashToken').value=st.settings.dashboard_token||'';
  }
  // Anonymous usage
  if(st&&st.anonymous_usage){
    var tb='';
    var entries=Object.entries(st.anonymous_usage);
    if(entries.length===0){
      tb='<tr><td colspan="4" style="text-align:center;color:var(--text-dim)">No anonymous pulls recorded today</td></tr>';
    }else{
      var q=st.settings?st.settings.anonymous_daily_pulls:100;
      entries.sort(function(a,b){return b[1].pull_count-a[1].pull_count});
      entries.forEach(function(pair){
        var ip=pair[0],eu=pair[1];
        var pct=progressPct(eu.pull_count,q);
        var cls=progressClass(pct);
        tb+='<tr><td>'+ip+'</td><td>'+fmt(eu.pull_count)+'</td><td>'+fmt(q)+'</td>';
        tb+='<td style="min-width:120px"><div class="progress-bar"><div class="fill '+cls+'" style="width:'+pct+'%"></div></div><span style="font-size:.75em;color:var(--text-dim)">'+pct+'%</span></td></tr>';
      });
    }
    document.getElementById('anonUsageBody').innerHTML=tb;
  }
  // Logs
  var l=await fetchJSON('/api/logs');
  if(l&&l.logs){
    var tb='';
    l.logs.slice().reverse().forEach(function(e){
      tb+='<div class="entry"><span class="time">'+e.time+'</span><span class="level '+e.level+'">'+e.level+'</span><span class="msg">'+e.message+'</span></div>';
    });
    document.getElementById('logsBody').innerHTML=tb||'<div class="entry" style="color:var(--text-dim)">No logs yet</div>';
  }
  document.getElementById('lastRefresh').textContent='Last refresh: '+new Date().toLocaleTimeString();
}
function sortUsers(field){
  if(sortField===field){sortAsc=!sortAsc}else{sortField=field;sortAsc=true}
  refresh();
}
// Accounts
async function addAccount(){
  var u=document.getElementById('acctUser').value.trim();
  var t=document.getElementById('acctToken').value.trim();
  var l=document.getElementById('acctLabel').value.trim();
  var msg=document.getElementById('addAcctMsg');
  if(!u||!t){msg.className='msg err';msg.textContent='Username and token are required.';return}
  var d=await apiCall('/api/accounts','POST',{username:u,token:t,label:l||u});
  if(d.ok){msg.className='msg ok';msg.textContent='Account added!';
    document.getElementById('acctUser').value='';document.getElementById('acctToken').value='';document.getElementById('acctLabel').value='';
    refresh();
  }else{msg.className='msg err';msg.textContent=d.error||'Failed to add account.'}
}
async function delAccount(username){
  if(!confirm('Remove account "'+username+'"?'))return;
  await apiCall('/api/accounts?username='+encodeURIComponent(username),'DELETE');
  refresh();
}
// Users
async function addUser(){
  var u=document.getElementById('newUsername').value.trim();
  var p=document.getElementById('newPassword').value;
  var q=parseInt(document.getElementById('newQuota').value)||500;
  var msg=document.getElementById('addUserMsg');
  if(!u||!p){msg.className='msg err';msg.textContent='Username and password are required.';return}
  var d=await apiCall('/api/users','POST',{username:u,password:p,daily_pull_quota:q});
  if(d.ok){msg.className='msg ok';msg.textContent='User "'+u+'" created!';
    document.getElementById('newUsername').value='';document.getElementById('newPassword').value='';document.getElementById('newQuota').value='';
    refresh();
  }else{msg.className='msg err';msg.textContent=d.error||'Failed to create user.'}
}
async function delUser(username){
  if(!confirm('Delete user "'+username+'"? This cannot be undone.'))return;
  await apiCall('/api/users?username='+encodeURIComponent(username),'DELETE');
  refresh();
}
async function toggleUser(username,active){
  await apiCall('/api/users','PUT',{username:username,is_active:active});
  refresh();
}
async function viewUsage(username){
  var d=await fetchJSON('/api/users/'+encodeURIComponent(username)+'/usage');
  if(!d)return;
  document.getElementById('usageModalTitle').textContent='Usage: '+username;
  var q=d.daily_pull_quota||500;
  var pct=progressPct(d.pull_count_today||0,q);
  var cls=progressClass(pct);
  var html='<div style="margin-bottom:12px">';
  html+='<strong>Quota:</strong> '+fmt(q)+' pulls/day<br>';
  html+='<strong>Pulls Today:</strong> '+fmt(d.pull_count_today||0)+'<br>';
  html+='<strong>Last Pull:</strong> '+(d.last_pull||'Never')+'<br>';
  html+='<div class="progress-bar" style="margin-top:8px;height:14px"><div class="fill '+cls+'" style="width:'+pct+'%"></div></div>';
  html+='<div style="text-align:center;font-size:.9em;margin-top:4px">'+pct+'% used</div>';
  html+='</div>';
  document.getElementById('usageModalBody').innerHTML=html;
  document.getElementById('usageModal').classList.add('show');
}
function closeModal(){document.getElementById('usageModal').classList.remove('show')}
function editUser(username){
  fetchJSON('/api/users').then(function(d){
    if(!d||!d.users)return;
    var u=d.users.find(function(x){return x.username===username});
    if(!u)return;
    document.getElementById('editModalTitle').textContent='Edit: '+username;
    document.getElementById('editUsername').value=username;
    document.getElementById('editPassword').value='';
    document.getElementById('editQuota').value=u.daily_pull_quota;
    document.getElementById('editModal').classList.add('show');
  });
}
function closeEditModal(){document.getElementById('editModal').classList.remove('show')}
async function saveEditUser(){
  var u=document.getElementById('editUsername').value;
  var p=document.getElementById('editPassword').value;
  var q=parseInt(document.getElementById('editQuota').value);
  var body={username:u};
  if(p)body.password=p;
  if(q>0)body.daily_pull_quota=q;
  await apiCall('/api/users','PUT',body);
  closeEditModal();
  refresh();
}
// Settings
async function saveSettings(){
  var ap=parseInt(document.getElementById('settAnonPulls').value);
  var dt=document.getElementById('settDashToken').value;
  var msg=document.getElementById('settingsMsg');
  var payload={anonymous_daily_pulls:ap};
  if(dt!==null)payload.dashboard_token=dt;
  var d=await apiCall('/api/settings','PUT',payload);
  if(d.settings){msg.className='msg ok';msg.textContent='Settings saved!';}
  else{msg.className='msg err';msg.textContent=d.error||'Failed to save.';}
}
refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        msg = args[0] if args else ''
        print(f'[{self.log_date_time_string()}] {msg}')

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def _get_client_ip(self):
        """Get client IP, respecting X-Forwarded-For."""
        xff = self.headers.get('X-Forwarded-For', '')
        if xff:
            return xff.split(',')[0].strip()
        return self.client_address[0]

    def _route(self):
        user_agent = self.headers.get('User-Agent', '')

        # Track all requests
        stats_increment('total_requests')

        # Block known crawlers - return nginx page
        if is_blocked_ua(user_agent):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=UTF-8')
            self.end_headers()
            self.wfile.write(NGINX_PAGE)
            stats_increment('success_count')
            return

        # Parse URL
        raw_path = self.path
        # Fix %3A encoding: some clients encode : as %3A in tag references
        if '%3A' in raw_path and '%2F' not in raw_path:
            raw_path = raw_path.replace('%3A', ':')

        path = raw_path.split('?')[0]
        qs = raw_path.split('?')[1] if '?' in raw_path else ''

        # Parse query parameters
        params = {}
        if qs:
            for part in qs.split('&'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    params[k] = unquote(v)

        # ---- Dashboard and API routes (auth-protected) ----

        # /dashboard - serve embedded HTML dashboard
        if path == '/dashboard':
            if not self._check_dashboard_auth():
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=UTF-8')
            if hasattr(self, '_pending_cookie') and self._pending_cookie:
                self.send_header('Set-Cookie', self._pending_cookie)
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
            stats_increment('success_count')
            return

        # /api/* - all dashboard API endpoints require auth
        if path.startswith('/api/'):
            if not self._check_dashboard_auth():
                return

        # /api/status - proxy status and stats
        if path == '/api/status':
            mem = 0
            try:
                mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                # macOS reports bytes, Linux reports KB
                if os.uname().sysname == 'Darwin':
                    pass  # already in bytes on macOS
                else:
                    mem = mem * 1024  # convert KB to bytes on Linux
            except Exception:
                mem = 0
            with _stats_lock:
                data = {
                    'status': 'running',
                    'port': PORT,
                    'mode': MODE,
                    'uptime_seconds': int(time.time() - STATS['start_time']),
                    'total_requests': STATS['total_requests'],
                    'success_count': STATS['success_count'],
                    'error_count': STATS['error_count'],
                    'authenticated_pulls': STATS.get('authenticated_pulls', 0),
                    'anonymous_pulls': STATS.get('anonymous_pulls', 0),
                    'memory_rss': mem,
                    'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                }
            self._respond_json(200, data)
            return

        # /api/health - reuse existing health check
        if path == '/api/health':
            self._handle_health()
            return

        # /api/accounts - manage Docker Hub accounts
        if path == '/api/accounts':
            self._handle_accounts(params)
            return

        # /api/users - user CRUD
        if path == '/api/users' or path.startswith('/api/users/'):
            self._handle_users(path, params)
            return

        # /api/settings - proxy settings
        if path == '/api/settings':
            self._handle_settings(params)
            return

        # /api/logs - recent log entries
        if path == '/api/logs':
            with _log_lock:
                logs = list(LOG_BUFFER[-50:])
            self._respond_json(200, {'logs': logs})
            return

        # ---- Existing proxy routes ----

        # Determine upstream registry from subdomain or ns= param
        hostname = params.get('hubhost') or self.headers.get('Host', '')
        host_top = hostname.split('.')[0]
        hub_host = resolve_upstream(host_top, params.get('ns'))
        is_docker_hub = (hub_host == HUB_HOST)

        # Check if browser request
        is_browser = 'mozilla' in user_agent.lower()

        # /health - diagnose upstream connectivity
        if path == '/health':
            self._handle_health()
            stats_increment('success_count')
            return

        # /v2/ ping - registry 2.0 handshake
        # Always challenge with 401 if no auth, so Docker sends credentials
        if path in ('/v2/', '/v2'):
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Basic '):
                import base64
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode()
                    username, password = decoded.split(':', 1)
                    result = authenticate_user(username, password)
                    if result and isinstance(result, dict):
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Docker-Distribution-API-Version', 'registry/2.0')
                        for k, v in CORS_HEADERS.items():
                            self.send_header(k, v)
                        self.end_headers()
                        self.wfile.write(b'{}')
                        stats_increment('success_count')
                        return
                except Exception:
                    pass
                self._respond_error(401, 'UNAUTHORIZED', 'Invalid credentials', www_authenticate=True)
                stats_increment('error_count')
                return
            self._respond_error(401, 'UNAUTHORIZED', 'authentication required', www_authenticate=True)
            stats_increment('error_count')
            return

        # /v2/search/* -> hub.docker.com (DSM search API, not registry)
        if path.startswith('/v2/search/'):
            self._proxy_transparent(path, qs, 'hub.docker.com')
            return

        # /v2/_catalog -> return empty catalog (Docker Hub doesn't support it for free)
        if path == '/v2/_catalog':
            self._respond_json(200, {'repositories': []})
            return

        # /v2/* registry API
        if path.startswith('/v2/'):
            # Manifest/tag requests require auth (forces Docker to authenticate)
            is_manifest = '/manifests/' in path or '/tags/' in path or path.endswith('/tags/list')
            if is_manifest:
                auth_header = self.headers.get('Authorization', '')
                if not auth_header.startswith('Basic '):
                    # No auth - challenge Docker to authenticate
                    self._respond_error(401, 'UNAUTHORIZED', 'authentication required', www_authenticate=True)
                    stats_increment('error_count')
                    return
                # Has auth - validate via _check_proxy_auth
                if not self._check_proxy_auth():
                    return
            # Blob requests pass through without auth check
            upstream_path = path
            if is_docker_hub and is_official_image(path):
                upstream_path = path.replace('/v2/', '/v2/library/', 1)
            self._proxy_registry(upstream_path, qs, hub_host, is_docker_hub)
            return

        # /token endpoint - proxy to auth server
        if '/token' in path:
            self._proxy_token(path, qs, hub_host)
            return

        # /v1/* search API -> index.docker.io
        # DSM adds library/ prefix to search queries, strip it
        if path.startswith('/v1/'):
            if 'library/' in qs and 'q=library/' in qs:
                qs = qs.replace('q=library/', 'q=', 1)
            self._proxy_transparent(path, qs, 'index.docker.io')
            return

        # Browser requests: check mode
        if is_browser or any(p in path for p in ['/search', '/_']):
            if MODE == 'disguise':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=UTF-8')
                self.end_headers()
                self.wfile.write(NGINX_PAGE)
                stats_increment('success_count')
                return
            else:
                # Transparent mode - proxy to hub.docker.com
                self._proxy_transparent(path, qs, 'hub.docker.com')
                return

        # Non-browser requests - proxy to hub.docker.com
        self._proxy_transparent(path, qs, 'hub.docker.com')

    # ============================================================
    # API Handlers
    # ============================================================

    def _handle_accounts(self, params):
        """Handle /api/accounts CRUD."""
        if self.command == 'GET':
            accounts = get_accounts()
            safe = []
            for a in accounts:
                safe.append({
                    'username': a['username'],
                    'label': a.get('label', a['username']),
                    'last_used': a.get('last_used'),
                    'pull_count': a.get('pull_count', 0),
                    'rate_limit_remaining': a.get('rate_limit_remaining'),
                })
            self._respond_json(200, {'accounts': safe})

        elif self.command == 'POST':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                data = json.loads(body)
                username = data.get('username', '').strip()
                token = data.get('token', '').strip()
                label = data.get('label', '').strip()
                if not username or not token:
                    self._respond_json(400, {'error': 'username and token are required'})
                    return
                result = add_account(username, token, label)
                if result is None:
                    self._respond_json(409, {'error': f'Account "{username}" already exists'})
                    return
                add_log('INFO', f'Account added: {username}')
                self._respond_json(200, {'ok': True, 'message': f'Account "{username}" added'})
            except json.JSONDecodeError:
                self._respond_json(400, {'error': 'Invalid JSON'})
            except Exception as e:
                self._respond_json(500, {'error': str(e)})

        elif self.command == 'DELETE':
            username = params.get('username', '').strip()
            if not username:
                self._respond_json(400, {'error': 'username parameter required'})
                return
            if remove_account(username):
                add_log('INFO', f'Account removed: {username}')
                self._respond_json(200, {'ok': True, 'message': f'Account "{username}" removed'})
            else:
                self._respond_json(404, {'error': f'Account "{username}" not found'})

    def _handle_users(self, path, params):
        """Handle /api/users CRUD and /api/users/<username>/usage."""
        # Check for /api/users/<username>/usage
        usage_match = re.match(r'^/api/users/([^/]+)/usage$', path)
        if usage_match:
            username = unquote(usage_match.group(1))
            if self.command == 'GET':
                user = get_user(username)
                if not user:
                    self._respond_json(404, {'error': f'User "{username}" not found'})
                    return
                usage = get_user_usage(username)
                self._respond_json(200, {
                    'username': username,
                    'daily_pull_quota': user.get('daily_pull_quota', 500),
                    'pull_count_today': usage.get('pull_count', 0),
                    'last_pull': usage.get('last_pull'),
                    'last_reset_date': usage.get('last_reset_date'),
                    'is_active': user.get('is_active', True),
                })
            else:
                self._respond_json(405, {'error': 'Method not allowed'})
            return

        if self.command == 'GET':
            users = get_users()
            # Enrich with usage data
            result = []
            for u in users:
                usage = get_user_usage(u['username'])
                result.append({
                    'username': u['username'],
                    'daily_pull_quota': u.get('daily_pull_quota', 500),
                    'pull_count_today': usage.get('pull_count', 0),
                    'last_pull': usage.get('last_pull'),
                    'last_reset_date': usage.get('last_reset_date'),
                    'created_at': u.get('created_at'),
                    'is_active': u.get('is_active', True),
                })
            self._respond_json(200, {'users': result})

        elif self.command == 'POST':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                data = json.loads(body)
                username = data.get('username', '').strip()
                password = data.get('password', '')
                quota = data.get('daily_pull_quota', 500)
                if not username or not password:
                    self._respond_json(400, {'error': 'username and password are required'})
                    return
                if len(username) < 2:
                    self._respond_json(400, {'error': 'Username must be at least 2 characters'})
                    return
                if len(password) < 4:
                    self._respond_json(400, {'error': 'Password must be at least 4 characters'})
                    return
                try:
                    quota = int(quota)
                    if quota < 1:
                        quota = 500
                except (ValueError, TypeError):
                    quota = 500
                result = add_user(username, password, quota)
                if result is None:
                    self._respond_json(409, {'error': f'User "{username}" already exists'})
                    return
                add_log('INFO', f'User created: {username}')
                self._respond_json(200, {'ok': True, 'message': f'User "{username}" created'})
            except json.JSONDecodeError:
                self._respond_json(400, {'error': 'Invalid JSON'})
            except Exception as e:
                self._respond_json(500, {'error': str(e)})

        elif self.command == 'PUT':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                data = json.loads(body)
                username = data.get('username', '').strip()
                if not username:
                    self._respond_json(400, {'error': 'username is required'})
                    return
                updates = {}
                if 'password' in data and data['password']:
                    updates['password'] = data['password']
                if 'daily_pull_quota' in data:
                    try:
                        q = int(data['daily_pull_quota'])
                        if q >= 1:
                            updates['daily_pull_quota'] = q
                    except (ValueError, TypeError):
                        pass
                if 'is_active' in data:
                    updates['is_active'] = bool(data['is_active'])
                if not updates:
                    self._respond_json(400, {'error': 'No valid fields to update'})
                    return
                result = update_user(username, **updates)
                if not result:
                    self._respond_json(404, {'error': f'User "{username}" not found'})
                    return
                add_log('INFO', f'User updated: {username} ({", ".join(updates.keys())})')
                self._respond_json(200, {'ok': True, 'message': f'User "{username}" updated'})
            except json.JSONDecodeError:
                self._respond_json(400, {'error': 'Invalid JSON'})
            except Exception as e:
                self._respond_json(500, {'error': str(e)})

        elif self.command == 'DELETE':
            username = params.get('username', '').strip()
            if not username:
                self._respond_json(400, {'error': 'username parameter required'})
                return
            if delete_user(username):
                add_log('INFO', f'User deleted: {username}')
                self._respond_json(200, {'ok': True, 'message': f'User "{username}" deleted'})
            else:
                self._respond_json(404, {'error': f'User "{username}" not found'})

    def _handle_settings(self, params):
        """Handle /api/settings GET/PUT."""
        if self.command == 'GET':
            settings = get_settings()
            anon_usage = get_anonymous_usage_all()
            self._respond_json(200, {'settings': settings, 'anonymous_usage': anon_usage})

        elif self.command == 'PUT':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                data = json.loads(body)
                patch = {}
                if 'anonymous_daily_pulls' in data:
                    try:
                        v = int(data['anonymous_daily_pulls'])
                        if v >= 0:
                            patch['anonymous_daily_pulls'] = v
                    except (ValueError, TypeError):
                        pass
                if 'dashboard_token' in data:
                    patch['dashboard_token'] = str(data['dashboard_token']).strip()
                if not patch:
                    self._respond_json(400, {'error': 'No valid settings to update'})
                    return
                settings = update_settings(patch)
                add_log('INFO', f'Settings updated: {list(patch.keys())}')
                self._respond_json(200, {'ok': True, 'settings': settings})
            except json.JSONDecodeError:
                self._respond_json(400, {'error': 'Invalid JSON'})
            except Exception as e:
                self._respond_json(500, {'error': str(e)})

    # ============================================================
    # Proxy auth (user-based with quotas)
    # ============================================================

    def _check_proxy_auth(self):
        """Check proxy-level auth for pulling images. Returns True if allowed."""
        client_ip = self._get_client_ip()

        # Check Basic Auth header (docker login sends this)
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode()
                username, password = decoded.split(':', 1)
                result = authenticate_user(username, password)
                if result == 'disabled':
                    self._respond_error(403, 'ACCOUNT_DISABLED',
                                        'User account is disabled. Contact administrator.')
                    stats_increment('error_count')
                    return False
                if result and isinstance(result, dict):
                    # Authenticated user - check quota
                    allowed, remaining, quota = check_and_increment_user(username)
                    if not allowed:
                        self._respond_quota_exceeded('user', username, quota)
                        stats_increment('error_count')
                        return False
                    stats_increment('authenticated_pulls')
                    add_log('INFO', f'Authenticated pull: {username} ({remaining}/{quota} remaining)')
                    return True
                # Invalid credentials - fall through to 401
            except Exception:
                pass

            # Basic auth was present but invalid
            self._respond_error(401, 'UNAUTHORIZED',
                                'Invalid credentials. Run: docker login <host>',
                                www_authenticate=True)
            stats_increment('error_count')
            return False

        # No auth header - anonymous access with IP-based rate limiting
        allowed, remaining, quota = check_and_increment_anonymous(client_ip)
        if not allowed:
            self._respond_quota_exceeded('anonymous', client_ip, quota)
            stats_increment('error_count')
            return False
        stats_increment('anonymous_pulls')
        return True

    def _respond_error(self, status, code, message, www_authenticate=False):
        """Send a JSON error response."""
        body = json.dumps({
            'errors': [{'code': code, 'message': message}]
        }).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Docker-Distribution-API-Version', 'registry/2.0')
        if www_authenticate:
            self.send_header('Www-Authenticate',
                             f'Basic realm="Docker Proxy",service="docker.dan.tw"')
        if status == 429:
            # Calculate seconds until midnight UTC
            import datetime
            now = datetime.datetime.utcnow()
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)
            retry_after = int((midnight - now).total_seconds())
            self.send_header('Retry-After', str(retry_after))
            self.send_header('Www-Authenticate',
                             f'Basic realm="Docker Proxy",service="docker.dan.tw"')
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _respond_quota_exceeded(self, auth_type, identifier, quota):
        """Send a 429 quota exceeded response."""
        if auth_type == 'user':
            msg = f'User "{identifier}" has exceeded the daily pull quota of {quota}. Please try again tomorrow.'
        else:
            msg = f'Anonymous pull quota exceeded ({quota}/day per IP). Please run: docker login <host>'
        self._respond_error(429, 'TOOMANYREQUESTS', msg)
        add_log('WARN', f'Quota exceeded for {auth_type} {identifier}')

    # ============================================================
    # Existing proxy methods (unchanged)
    # ============================================================

    def _proxy_registry(self, upstream_path, query, hub_host, is_docker_hub):
        """Proxy /v2/* registry API requests with token exchange."""
        repo = None
        m = re.match(r'^/v2/(.+?)/(manifests|blobs|tags|referrers)/', upstream_path)
        if m:
            repo = m.group(1)
        else:
            m = re.match(r'^/v2/(.+)/tags/list', upstream_path)
            if m:
                repo = m.group(1)

        upstream_url = f'https://{hub_host}{upstream_path}'
        if query:
            upstream_url += f'?{query}'

        fwd_headers = {
            'Host': hub_host,
            'User-Agent': self.headers.get('User-Agent', 'docker-proxy/1.0'),
            'Accept': self.headers.get('Accept', '*/*'),
            'Accept-Encoding': 'identity',
            'Connection': 'keep-alive',
        }

        if repo:
            if hub_host == HUB_HOST:
                token = get_token(repo)
            elif hub_host in ('ghcr.io',):
                token = get_token(repo, 'https://ghcr.io/token', 'ghcr.io')
            elif hub_host in ('quay.io',):
                token = get_token(repo, 'https://quay.io/v2/auth', 'quay.io')
            else:
                token = get_token(repo)
            if token:
                fwd_headers['Authorization'] = f'Bearer {token}'

        # Forward AWS S3 signature header (needed for some blob downloads)
        if self.headers.get('X-Amz-Content-Sha256'):
            fwd_headers['X-Amz-Content-Sha256'] = self.headers.get('X-Amz-Content-Sha256')

        try:
            req = urllib.request.Request(upstream_url, headers=fwd_headers)
            ctx = ssl.create_default_context()
            # Don't follow redirects - CDN blob URLs are IP-signed
            # and must be fetched directly by the client
            opener = urllib.request.build_opener(NoRedirectHandler())
            with opener.open(req, timeout=30) as resp:
                body = resp.read()
                resp_headers = dict(resp.getheaders())

                # Pass redirects back to client (CDN URLs are IP-signed)
                if resp.status in (301, 302, 307, 308) and 'location' in resp_headers:
                    resp_headers['Docker-Distribution-API-Version'] = 'registry/2.0'
                    self.send_response(resp.status)
                    for k, v in resp_headers.items():
                        if k.lower() not in ('connection',):
                            self.send_header(k, v)
                    for k, v in CORS_HEADERS.items():
                        self.send_header(k, v)
                    self.end_headers()
                    stats_increment('success_count')
                    return

                if 'Www-Authenticate' in resp_headers:
                    resp_headers['Www-Authenticate'] = self._rewrite_auth(
                        resp_headers['Www-Authenticate']
                    )

                resp_headers['Docker-Distribution-API-Version'] = 'registry/2.0'
                for h in ['Content-Security-Policy', 'Transfer-Encoding']:
                    resp_headers.pop(h, None)

                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection',):
                        self.send_header(k, v)
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
                stats_increment('success_count')

        except urllib.error.HTTPError as e:
            body = e.read()
            resp_headers = dict(e.headers)

            # Pass redirects back to client
            if e.code in (301, 302, 307, 308) and resp_headers.get('Location'):
                resp_headers['Docker-Distribution-API-Version'] = 'registry/2.0'
                self.send_response(e.code)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection', 'transfer-encoding'):
                        self.send_header(k, v)
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                stats_increment('error_count')
                return

            if 'Www-Authenticate' in resp_headers:
                resp_headers['Www-Authenticate'] = self._rewrite_auth(
                    resp_headers['Www-Authenticate']
                )
            resp_headers['Docker-Distribution-API-Version'] = 'registry/2.0'

            self.send_response(e.code)
            for k, v in resp_headers.items():
                if k.lower() not in ('connection', 'transfer-encoding'):
                    self.send_header(k, v)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            stats_increment('error_count')
            if e.code not in (301, 302, 307, 308):
                add_log('ERROR', f'Registry proxy error {e.code}: {self.path}')

        except Exception as e:
            print(f'[ERROR] {self.command} {self.path}: {e}')
            self._respond_json(502, {'error': 'proxy_error', 'message': str(e)})
            stats_increment('error_count')
            add_log('ERROR', f'Registry proxy exception: {e}')

    def _proxy_token(self, path, query, hub_host):
        """Proxy /token requests to the appropriate auth server."""
        if hub_host == 'ghcr.io':
            auth_host = 'https://ghcr.io'
        elif hub_host == 'quay.io':
            auth_host = 'https://quay.io'
        else:
            auth_host = AUTH_URL

        token_url = f'{auth_host}{path}'
        if query:
            token_url += f'?{query}'

        fwd_headers = {
            'User-Agent': self.headers.get('User-Agent', 'docker-proxy/1.0'),
            'Accept': self.headers.get('Accept', '*/*'),
        }

        try:
            req = urllib.request.Request(token_url, headers=fwd_headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                resp_headers = dict(resp.getheaders())
                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection', 'transfer-encoding'):
                        self.send_header(k, v)
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
                stats_increment('success_count')
        except urllib.error.HTTPError as e:
            body = e.read()
            self.send_response(e.code)
            for k, v in dict(e.headers).items():
                if k.lower() not in ('connection', 'transfer-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            stats_increment('error_count')
            add_log('ERROR', f'Token proxy error {e.code}: {path}')
        except Exception as e:
            self._respond_json(502, {'error': 'token_error', 'message': str(e)})
            stats_increment('error_count')
            add_log('ERROR', f'Token proxy exception: {e}')

    def _proxy_transparent(self, path, query, upstream_host):
        """Transparent proxy for browser/search requests."""
        upstream_url = f'https://{upstream_host}{path}'
        if query:
            upstream_url += f'?{query}'

        fwd_headers = {
            'Host': upstream_host,
            'User-Agent': self.headers.get('User-Agent', 'docker-proxy/1.0'),
            'Accept': self.headers.get('Accept', '*/*'),
            'Accept-Language': self.headers.get('Accept-Language', ''),
            'Accept-Encoding': 'identity',
            'Connection': 'keep-alive',
        }
        if self.headers.get('Cookie'):
            fwd_headers['Cookie'] = self.headers.get('Cookie')
        if self.headers.get('Authorization'):
            fwd_headers['Authorization'] = self.headers.get('Authorization')

        try:
            req = urllib.request.Request(upstream_url, headers=fwd_headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                body = resp.read()
                resp_headers = dict(resp.getheaders())

                if 'Location' in resp_headers:
                    loc = resp_headers['Location']
                    for host in ['hub.docker.com', 'index.docker.io']:
                        loc = loc.replace(f'https://{host}', '')
                    resp_headers['Location'] = loc

                for h in ['Content-Security-Policy', 'X-Frame-Options',
                          'Content-Security-Policy-Report-Only']:
                    resp_headers.pop(h, None)

                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection', 'transfer-encoding'):
                        self.send_header(k, v)
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)
                stats_increment('success_count')

        except urllib.error.HTTPError as e:
            body = e.read()
            resp_headers = dict(e.headers)
            self.send_response(e.code)
            for k, v in resp_headers.items():
                if k.lower() not in ('connection', 'transfer-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            stats_increment('error_count')
            add_log('ERROR', f'Transparent proxy error {e.code}: {self.path}')

        except Exception as e:
            print(f'[ERROR] {self.command} {self.path}: {e}')
            self._respond_json(502, {'error': 'proxy_error', 'message': str(e)})
            stats_increment('error_count')
            add_log('ERROR', f'Transparent proxy exception: {e}')

    def _handle_health(self):
        """Diagnose connectivity to upstream services."""
        checks = [
            ('auth.docker.io', f'{AUTH_URL}/token?service=registry.docker.io&scope=repository:library/alpine:pull'),
            ('registry-1.docker.io', f'https://{HUB_HOST}/v2/'),
            ('hub.docker.com', 'https://hub.docker.com/'),
        ]
        results = []
        for name, url in checks:
            start = time.time()
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'docker-proxy/health'})
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    elapsed = int((time.time() - start) * 1000)
                    ok = resp.status in (200, 401)  # 401 is expected for registry without auth
                    results.append({
                        'name': name, 'status': f'HTTP {resp.status}',
                        'latency': f'{elapsed}ms', 'detail': 'OK' if ok else f'HTTP {resp.status}'
                    })
            except urllib.error.HTTPError as e:
                elapsed = int((time.time() - start) * 1000)
                ok = e.code in (200, 401)  # 401 is expected for registry without auth
                results.append({
                    'name': name, 'status': f'HTTP {e.code}',
                    'latency': f'{elapsed}ms', 'detail': 'OK' if ok else f'HTTP {e.code}'
                })
            except Exception as e:
                elapsed = int((time.time() - start) * 1000)
                results.append({
                    'name': name, 'status': 'FAIL',
                    'latency': f'{elapsed}ms', 'detail': str(e)
                })
        self._respond_json(200, {
            'proxy': 'running',
            'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'listen': f':{PORT}',
            'checks': results,
        })

    def _follow_cdn(self, location):
        """Follow CDN redirect for blob downloads, stream result to client."""
        # Remove Authorization header for CDN requests
        fwd_headers = {
            'User-Agent': self.headers.get('User-Agent', 'docker-proxy/1.0'),
            'Accept': self.headers.get('Accept', '*/*'),
        }
        try:
            req = urllib.request.Request(location, headers=fwd_headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                resp_headers = dict(resp.getheaders())
                resp_headers['Access-Control-Allow-Origin'] = '*'
                resp_headers['Access-Control-Expose-Headers'] = '*'
                resp_headers['Cache-Control'] = 'max-age=31536000'
                for h in ['Content-Security-Policy', 'Content-Security-Policy-Report-Only', 'Clear-Site-Data']:
                    resp_headers.pop(h, None)
                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection', 'transfer-encoding'):
                        self.send_header(k, v)
                self.end_headers()
                # Stream body in chunks
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            stats_increment('success_count')
        except Exception as e:
            print(f'[ERROR] CDN follow failed: {location} -> {e}')
            self._respond_json(502, {'error': 'cdn_error', 'message': str(e)})
            stats_increment('error_count')
            add_log('ERROR', f'CDN follow failed: {e}')

    def _rewrite_auth(self, auth):
        """Rewrite Www-Authenticate header to point to this proxy."""
        host = self.headers.get('Host', f'localhost:{PORT}')
        auth = auth.replace(AUTH_URL, f'http://{host}')
        auth = auth.replace('https://ghcr.io/token', f'http://{host}/token')
        auth = auth.replace('https://quay.io/v2/auth', f'http://{host}/token')
        return auth

    def _check_dashboard_auth(self):
        """Check dashboard auth via cookie or query param. Returns True if allowed."""
        # Get current token (settings file takes priority over env var)
        settings = get_settings()
        token = settings.get('dashboard_token', '') or DASHBOARD_TOKEN
        if not token:
            return True

        # Check cookie
        cookie = self.headers.get('Cookie', '')
        if f'dashboard_token={token}' in cookie:
            return True

        # Check query param ?token=xxx
        if '?' in self.path:
            for part in self.path.split('?', 1)[1].split('&'):
                if part.startswith('token=') and part[6:] == token:
                    self._pending_cookie = f'dashboard_token={token}; Path=/; HttpOnly; Max-Age=86400'
                    return True

        # Auth required - show login page
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        self.end_headers()
        self.wfile.write(LOGIN_HTML.encode())
        return False

    def _respond_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        if hasattr(self, '_pending_cookie') and self._pending_cookie:
            self.send_header('Set-Cookie', self._pending_cookie)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    # Ensure data directory exists
    for fpath in [USERS_FILE, ACCOUNTS_FILE, SETTINGS_FILE, USAGE_FILE]:
        dirname = os.path.dirname(fpath)
        if dirname:
            os.makedirs(dirname, exist_ok=True)

    server = http.server.HTTPServer(('0.0.0.0', PORT), ProxyHandler)
    print(f'Docker proxy listening on :{PORT} (mode={MODE}, blocked_uas={len(BLOCKED_UAS)})')
    print(f'Accounts file: {ACCOUNTS_FILE}')
    print(f'Users file: {USERS_FILE}')
    print(f'Settings file: {SETTINGS_FILE}')
    print(f'Usage file: {USAGE_FILE}')
    users = get_users()
    print(f'User auth: {len(users)} registered users')
    settings = get_settings()
    print(f'Anonymous pulls: {settings.get("anonymous_daily_pulls", 100)}/day per IP')
    print(f'Dashboard: http://localhost:{PORT}/dashboard')
    server.serve_forever()
