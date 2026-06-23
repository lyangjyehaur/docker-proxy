#!/usr/bin/env python3
"""Lightweight multi-registry Docker proxy.

Supports: Docker Hub, GHCR, Quay, GCR, K8s GCR, NVCR, Cloudsmith.
Transparent browser view, auto library/ prefix, token exchange, CORS.
Includes web dashboard and Docker Hub account management.
"""

import http.server
import urllib.request
import urllib.error
import json
import re
import os
import ssl
import time
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

# Dashboard auth token (set via env to protect dashboard/API)
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
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS, POST, DELETE',
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
    import base64
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
    m = re.match(r'^/v2/([^/]+)/(manifests|blobs|tags)/', path)
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
<h1>🚢 Docker Proxy</h1>
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
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px}
.card h3{color:var(--text-dim);font-size:.85em;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}
.card .value{font-size:2em;font-weight:700;color:#fff}
.card .sub{color:var(--text-dim);font-size:.85em;margin-top:4px}
.section{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}
.section h2{font-size:1.1em;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.section h2 span{font-size:1.2em}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);font-size:.9em}
th{color:var(--text-dim);font-weight:600;text-transform:uppercase;font-size:.75em;letter-spacing:.5px}
td{color:var(--text)}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75em;font-weight:600}
.badge.ok{background:rgba(63,185,80,.15);color:var(--green)}
.badge.fail{background:rgba(248,81,73,.15);color:var(--red)}
.badge.warn{background:rgba(210,153,34,.15);color:var(--yellow)}
.form-row{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.form-row input{flex:1;min-width:150px;padding:8px 12px;background:#0d1117;border:1px solid var(--border);
border-radius:6px;color:var(--text);font-size:.9em}
.form-row input::placeholder{color:var(--text-dim)}
.btn{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:.85em;font-weight:600;transition:.15s}
.btn.primary{background:var(--accent);color:#fff}
.btn.primary:hover{background:#79c0ff}
.btn.danger{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.btn.danger:hover{background:rgba(248,81,73,.3)}
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
  <div class="card"><h3>Successful</h3><div class="value" style="color:var(--green)" id="successReqs">--</div><div class="sub">2xx responses</div></div>
  <div class="card"><h3>Errors</h3><div class="value" style="color:var(--red)" id="errorReqs">--</div><div class="sub">4xx/5xx responses</div></div>
  <div class="card"><h3>Memory Usage</h3><div class="value" id="memUsage">--</div><div class="sub">RSS</div></div>
</div>

<div class="section">
  <h2><span>&#128268;</span> Upstream Health Checks</h2>
  <table>
    <thead><tr><th>Service</th><th>Status</th><th>Latency</th><th>Detail</th></tr></thead>
    <tbody id="healthBody"><tr><td colspan="4" style="text-align:center;color:var(--text-dim)">Loading...</td></tr></tbody>
  </table>
</div>

<div class="section">
  <h2><span>&#128100;</span> Docker Hub Accounts</h2>
  <div style="margin-bottom:16px">
    <div class="form-row">
      <input type="text" id="acctUser" placeholder="Username">
      <input type="text" id="acctToken" placeholder="Access Token">
      <input type="text" id="acctLabel" placeholder="Label (optional)">
      <button class="btn primary" onclick="addAccount()">Add Account</button>
    </div>
    <div id="addMsg" style="font-size:.85em;margin-top:4px"></div>
  </div>
  <table>
    <thead><tr><th>Label</th><th>Username</th><th>Pull Count</th><th>Rate Limit</th><th>Last Used</th><th>Action</th></tr></thead>
    <tbody id="accountsBody"><tr><td colspan="6" style="text-align:center;color:var(--text-dim)">Loading...</td></tr></tbody>
  </table>
</div>

<div class="section">
  <h2><span>&#128196;</span> Recent Logs</h2>
  <div class="log-entries" id="logsBody"><div class="entry" style="color:var(--text-dim)">Loading...</div></div>
</div>

<div class="refresh-info">Auto-refresh every 5 seconds &middot; <span id="lastRefresh"></span></div>

<script>
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
async function fetchJSON(url){
try{
var tk=new URLSearchParams(window.location.search).get('token')||'';
var sep=url.includes('?')?'&':'?';
var r=await fetch(tk?url+sep+'token='+encodeURIComponent(tk):url);
if(r.status===401){document.body.innerHTML='<h1 style="color:#f85149;text-align:center;margin-top:40vh">Session expired</h1>';return null}
return await r.json()
}catch(e){return null}}
async function refresh(){
  var s=await fetchJSON('/api/status');
  if(s){
    document.getElementById('totalReqs').textContent=fmt(s.total_requests);
    document.getElementById('successReqs').textContent=fmt(s.success_count);
    document.getElementById('errorReqs').textContent=fmt(s.error_count);
    document.getElementById('memUsage').textContent=memFmt(s.memory_rss);
    document.getElementById('uptimeText').textContent='Uptime: '+uptime(s.uptime_seconds);
    document.getElementById('statusDot').className='dot green';
    document.getElementById('statusText').textContent='Running on :'+s.port;
  }else{
    document.getElementById('statusDot').className='dot red';
    document.getElementById('statusText').textContent='Unreachable';
  }
  var h=await fetchJSON('/api/health');
  if(h&&h.checks){
    var tb='';
    h.checks.forEach(function(c){
      var cls=c.detail==='OK'?'ok':'fail';
      tb+='<tr><td>'+c.name+'</td><td><span class="badge '+cls+'">'+c.status+'</span></td><td>'+c.latency+'</td><td>'+c.detail+'</td></tr>';
    });
    document.getElementById('healthBody').innerHTML=tb;
  }
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
      tb+='<td><button class="btn danger" onclick="delAccount(\''+ac.username+'\')">Remove</button></td></tr>';
    });
    document.getElementById('accountsBody').innerHTML=tb;
  }
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
async function addAccount(){
  var u=document.getElementById('acctUser').value.trim();
  var t=document.getElementById('acctToken').value.trim();
  var l=document.getElementById('acctLabel').value.trim();
  var msg=document.getElementById('addMsg');
  if(!u||!t){msg.style.color='var(--red)';msg.textContent='Username and token are required.';return}
  try{
    var r=await fetch('/api/accounts',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:u,token:t,label:l||u})});
    var d=await r.json();
    if(d.ok){msg.style.color='var(--green)';msg.textContent='Account added!';
      document.getElementById('acctUser').value='';document.getElementById('acctToken').value='';document.getElementById('acctLabel').value='';
      refresh();
    }else{msg.style.color='var(--red)';msg.textContent=d.error||'Failed to add account.'}
  }catch(e){msg.style.color='var(--red)';msg.textContent='Request failed.'}
}
async function delAccount(username){
  if(!confirm('Remove account "'+username+'"?'))return;
  try{
    await fetch('/api/accounts?username='+encodeURIComponent(username),{method:'DELETE'});
    refresh();
  }catch(e){}
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

    def do_DELETE(self):
        self._route()

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

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
            if self.command == 'GET':
                accounts = get_accounts()
                # Mask tokens for display
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
        if path in ('/v2/', '/v2'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Docker-Distribution-API-Version', 'registry/2.0')
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b'{}')
            stats_increment('success_count')
            return

        # /v2/search/* -> hub.docker.com (DSM search API, not registry)
        if path.startswith('/v2/search/'):
            self._proxy_transparent(path, qs, 'hub.docker.com')
            return

        # /v2/* registry API
        if path.startswith('/v2/'):
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

    def _proxy_registry(self, upstream_path, query, hub_host, is_docker_hub):
        """Proxy /v2/* registry API requests with token exchange."""
        repo = None
        m = re.match(r'^/v2/(.+?)/(manifests|blobs|tags)/', upstream_path)
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
        # If no token configured, allow all access
        if not DASHBOARD_TOKEN:
            return True

        # Check cookie
        cookie = self.headers.get('Cookie', '')
        if f'dashboard_token={DASHBOARD_TOKEN}' in cookie:
            return True

        # Check query param ?token=xxx
        if '?' in self.path:
            for part in self.path.split('?', 1)[1].split('&'):
                if part.startswith('token=') and part[6:] == DASHBOARD_TOKEN:
                    # Authenticated - set cookie for future requests
                    self._pending_cookie = f'dashboard_token={DASHBOARD_TOKEN}; Path=/; HttpOnly; Max-Age=86400'
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
    server = http.server.HTTPServer(('0.0.0.0', PORT), ProxyHandler)
    print(f'Docker proxy listening on :{PORT} (mode={MODE}, blocked_uas={len(BLOCKED_UAS)})')
    print(f'Accounts file: {ACCOUNTS_FILE}')
    print(f'Dashboard: http://localhost:{PORT}/dashboard')
    server.serve_forever()
