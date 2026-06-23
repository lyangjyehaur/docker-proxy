#!/usr/bin/env python3
"""Lightweight multi-registry Docker proxy.

Supports: Docker Hub, GHCR, Quay, GCR, K8s GCR, NVCR, Cloudsmith.
Transparent browser view, auto library/ prefix, token exchange, CORS.
"""

import http.server
import urllib.request
import urllib.error
import json
import re
import os
import ssl
import time
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(os.environ.get('PORT', 3000))

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
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Max-Age': '1728000',
}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects - return them to the client."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_token(repo, auth_url=AUTH_URL, service='registry.docker.io'):
    """Get a pull token for the given repo, with caching."""
    cache_key = (auth_url, repo)
    now = time.time()
    cached = _token_cache.get(cache_key)
    if cached and cached['expires'] > now:
        return cached['token']

    url = f'{auth_url}/token?service={service}&scope=repository:{repo}:pull'
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


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f'[{self.log_date_time_string()}] {args[0]}')

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def _route(self):
        # Parse URL
        raw_path = self.path
        # Fix %3A encoding: some clients encode : as %3A in tag references
        # e.g. /v2/python/manifests/sha256%3Aabc123 -> /v2/python/manifests/sha256:abc123
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

        # Determine upstream registry from subdomain or ns= param
        hostname = params.get('hubhost') or self.headers.get('Host', '')
        host_top = hostname.split('.')[0]
        hub_host = resolve_upstream(host_top, params.get('ns'))
        is_docker_hub = (hub_host == HUB_HOST)

        # /v2/ ping - registry 2.0 handshake
        if path == '/v2/':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Docker-Distribution-API-Version', 'registry/2.0')
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b'{}')
            return

        # /v2/* registry API
        if path.startswith('/v2/'):
            upstream_path = path
            # Auto-add library/ prefix for Docker Hub official images
            if is_docker_hub and is_official_image(path):
                upstream_path = path.replace('/v2/', '/v2/library/', 1)
            self._proxy_registry(upstream_path, qs, hub_host, is_docker_hub)
            return

        # /token endpoint - proxy to auth server
        if '/token' in path:
            self._proxy_token(path, qs, hub_host)
            return

        # /v1/* search API -> index.docker.io
        if path.startswith('/v1/'):
            self._proxy_transparent(path, qs, 'index.docker.io')
            return

        # Everything else -> hub.docker.com
        self._proxy_transparent(path, qs, 'hub.docker.com')

    def _proxy_registry(self, upstream_path, query, hub_host, is_docker_hub):
        """Proxy /v2/* registry API requests with token exchange."""
        # Extract repo name for token
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

        # Get token - different auth servers for different registries
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

        try:
            req = urllib.request.Request(upstream_url, headers=fwd_headers)
            # Don't follow redirects - blobs redirect to signed CDN URLs
            opener = urllib.request.build_opener(NoRedirectHandler())
            with opener.open(req, timeout=30) as resp:
                body = resp.read()
                resp_headers = dict(resp.getheaders())

                # Rewrite redirect Location
                if resp.status in (301, 302, 307, 308) and 'location' in resp_headers:
                    resp_headers['location'] = self._rewrite_location(
                        resp_headers['location'], hub_host
                    )

                # Rewrite Www-Authenticate
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

        except urllib.error.HTTPError as e:
            body = e.read()
            resp_headers = dict(e.headers)

            if e.code in (301, 302, 307, 308) and 'location' in resp_headers:
                resp_headers['location'] = self._rewrite_location(
                    resp_headers['location'], hub_host
                )

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

        except Exception as e:
            print(f'[ERROR] {self.command} {self.path}: {e}')
            self._respond_json(502, {'error': 'proxy_error', 'message': str(e)})

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
        except urllib.error.HTTPError as e:
            body = e.read()
            self.send_response(e.code)
            for k, v in dict(e.headers).items():
                if k.lower() not in ('connection', 'transfer-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self._respond_json(502, {'error': 'token_error', 'message': str(e)})

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

                # Rewrite redirects
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

        except urllib.error.HTTPError as e:
            body = e.read()
            resp_headers = dict(e.headers)
            self.send_response(e.code)
            for k, v in resp_headers.items():
                if k.lower() not in ('connection', 'transfer-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        except Exception as e:
            print(f'[ERROR] {self.command} {self.path}: {e}')
            self._respond_json(502, {'error': 'proxy_error', 'message': str(e)})

    def _rewrite_location(self, location, hub_host):
        """Rewrite redirect Location header."""
        if hub_host in location:
            location = location.replace(f'https://{hub_host}', '')
        if 'registry-1.docker.io' in location:
            location = location.replace('https://registry-1.docker.io', '')
        return location

    def _rewrite_auth(self, auth):
        """Rewrite Www-Authenticate header to point to this proxy."""
        host = self.headers.get('Host', f'localhost:{PORT}')
        auth = auth.replace(AUTH_URL, f'http://{host}')
        auth = auth.replace('https://ghcr.io/token', f'http://{host}/token')
        auth = auth.replace('https://quay.io/v2/auth', f'http://{host}/token')
        return auth

    def _respond_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', PORT), ProxyHandler)
    print(f'Docker proxy listening on :{PORT}')
    server.serve_forever()
