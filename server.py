#!/usr/bin/env python3
"""Lightweight Docker Hub proxy - transparent for browser, registry API with library/ prefix."""

import http.server
import urllib.request
import urllib.error
import json
import re
import os
import ssl
import time

PORT = int(os.environ.get('PORT', 3000))
HUB_HOST = 'registry-1.docker.io'
AUTH_URL = 'https://auth.docker.io'

# Token cache
_token_cache = {}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects - return them to the client."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Don't follow


def get_token(repo):
    now = time.time()
    cached = _token_cache.get(repo)
    if cached and cached['expires'] > now:
        return cached['token']
    url = f'{AUTH_URL}/token?service=registry.docker.io&scope=repository:{repo}:pull'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'docker-proxy/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            token = data.get('token')
            if token:
                _token_cache[repo] = {
                    'token': token,
                    'expires': now + data.get('expires_in', 300) - 60,
                }
            return token
    except Exception as e:
        print(f'[WARN] Token fetch failed for {repo}: {e}')
        return None


def is_official_image(path):
    """Check if path is /v2/<name>/... where <name> has no namespace (no /)."""
    m = re.match(r'^/v2/([^/]+)/(manifests|blobs|tags)/', path)
    if not m:
        m = re.match(r'^/v2/([^/]+)/tags/list', path)
    if not m:
        return False
    return '/' not in m.group(1)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f'[{self.log_date_time_string()}] {args[0]}')

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def _route(self):
        path = self.path.split('?')[0]
        query = self.path.split('?')[1] if '?' in self.path else ''

        # /v2/ ping - registry 2.0 handshake
        if path == '/v2/':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Docker-Distribution-API-Version', 'registry/2.0')
            self.end_headers()
            self.wfile.write(b'{}')
            return

        # /v2/* registry API - library/ prefix + token exchange
        if path.startswith('/v2/'):
            upstream_path = path
            if is_official_image(path):
                upstream_path = path.replace('/v2/', '/v2/library/', 1)
            self._proxy_registry(upstream_path, query)
            return

        # Everything else - transparent proxy to hub.docker.com
        self._proxy_transparent(path, query)

    def _proxy_registry(self, upstream_path, query):
        """Proxy /v2/* registry API requests with token exchange."""
        repo = None
        m = re.match(r'^/v2/(.+?)/(manifests|blobs|tags)/', upstream_path)
        if m:
            repo = m.group(1)
        else:
            m = re.match(r'^/v2/(.+)/tags/list', upstream_path)
            if m:
                repo = m.group(1)

        upstream_url = f'https://{HUB_HOST}{upstream_path}'
        if query:
            upstream_url += f'?{query}'

        fwd_headers = {
            'Host': HUB_HOST,
            'User-Agent': self.headers.get('User-Agent', 'docker-proxy/1.0'),
            'Accept': self.headers.get('Accept', '*/*'),
            'Accept-Encoding': 'identity',
            'Connection': 'keep-alive',
        }

        if repo:
            token = get_token(repo)
            if token:
                fwd_headers['Authorization'] = f'Bearer {token}'

        try:
            req = urllib.request.Request(upstream_url, headers=fwd_headers)
            ctx = ssl.create_default_context()
            # Don't follow redirects - Docker Hub blobs redirect to signed CDN URLs
            # that must be fetched directly by the client
            opener = urllib.request.build_opener(NoRedirectHandler())
            with opener.open(req, timeout=30) as resp:
                body = resp.read()
                resp_headers = dict(resp.getheaders())

                # Rewrite redirect Location to go through this proxy
                if resp.status in (301, 302, 307, 308) and 'location' in resp_headers:
                    location = resp_headers['location']
                    # If redirecting to Docker Hub/registry, rewrite to use this proxy
                    if 'registry-1.docker.io' in location:
                        location = location.replace(f'https://{HUB_HOST}', '')
                    resp_headers['location'] = location

                if 'Www-Authenticate' in resp_headers:
                    resp_headers['Www-Authenticate'] = resp_headers['Www-Authenticate'].replace(
                        AUTH_URL, f'http://{self.headers.get("Host", f"localhost:{PORT}")}'
                    )
                resp_headers['Docker-Distribution-API-Version'] = 'registry/2.0'
                for h in ['Content-Security-Policy', 'Transfer-Encoding']:
                    resp_headers.pop(h, None)

                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection',):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

        except urllib.error.HTTPError as e:
            body = e.read()
            resp_headers = dict(e.headers)

            # Handle redirects - pass Location to client
            if e.code in (301, 302, 307, 308) and 'location' in resp_headers:
                location = resp_headers['location']
                if 'registry-1.docker.io' in location:
                    location = location.replace(f'https://{HUB_HOST}', '')
                resp_headers['location'] = location

            if 'Www-Authenticate' in resp_headers:
                resp_headers['Www-Authenticate'] = resp_headers['Www-Authenticate'].replace(
                    AUTH_URL, f'http://{self.headers.get("Host", f"localhost:{PORT}")}'
                )
            resp_headers['Docker-Distribution-API-Version'] = 'registry/2.0'
            self.send_response(e.code)
            for k, v in resp_headers.items():
                if k.lower() not in ('connection', 'transfer-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        except Exception as e:
            print(f'[ERROR] {self.command} {self.path}: {e}')
            self._respond_json(502, {'error': 'proxy_error', 'message': str(e)})

    def _proxy_transparent(self, path, query):
        """Transparent proxy to hub.docker.com for browser access."""
        # /v1/* paths go to index.docker.io (search API)
        if path.startswith('/v1/'):
            upstream_host = 'index.docker.io'
        else:
            upstream_host = 'hub.docker.com'

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

        # Forward cookies for logged-in sessions
        if self.headers.get('Cookie'):
            fwd_headers['Cookie'] = self.headers.get('Cookie')

        # Forward Authorization header for authenticated requests
        if self.headers.get('Authorization'):
            fwd_headers['Authorization'] = self.headers.get('Authorization')

        try:
            req = urllib.request.Request(upstream_url, headers=fwd_headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                body = resp.read()
                resp_headers = dict(resp.getheaders())

                # Rewrite redirects to stay on this proxy
                if 'Location' in resp_headers:
                    resp_headers['Location'] = resp_headers['Location'].replace(
                        'https://hub.docker.com', ''
                    ).replace(
                        'https://index.docker.io', ''
                    )

                # Remove security headers that block embedding
                for h in ['Content-Security-Policy', 'X-Frame-Options',
                          'Content-Security-Policy-Report-Only']:
                    resp_headers.pop(h, None)

                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    if k.lower() not in ('connection', 'transfer-encoding'):
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

    def _respond_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', PORT), ProxyHandler)
    print(f'Docker proxy listening on :{PORT}')
    server.serve_forever()
