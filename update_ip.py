"""Pangolin Rule Updater — multi-client webhook server.

Each client has a unique secret token mapped to one or more Pangolin rules.
When a client calls GET /update?token=<secret>, their originating IP is applied
to every rule defined for that token.

Configuration is loaded from a YAML file (default: config.yml, override with
the CONFIG_FILE environment variable).
"""

import hmac
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests
import yaml

# Secrets shorter than this are rejected at startup.
_MIN_SECRET_LEN = 32

# Forwarded-IP headers are only trusted when the direct TCP peer is on a
# private network (i.e. a reverse proxy container on the same Docker network).
# Connections arriving from a public IP are served using the TCP peer address
# so that a client cannot whitelist an arbitrary IP by forging these headers.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ── Configuration models ───────────────────────────────────────────────────────

@dataclass
class RuleTarget:
    resource_id: int
    rule_id: int
    priority: int = 100
    action: str = "ACCEPT"
    match: str = "IP"
    enabled: bool = True


@dataclass
class ClientConfig:
    name: str
    secret: str
    rules: list[RuleTarget]
    pangolin_host: str
    pangolin_api_key: str
    _cached_ip: Optional[str] = field(default=None, repr=False)


# ── Config loading ─────────────────────────────────────────────────────────────

def _parse_rule(raw: dict) -> RuleTarget:
    match = str(raw.get("match", "IP")).upper()
    if match not in ("IP", "CIDR", "PATH"):
        raise ValueError(f"Invalid match value: {match!r} — must be IP, CIDR, or PATH")
    action = str(raw.get("action", "ACCEPT")).upper()
    if action not in ("ACCEPT", "DROP"):
        raise ValueError(f"Invalid action value: {action!r} — must be ACCEPT or DROP")
    return RuleTarget(
        resource_id=int(raw["resource_id"]),
        rule_id=int(raw["rule_id"]),
        priority=int(raw.get("priority", 100)),
        action=action,
        match=match,
        enabled=bool(raw.get("enabled", True)),
    )


def load_config(path: str) -> tuple[int, str, list[ClientConfig]]:
    """Load YAML config. Returns (server_port, server_path, clients)."""
    with open(path) as f:
        cfg = yaml.safe_load(f)

    global_host = str(cfg.get("pangolin_host", "")).rstrip("/")
    global_key = str(cfg.get("pangolin_api_key", ""))

    server_cfg = cfg.get("server", {})
    port = int(server_cfg.get("port", 8080))
    path = str(server_cfg.get("path", "/update"))

    seen_secrets: set[str] = set()
    clients: list[ClientConfig] = []

    for raw_client in cfg.get("clients", []):
        name = str(raw_client["name"])
        secret = str(raw_client["secret"])

        if not secret:
            raise ValueError(f"Client {name!r}: secret must not be empty")
        if len(secret) < _MIN_SECRET_LEN:
            raise ValueError(
                f"Client {name!r}: secret is too short "
                f"({len(secret)} chars, minimum {_MIN_SECRET_LEN}). "
                f"Generate one with: openssl rand -hex {_MIN_SECRET_LEN // 2}"
            )
        if secret in seen_secrets:
            raise ValueError(f"Duplicate secret detected for client {name!r}")
        seen_secrets.add(secret)

        host = str(raw_client.get("pangolin_host") or global_host).rstrip("/")
        key = str(raw_client.get("pangolin_api_key") or global_key)

        if not host:
            raise ValueError(f"Client {name!r}: pangolin_host is not set")
        if not key:
            raise ValueError(f"Client {name!r}: pangolin_api_key is not set")

        rules = [_parse_rule(r) for r in raw_client.get("rules", [])]
        if not rules:
            raise ValueError(f"Client {name!r}: at least one rule must be defined")

        clients.append(ClientConfig(
            name=name,
            secret=secret,
            rules=rules,
            pangolin_host=host,
            pangolin_api_key=key,
        ))

    if not clients:
        raise ValueError("No clients defined in config")

    return port, path, clients


# ── Pangolin API ───────────────────────────────────────────────────────────────

# One requests.Session per Pangolin API key, reusing TCP connections
_sessions: dict[str, requests.Session] = {}


def _get_session(api_key: str) -> requests.Session:
    if api_key not in _sessions:
        s = requests.Session()
        s.headers.update({
            "accept": "*/*",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })
        _sessions[api_key] = s
    return _sessions[api_key]


def _update_pangolin_rule(host: str, api_key: str, rule: RuleTarget, ip: str) -> bool:
    url = f"{host}/v1/resource/{rule.resource_id}/rule/{rule.rule_id}"
    payload = {
        "action":   rule.action,
        "match":    rule.match,
        "value":    ip,
        "priority": rule.priority,
        "enabled":  rule.enabled,
    }
    try:
        resp = _get_session(api_key).post(url, data=json.dumps(payload), timeout=10)
        if resp.status_code != 200:
            # Truncate response body to avoid flooding logs with large payloads.
            snippet = resp.text[:200].replace("\n", " ")
            print(f"[error] Rule {rule.rule_id} (resource {rule.resource_id}): "
                  f"{resp.status_code} {snippet}")
            return False
        print(f"[pangolin] rule {rule.rule_id} (resource {rule.resource_id}) → {ip}")
        return True
    except Exception as e:
        print(f"[error] Rule {rule.rule_id} (resource {rule.resource_id}): {e}")
        return False


def _push_ip_for_client(client: ClientConfig, ip: str) -> tuple[int, int]:
    """Update all rules for a client. Returns (success_count, total_count)."""
    success = sum(
        _update_pangolin_rule(client.pangolin_host, client.pangolin_api_key, rule, ip)
        for rule in client.rules
    )
    return success, len(client.rules)


# ── HTTP handler ───────────────────────────────────────────────────────────────

_HTML_OK = ("<html><body><h1>Updated</h1>"
            "<p>All {total} rule(s) set to: {ip}</p></body></html>")
_HTML_NO_CHANGE = ("<html><body><h1>No change</h1>"
                   "<p>IP already up-to-date: {ip}</p></body></html>")
_HTML_PARTIAL = ("<html><body><h1>Partial update</h1>"
                 "<p>{ok}/{total} rule(s) updated to: {ip}</p></body></html>")
_HTML_UNAUTH = "<html><body><h1>Unauthorized</h1></body></html>"
_HTML_ERROR  = "<html><body><h1>Error</h1><p>Update failed.</p></body></html>"


def _extract_client_ip(handler: "UpdateHandler") -> str:
    """Extract the real client IP from the request.

    Forwarded-IP headers (X-Real-Ip, Cf-Connecting-Ip, X-Forwarded-For) are
    only trusted when the direct TCP peer is on a private network, meaning the
    connection came through a trusted reverse proxy (e.g. Pangolin on the same
    Docker network).  Direct connections from public IPs use the TCP peer
    address so that forwarded headers cannot be forged to spoof the source IP.

    For X-Forwarded-For the rightmost (last) entry is used because it is
    appended by the last trusted hop and cannot be prepended by the client.
    """
    peer_ip = handler.client_address[0]

    if not _is_private_ip(peer_ip):
        # Direct connection from a public IP — ignore all forwarded headers.
        return peer_ip

    # X-Real-Ip: set directly by Nginx/Traefik/Pangolin to the client IP.
    val = handler.headers.get("X-Real-Ip", "").strip()
    if val:
        return val

    # Cf-Connecting-Ip: set by Cloudflare to the originating client IP.
    val = handler.headers.get("Cf-Connecting-Ip", "").strip()
    if val:
        return val

    # X-Forwarded-For: take the rightmost entry — it is appended by the last
    # trusted proxy and cannot be prepended/forged by the client.
    fwd = handler.headers.get("X-Forwarded-For", "").strip()
    if fwd:
        return fwd.split(",")[-1].strip()

    return peer_ip


def _lookup_client(
    client_map: dict[str, ClientConfig], token: str
) -> Optional[ClientConfig]:
    """Constant-time token lookup to prevent timing side-channel attacks.

    Iterates every registered client using hmac.compare_digest so that the
    response time does not reveal whether a submitted token is 'close' to a
    valid one.  All comparisons run regardless of early matches.
    """
    result: Optional[ClientConfig] = None
    token_bytes = token.encode()
    for secret, client in client_map.items():
        if hmac.compare_digest(secret.encode(), token_bytes):
            result = client
    return result


class UpdateHandler(BaseHTTPRequestHandler):
    # Injected at class-construction time in main()
    _client_map: dict[str, ClientConfig]
    _server_path: str

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path != self._server_path:
            self._send(404, "<h1>Not Found</h1>")
            return

        token = parse_qs(parsed.query).get("token", [""])[0]
        client = _lookup_client(self._client_map, token)
        if not client:
            print("[warn] Unauthorized request — bad or missing token")
            self._send(401, _HTML_UNAUTH)
            return

        requester_ip = _extract_client_ip(self)
        try:
            ipaddress.ip_address(requester_ip)
        except ValueError:
            print(f"[error] Unparseable client IP: {requester_ip!r}")
            self._send(400, _HTML_ERROR)
            return

        print(f"[trigger] {client.name} — request from {requester_ip}")

        if requester_ip == client._cached_ip:
            print(f"[trigger] {client.name} — IP unchanged, skipping update")
            self._send(200, _HTML_NO_CHANGE.format(ip=requester_ip))
            return

        ok, total = _push_ip_for_client(client, requester_ip)

        if ok == total:
            client._cached_ip = requester_ip
            self._send(200, _HTML_OK.format(ip=requester_ip, total=total))
        elif ok > 0:
            client._cached_ip = requester_ip
            self._send(207, _HTML_PARTIAL.format(ok=ok, total=total, ip=requester_ip))
        else:
            self._send(500, _HTML_ERROR)

    def _send(self, code: int, body: str) -> None:
        encoded = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        pass  # suppress default CLF access log


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    config_path = os.environ.get("CONFIG_FILE", "config.yml")
    print(f"[info] Loading config from {config_path!r}")

    try:
        port, path, clients = load_config(config_path)
    except FileNotFoundError:
        print(f"[fatal] Config file not found: {config_path}")
        sys.exit(1)
    except (KeyError, ValueError, TypeError) as e:
        print(f"[fatal] Config error: {e}")
        sys.exit(1)

    client_map: dict[str, ClientConfig] = {c.secret: c for c in clients}

    print(f"[info] {len(clients)} client(s) configured:")
    for c in clients:
        rule_ids = ", ".join(
            f"resource {r.resource_id}/rule {r.rule_id}" for r in c.rules
        )
        print(f"  - {c.name}: {len(c.rules)} rule(s) → [{rule_ids}]")

    # Build handler class with config injected as class attributes
    handler_cls = type("Handler", (UpdateHandler,), {
        "_client_map": client_map,
        "_server_path": path,
    })

    print(f"[info] Listening on 0.0.0.0:{port}{path}")
    with HTTPServer(("0.0.0.0", port), handler_cls) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()

