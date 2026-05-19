#!/usr/bin/env python3
"""
Route FNkit HTTP(S) lookups through Tor (SOCKS5), with optional local Tor daemon + bridges.

Inspired by transparent Tor routing tools (e.g. backbox-anonymous); this module stays at
application level (no iptables/root): urllib traffic uses SOCKS5h on 127.0.0.1:9050 by default.

Config: ``data/config/.tor_transport.json`` (local, not committed).
Bridges: ``data/config/tor_bridges.txt`` — see ``data/config/tor_bridges.txt.example``.
Daemon: ``scripts/fnkit-tor.sh start|stop|status``.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
from urllib.request import Request

from paths import CONFIG_DIR, REPO_ROOT, TOR_BRIDGES_FILE, TOR_CONFIG_FILE, TOR_DAEMON_DIR

DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
TOR_CHECK_FALLBACK = "https://check.torproject.org/?lang=en"

_orig_urlopen = urllib.request.urlopen
_active = False
_proxy: Tuple[str, int] = (DEFAULT_SOCKS_HOST, DEFAULT_SOCKS_PORT)
_fnkit_tor_script = REPO_ROOT / "scripts" / "fnkit-tor.sh"


def _load_json_config() -> Dict[str, Any]:
    if not TOR_CONFIG_FILE.exists():
        return {}
    try:
        with open(TOR_CONFIG_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(cfg: Dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(TOR_CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def config_enabled() -> bool:
    cfg = _load_json_config()
    return bool(cfg.get("enabled"))


def is_active() -> bool:
    return _active


def socks_endpoint() -> Tuple[str, int]:
    return _proxy


def probe_socks(
    host: Optional[str] = None,
    port: Optional[int] = None,
    *,
    timeout: float = 3.0,
) -> bool:
    """Return True if SOCKS port accepts a connection."""
    h = host or _proxy[0]
    p = port if port is not None else _proxy[1]
    try:
        with socket.create_connection((h, p), timeout=timeout):
            return True
    except OSError:
        return False


def _socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    *,
    timeout: float = 30.0,
) -> socket.socket:
    """SOCKS5 CONNECT with remote hostname (SOCKS5h semantics)."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise OSError("SOCKS5: no auth method accepted")
        host_b = dest_host.encode("idna") if dest_host.isascii() else dest_host.encode("utf-8")
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", dest_port)
        sock.sendall(req)
        hdr = sock.recv(4)
        if len(hdr) < 4 or hdr[0] != 0x05:
            raise OSError("SOCKS5: bad reply header")
        if hdr[1] != 0x00:
            raise OSError(f"SOCKS5: connect failed (code {hdr[1]})")
        atyp = hdr[3]
        if atyp == 0x01:
            sock.recv(4 + 2)
        elif atyp == 0x03:
            ln = sock.recv(1)
            if ln:
                sock.recv(ln[0] + 2)
        elif atyp == 0x04:
            sock.recv(16 + 2)
        return sock
    except Exception:
        sock.close()
        raise


class _SocksHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = _socks5_connect(
            _proxy[0],
            _proxy[1],
            self.host,
            self.port or 80,
            timeout=float(self.timeout or 30),
        )


class _SocksHTTPSConnection(_SocksHTTPConnection):
    default_port = 443

    def connect(self) -> None:
        self.sock = _socks5_connect(
            _proxy[0],
            _proxy[1],
            self.host,
            self.port or 443,
            timeout=float(self.timeout or 30),
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _SocksHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: Request) -> http.client.HTTPResponse:
        return self.do_open(_SocksHTTPConnection, req)


class _SocksHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: Request) -> http.client.HTTPResponse:
        return self.do_open(_SocksHTTPSConnection, req)


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_SocksHTTPHandler(), _SocksHTTPSHandler())


_opener: Optional[urllib.request.OpenerDirector] = None


def patched_urlopen(
    url: Union[str, Request],
    data=None,
    timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
    *,
    cafile=None,
    capath=None,
    cadefault=False,
    context=None,
):
    if not _active:
        return _orig_urlopen(
            url,
            data=data,
            timeout=timeout,
            cafile=cafile,
            capath=capath,
            cadefault=cadefault,
            context=context,
        )
    global _opener
    if _opener is None:
        _opener = _build_opener()
    if isinstance(url, str):
        req = Request(url, data=data)
    else:
        req = url
        if data is not None and req.data is None:
            req = Request(req.full_url, data=data, headers=dict(req.header_items()))
    return _opener.open(req, timeout=timeout)


def activate(
    *,
    socks_host: str = DEFAULT_SOCKS_HOST,
    socks_port: int = DEFAULT_SOCKS_PORT,
    persist: bool = True,
) -> bool:
    """Enable Tor transport; returns False if SOCKS is unreachable."""
    global _active, _proxy, _opener
    _proxy = (socks_host, int(socks_port))
    if not probe_socks():
        return False
    _opener = None
    urllib.request.urlopen = patched_urlopen  # type: ignore[assignment]
    _active = True
    if persist:
        cfg = _load_json_config()
        cfg["enabled"] = True
        cfg["socks_host"] = socks_host
        cfg["socks_port"] = int(socks_port)
        save_config(cfg)
    return True


def deactivate(*, persist: bool = True) -> None:
    global _active, _opener
    urllib.request.urlopen = _orig_urlopen  # type: ignore[assignment]
    _active = False
    _opener = None
    if persist:
        cfg = _load_json_config()
        cfg["enabled"] = False
        save_config(cfg)


def _parse_socks_arg(value: Optional[str]) -> Tuple[str, int]:
    if not value:
        cfg = _load_json_config()
        host = str(cfg.get("socks_host") or DEFAULT_SOCKS_HOST)
        port = int(cfg.get("socks_port") or DEFAULT_SOCKS_PORT)
        return host, port
    if ":" in value:
        host, port_s = value.rsplit(":", 1)
        return host.strip(), int(port_s)
    return value.strip(), DEFAULT_SOCKS_PORT


def run_tor_script(
    action: str,
    *,
    timeout: int = 120,
    extra_env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str]:
    if not _fnkit_tor_script.is_file():
        return 1, f"Missing {_fnkit_tor_script}"
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            ["/bin/bash", str(_fnkit_tor_script), action],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def ensure_tor_daemon(
    *,
    use_bridges: bool = True,
    exit_countries: Optional[str] = None,
) -> Tuple[bool, str]:
    """Start local Tor via fnkit-tor.sh if SOCKS is down."""
    if probe_socks():
        return True, "SOCKS already listening"
    action = "start"
    if use_bridges and TOR_BRIDGES_FILE.is_file():
        action = "start-bridges"
    extra_env: Dict[str, str] = {}
    if exit_countries:
        extra_env["FNKIT_TOR_EXIT_NODES"] = exit_countries
    code, out = run_tor_script(action, timeout=180, extra_env=extra_env or None)
    deadline = time.time() + 90
    while time.time() < deadline:
        if probe_socks():
            return True, out or "Tor started"
        time.sleep(1.5)
    return False, out or f"Tor start failed (exit {code})"


def verify_tor_circuit(*, timeout: float = 25.0) -> Dict[str, Any]:
    """Check check.torproject.org JSON API through current transport."""
    result: Dict[str, Any] = {"ok": False, "is_tor": False, "ip": None, "error": None}
    try:
        req = Request(TOR_CHECK_URL, headers={"User-Agent": "fnkit-tor_transport/1.0"})
        with patched_urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        result["ip"] = data.get("IP") or data.get("ip")
        result["is_tor"] = bool(data.get("IsTor"))
        result["ok"] = True
        return result
    except Exception as exc:
        result["error"] = str(exc)
    try:
        req = Request(TOR_CHECK_FALLBACK, headers={"User-Agent": "fnkit-tor_transport/1.0"})
        with patched_urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        result["ok"] = True
        result["is_tor"] = "Congratulations" in html and "configured to use Tor" in html
        return result
    except Exception as exc2:
        result["error"] = str(exc2)
    return result


def status_report(*, lang: str = "en") -> str:
    host, port = _proxy
    lines = [
        f"Transport: {'Tor (SOCKS5)' if _active else 'direct'}",
        f"SOCKS: {host}:{port} ({'up' if probe_socks(host, port) else 'down'})",
        f"Config: {TOR_CONFIG_FILE} (enabled={config_enabled()})",
    ]
    if TOR_BRIDGES_FILE.is_file():
        lines.append(f"Bridges file: {TOR_BRIDGES_FILE} (present)")
    else:
        lines.append(f"Bridges file: {TOR_BRIDGES_FILE} (missing — direct only)")
    if _active and probe_socks(host, port):
        v = verify_tor_circuit()
        if v.get("ok"):
            tor_on = "yes" if v.get("is_tor") else "no"
            lines.append(f"check.torproject.org: IsTor={tor_on}, IP={v.get('ip') or '?'}")
        else:
            lines.append(f"check.torproject.org: failed ({v.get('error')})")
    return "\n".join(lines)


def init_from_cli(args, *, lang: str = "en") -> Optional[str]:
    """
    Apply --tor / --no-tor / config / FNKIT_TOR.
    Returns error message string or None on success.
    """
    if getattr(args, "tor_status", False):
        print(status_report(lang=lang))
        sys.exit(0)

    env_tor = os.environ.get("FNKIT_TOR", "").strip().lower() in ("1", "true", "yes", "on")
    want = env_tor or config_enabled()
    if getattr(args, "tor", False):
        want = True
    if getattr(args, "no_tor", False):
        want = False

    if not want:
        if config_enabled() and getattr(args, "no_tor", False):
            deactivate(persist=True)
        return None

    host, port = _parse_socks_arg(getattr(args, "tor_socks", None))

    if not probe_socks(host, port) and (
        getattr(args, "tor_start", False)
        or getattr(args, "tor", False)
        or config_enabled()
    ):
        ok, msg = ensure_tor_daemon(use_bridges=True)
        if not ok:
            return msg or "Could not start Tor (install tor + optional obfs4proxy; see README)"

    if not probe_socks(host, port):
        hint = (
            f"SOCKS {host}:{port} unreachable. Run: ./scripts/fnkit-tor.sh start "
            f"(or add bridges to {TOR_BRIDGES_FILE})"
        )
        return hint

    persist = bool(getattr(args, "tor", False) or env_tor)
    if not activate(socks_host=host, socks_port=port, persist=persist):
        return f"Failed to activate SOCKS {host}:{port}"

    if getattr(args, "tor", False):
        v = verify_tor_circuit()
        if v.get("ok") and not v.get("is_tor"):
            deactivate(persist=False)
            return (
                "SOCKS is up but traffic does not appear to exit via Tor. "
                "Add obfs4 bridges to data/config/tor_bridges.txt and run: "
                "./scripts/fnkit-tor.sh start-bridges"
            )
    return None

