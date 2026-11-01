"""Minimal VPNGate .ovpn -> sing-box openvpn-client converter (stdlib only)."""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_USERNAME = "vpn"
DEFAULT_PASSWORD = "vpn"
# VPNGate uses legacy crypto; sing-box >= 1.14 defaults to AEAD only,
# so the old ciphers must be listed explicitly.
DEFAULT_DATA_CIPHERS = ["AES-128-CBC", "AES-256-CBC", "BF-CBC"]
DEFAULT_AUTH = "SHA1"
# Cap concurrent throwaway sing-box dials
MAX_CONCURRENT_DIALS = 25
_DIAL_GATE = threading.BoundedSemaphore(MAX_CONCURRENT_DIALS)

_BLOCK_RE = re.compile(r"<(ca|cert|key|tls-auth|tls-crypt)>(.*?)</\1>", re.IGNORECASE | re.DOTALL)
_REMOTE_RE = re.compile(r"^\s*remote\s+(\S+)\s+(\d+)(?:\s+(\S+))?\s*$", re.IGNORECASE | re.MULTILINE)
_PROTO_RE = re.compile(r"^\s*proto\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_AUTH_RE = re.compile(r"^\s*auth\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_CIPHER_RE = re.compile(r"^\s*cipher\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_REMOTE_RANDOM_RE = re.compile(r"^\s*remote-random\s*$", re.IGNORECASE | re.MULTILINE)
_KEY_DIRECTION_RE = re.compile(r"^\s*key-direction\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_KEEPALIVE_RE = re.compile(r"^\s*keepalive\s+(\d+)\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_PING_RE = re.compile(r"^\s*ping\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_PING_RESTART_RE = re.compile(r"^\s*ping-restart\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_RENEG_SEC_RE = re.compile(r"^\s*reneg-sec\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def _keepalive_fields(config_text: str) -> dict:
    """Map OpenVPN keepalive directives to sing-box openvpn-client fields.

    keepalive <interval> <timeout> == ping <interval> + ping-restart
    <timeout>. Values are clamped to sane ranges; unparsable values are
    ignored. Defaults (10s/60s, the common keepalive 10 60) keep idle NAT
    mappings alive when the profile sets nothing: without them an idle
    tunnel is reaped after ~10min while TCP 443 still answers, which looks
    exactly like "verified IP but cannot connect".
    """
    fields: dict = {}
    try:
        ka = _KEEPALIVE_RE.search(config_text)
        if ka:
            iv, to = int(ka.group(1)), int(ka.group(2))
            if 1 <= iv <= 3600:
                fields["ping_interval"] = f"{iv}s"
            if 1 <= to <= 86400:
                fields["ping_restart"] = f"{to}s"
        else:
            pm = _PING_RE.search(config_text)
            if pm and 1 <= int(pm.group(1)) <= 3600:
                fields["ping_interval"] = f"{int(pm.group(1))}s"
            prm = _PING_RESTART_RE.search(config_text)
            if prm and 1 <= int(prm.group(1)) <= 86400:
                fields["ping_restart"] = f"{int(prm.group(1))}s"
        rs = _RENEG_SEC_RE.search(config_text)
        if rs:
            v = int(rs.group(1))
            if v == 0:
                fields["renegotiate_disabled"] = True
            elif 1 <= v <= 30 * 86400:
                fields["renegotiate_interval"] = f"{v}s"
    except (ValueError, AttributeError):
        pass
    if "ping_interval" not in fields:
        fields["ping_interval"] = "10s"
    if "ping_restart" not in fields:
        fields["ping_restart"] = "60s"
    return fields


def _is_tcp_proto(proto: str) -> bool:
    return proto.lower().startswith("tcp")


def _all_tcp_remotes(config_text: str) -> list[tuple[str, int]]:
    """Return every TCP remote in order (explicit proto first, then global)."""
    global_protos = [m.group(1) for m in _PROTO_RE.finditer(config_text)]
    global_tcp = any(_is_tcp_proto(p) for p in global_protos)
    remotes = [(m.group(1), int(m.group(2)), (m.group(3) or "")) for m in _REMOTE_RE.finditer(config_text)]
    if not remotes:
        raise ValueError("no remote directive found")
    explicit = [(host, port) for host, port, proto in remotes
                if proto and _is_tcp_proto(proto)]
    if explicit:
        return explicit
    if global_tcp:
        fallback = [(host, port) for host, port, proto in remotes
                    if not proto or not proto.lower().startswith("udp")]
        if fallback:
            return fallback
    raise ValueError("no TCP remote found (only UDP available)")


def _pick_tcp_remote(config_text: str) -> tuple[str, int]:
    return _all_tcp_remotes(config_text)[0]


def primary_server(endpoint: dict) -> tuple[str, int]:
    """First reachable address of an endpoint (singular or servers[0])."""
    if "server" in endpoint:
        return endpoint["server"], endpoint["server_port"]
    first = endpoint["servers"][0]
    return first["server"], first["server_port"]


def ovpn_to_endpoint(
    config_text: str,
    tag: str,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> dict:
    """Convert one OpenVPN client config (TCP) to a sing-box openvpn-client endpoint."""
    if not config_text or not config_text.strip():
        raise ValueError("empty openvpn config")
    tcp_remotes = _all_tcp_remotes(config_text)

    blocks: dict[str, str] = {}
    for m in _BLOCK_RE.finditer(config_text):
        blocks[m.group(1).lower()] = m.group(2).strip()
    if "ca" not in blocks or not blocks["ca"]:
        raise ValueError("missing <ca> block")

    auth_m = _AUTH_RE.search(config_text)
    auth = auth_m.group(1).upper() if auth_m else DEFAULT_AUTH
    cipher_m = _CIPHER_RE.search(config_text)
    data_ciphers = list(DEFAULT_DATA_CIPHERS)
    if cipher_m:
        cipher = cipher_m.group(1)
        data_ciphers = [cipher] + [c for c in data_ciphers if c.lower() != cipher.lower()]

    if blocks.get("cert") and not blocks.get("key"):
        raise ValueError("client <cert> without <key> (must be both or neither)")
    if blocks.get("key") and not blocks.get("cert"):
        raise ValueError("client <key> without <cert> (must be both or neither)")
    tls: dict = {
        "certificate": blocks["ca"],
        "certificate_profile": "legacy",
    }
    if blocks.get("cert"):
        tls["client_certificate"] = blocks["cert"]
    if blocks.get("key"):
        tls["client_key"] = blocks["key"]
    # sing-box control_wrap replaces OpenVPN tls-auth/tls-crypt inline keys.
    # Dropping them silently breaks the handshake, so map them explicitly.
    # direction is a "server"/"client" STRING (OpenVPN key-direction 0/1)
    # and only exists for tls_auth; tls_crypt never carries one.
    if blocks.get("tls-crypt"):
        control_wrap: dict = {"type": "tls_crypt", "key": blocks["tls-crypt"]}
    elif blocks.get("tls-auth"):
        control_wrap = {"type": "tls_auth", "key": blocks["tls-auth"]}
        direction_m = _KEY_DIRECTION_RE.search(config_text)
        if direction_m:
            direction = {"0": "server", "1": "client"}.get(
                direction_m.group(1))
            if direction is not None:
                control_wrap["direction"] = direction
    else:
        control_wrap = {}
    if control_wrap:
        tls["control_wrap"] = control_wrap

    return {
        "type": "openvpn-client",
        "tag": tag,
        **_server_fields(tcp_remotes),
        "network": "tcp",
        "username": username,
        "password": password,
        "tls": tls,
        "data_ciphers": data_ciphers,
        "data_ciphers_fallback": data_ciphers[0],
        "auth": auth,
        **_keepalive_fields(config_text),
        **({"remote_random": True} if _REMOTE_RANDOM_RE.search(config_text) else {}),
        "system": False,
        "redirect_gateway": True,
    }


def _server_fields(tcp_remotes: list[tuple[str, int]]) -> dict:
    """Singular server/server_port for one remote, servers[] otherwise.

    sing-box requires exactly one of server / servers (they conflict),
    so multi-remote configs move to servers[] for in-order failover.
    """
    if len(tcp_remotes) == 1:
        host, port = tcp_remotes[0]
        return {"server": host, "server_port": port}
    return {"servers": [
        {"server": host, "server_port": port, "network": "tcp"}
        for host, port in tcp_remotes
    ]}


def probe_tcp_latency(host: str, port: int, timeout: int = 5) -> int:
    """Measure TCP handshake latency in ms; return 0 when unreachable.

    This is a real-connection pre-filter: VPNGate advertises Speed values
    that say nothing about whether the node accepts connections right now.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = None
    start = time.monotonic()
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return max(1, int((time.monotonic() - start) * 1000))
    except OSError:
        return 0
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("eof")
        data += chunk
    return data


def _socks5_get_latency_ms(proxy_host: str, proxy_port: int,
                           target_host: str = "opencode.ai",
                           target_port: int = 443,
                           path: str = "/",
                           timeout: float = 20,
                           cafile: str | None = None,
                           expected_codes: tuple[int, ...] = (200, 204, 301, 302)) -> int | None:
    """One HTTPS GET through a SOCKS5 proxy; ms on HTTP 204, else None.

    The GET goes through a real TLS handshake (SNI=target_host), so the
    measured latency matches what curl reports (TCP+TLS+HTTP).
    """
    family = socket.AF_INET6 if ":" in proxy_host else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return None
        try:
            addr = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
        except OSError:
            encoded = target_host.encode("idna")
            if len(encoded) > 255:
                return None
            request = (b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
                       + target_port.to_bytes(2, "big"))
        sock.sendall(request)
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return None
        try:
            context = (ssl.create_default_context(cafile=cafile) if cafile
                       else ssl.create_default_context())
            sock = context.wrap_socket(sock, server_hostname=target_host)
        except OSError:
            return None
        start = time.monotonic()
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            head += chunk
            if len(head) > 8192:
                return None
        try:
            code = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None
        if code not in expected_codes:
            return None
        return max(1, int((time.monotonic() - start) * 1000))
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _socks5_get_text(proxy_host: str, proxy_port: int,
                     target_host: str = "api.ipify.org",
                     target_port: int = 443,
                     path: str = "/?format=text",
                     timeout: float = 20) -> tuple | None:
    """One HTTPS GET through a SOCKS5 proxy; (code, body, ms) or None.

    Same handshake as _socks5_get_latency_ms, but returns the response
    body so callers can read small text APIs (e.g. api.ipify.org).
    """
    family = socket.AF_INET6 if ":" in proxy_host else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((proxy_host, proxy_port))
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return None
        try:
            addr = socket.inet_aton(target_host)
            request = b"\x05\x01\x00\x01" + addr + target_port.to_bytes(2, "big")
        except OSError:
            encoded = target_host.encode("idna")
            if len(encoded) > 255:
                return None
            request = (b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
                       + target_port.to_bytes(2, "big"))
        sock.sendall(request)
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            return None
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return None
        try:
            sock = ssl.create_default_context().wrap_socket(
                sock, server_hostname=target_host)
        except OSError:
            return None
        start = time.monotonic()
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        raw = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError:
                return None
            if not chunk:
                break
            raw += chunk
            if len(raw) > 65536:
                return None
        ms = max(1, int((time.monotonic() - start) * 1000))
        head, _, body = raw.partition(b"\r\n\r\n")
        try:
            code = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return None
        return (code, body.strip(), ms)
    except (OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _looks_like_ipv4(text: bytes) -> bool:
    try:
        socket.inet_aton(text.decode("ascii").strip())
    except (OSError, ValueError, UnicodeError):
        return False
    return text.count(b".") == 3


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _log_dial_failure(endpoint: dict, err_path: str) -> None:
    """Print the sing-box stderr tail so CI logs show why a dial failed."""
    try:
        with open(err_path, "rb") as handle:
            tail = handle.read()[-2048:].decode("utf-8", errors="replace").strip()
    except OSError:
        tail = ""
    detail = f"\nsing-box log tail:\n{tail}" if tail else " (no sing-box log captured)"
    print(f"dial failed for {endpoint.get('server')}:{endpoint.get('server_port')}{detail}",
          flush=True)


def _dial_probe_config(endpoint: dict, port: int) -> dict:
    """Throwaway single-endpoint config with the route pinned to the probe tag.

    The serving config defaults route.final to the "auto" urltest group
    (VPN-only) -- right for serving, wrong for measuring: urltest would route
    around the endpoint under test. Probing must exit only
    through the endpoint, like the proven manual dial path.
    """
    probe_endpoint = dict(endpoint)
    probe_endpoint["tag"] = "dial-probe"
    config = build_singbox_config([probe_endpoint], mixed_listen="127.0.0.1",
                                  mixed_port=port)
    config["route"]["final"] = "dial-probe"
    return config


def measure_real_latency(endpoint: dict, singbox_bin: str = "sing-box",
                         timeout: int = 20, poll_interval: int = 2,
                         target_host: str = "opencode.ai",
                         target_port: int = 443,
                         path: str = "/",
                         expected_codes: tuple[int, ...] = (200, 204, 301, 302)) -> int | None:
    """Dial one endpoint with a throwaway sing-box; verify HTTP 200/reachable ms or None."""
    port = _free_port()
    config = _dial_probe_config(endpoint, port)
    tmpdir = tempfile.TemporaryDirectory()
    _DIAL_GATE.acquire()
    try:
        cfg_path = str(Path(tmpdir.name) / "dial.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        err_path = str(Path(tmpdir.name) / "dial-stderr.log")
        try:
            err_handle = open(err_path, "ab")
        except OSError:
            err_handle = None
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=err_handle or subprocess.DEVNULL)
        except OSError:
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            print(f"dial failed for {endpoint.get('server')}:{endpoint.get('server_port')}: "
                  f"cannot start {singbox_bin}", flush=True)
            return None
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                first = _socks5_get_latency_ms(
                    "127.0.0.1", port, target_host, target_port, path,
                    expected_codes=expected_codes,
                    timeout=min(10, max(1, remaining)))
                if first is not None:
                    # The readiness probe already completed a full HTTPS GET
                    # through the tunnel; return it directly. A second timed
                    # GET would only re-race a shrinking deadline (e.g. a 2s
                    # budget when readiness arrives at 118s of 120s).
                    return first
                if proc.poll() is not None:
                    break  # sing-box died; the tunnel will never come up
                time.sleep(poll_interval)
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _log_dial_failure(endpoint, err_path)
            return None
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
    finally:
        _DIAL_GATE.release()
        tmpdir.cleanup()


def measure_exit_ip(endpoint: dict, singbox_bin: str = "sing-box",
                    timeout: int = 20, poll_interval: int = 2) -> tuple:
    """Exit IP through one endpoint: (ip, ms) or (None, None).

    Same throwaway sing-box dial as measure_real_latency, but fetches
    api.ipify.org so the caller learns the actual exit IP, not just
    the end-to-end latency.
    """
    port = _free_port()
    config = _dial_probe_config(endpoint, port)
    tmpdir = tempfile.TemporaryDirectory()
    _DIAL_GATE.acquire()
    try:
        cfg_path = str(Path(tmpdir.name) / "dial.json")
        Path(cfg_path).write_text(json.dumps(config), encoding="utf-8")
        err_path = str(Path(tmpdir.name) / "dial-stderr.log")
        try:
            err_handle = open(err_path, "ab")
        except OSError:
            err_handle = None
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=err_handle or subprocess.DEVNULL)
        except OSError:
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            print(f"verify failed for {endpoint.get('server')}:{endpoint.get('server_port')}: "
                  f"cannot start {singbox_bin}", flush=True)
            return (None, None)
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                fetched = _socks5_get_text(
                    "127.0.0.1", port, "api.ipify.org", 443, "/?format=text",
                    timeout=min(10, max(1, remaining)))
                if (fetched is not None and fetched[0] == 200
                        and _looks_like_ipv4(fetched[1])):
                    return (fetched[1].decode("ascii").strip(), fetched[2])
                if proc.poll() is not None:
                    break  # sing-box died; the tunnel will never come up
                time.sleep(poll_interval)
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
            _log_dial_failure(endpoint, err_path)
            return (None, None)
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if err_handle is not None:
                try:
                    err_handle.close()
                except OSError:
                    pass
    finally:
        _DIAL_GATE.release()
        tmpdir.cleanup()


def _safe_dial(dial_fn, node: dict) -> int | None:
    try:
        result = dial_fn(node)
    except Exception:
        return None
    return result if isinstance(result, int) and result > 0 else None


def _iter_tcp_candidates(csv_text, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD):
    """Yield (speed, country, country_short, untagged-endpoint) for TCP rows."""
    lines = [ln for ln in csv_text.splitlines() if ln and not ln.startswith("*")]
    if not lines:
        raise ValueError("empty snapshot")
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "OpenVPN_ConfigData_Base64" not in reader.fieldnames:
        raise ValueError("snapshot columns are incomplete")

    found = False
    for row in reader:
        encoded = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not encoded:
            continue
        try:
            config_text = base64.b64decode(encoded, validate=True).decode("utf-8")
            endpoint = ovpn_to_endpoint(config_text, tag="", username=username, password=password)
        except (ValueError, UnicodeError):
            continue  # UDP-only / broken / unsafe rows are skipped
        try:
            speed = int((row.get("Speed") or "0").strip() or "0")
        except ValueError:
            speed = 0
        found = True
        yield (speed, (row.get("CountryLong") or "").strip(),
               (row.get("CountryShort") or "").strip().upper(), endpoint)
    if not found:
        raise ValueError("snapshot contains no TCP-convertible nodes")


def snapshot_to_nodes(
    csv_text: str,
    limit: int | None = 0,
    probe: bool = True,
    probe_fn=None,
    probe_timeout: int = 5,
    probe_workers: int = 30,
    probe_pool: int = 60,
    real_topk: int = 0,
    dial_fn=None,
    dial_workers: int = 20,
    dial_timeout: int = 15,
    target_host: str = "opencode.ai",
    target_port: int = 443,
    target_path: str = "/",
    only_verified: bool = True,
    singbox_bin: str = "sing-box",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> list[dict]:
    """Parse a snapshot into node dicts with country + measured latency.

    Nodes are real-connection filtered (TCP handshake must succeed) and
    sorted by measured latency. With probe=False falls back to Speed ranking
    with latency_ms=None. limit=0/None means all nodes.

    With real_topk>0 the top-K handshake winners are additionally dialed
    through a real tunnel and re-ranked: measured nodes first by real
    end-to-end latency, the rest by handshake latency. Dial failures are
    refilled from the next handshake-ranked nodes until real_topk measured
    or the pool is exhausted; persistent failures stay unmeasured (None)
    and sort last. Returns [] when nothing is reachable (caller decides
    failure).
    """
    if probe_pool is not None and probe_pool < 0:
        raise ValueError(f"probe_pool must be >= 0, got {probe_pool}")
    if limit is not None and limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")
    candidates = list(_iter_tcp_candidates(csv_text, username, password))
    check = probe_fn if probe_fn is not None else (
        lambda host, port: probe_tcp_latency(host, port, probe_timeout))

    def _node(speed, country, country_short, endpoint, latency_ms):
        host, port = primary_server(endpoint)
        return {"server": host, "server_port": port,
                "country": country, "country_short": country_short,
                "speed": speed, "latency_ms": latency_ms, "real_latency_ms": None,
                "endpoint": endpoint}

    if not probe:
        ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
        nodes = [_node(speed, country, short, ep, None)
                 for speed, country, short, ep in ranked]
    else:
        # Speed says nothing about reachability, so probe Speed-ranked
        # chunks until one yields survivors instead of giving up after
        # the first probe_pool rows.
        ranked = sorted(candidates, key=lambda item: item[0], reverse=True)
        step = probe_pool if probe_pool else len(ranked) or 1
        nodes = []
        for start in range(0, len(ranked), step):
            chunk = ranked[start:start + step]
            latencies: dict[int, int] = {}
            with ThreadPoolExecutor(max_workers=probe_workers) as executor:
                future_map = {executor.submit(
                    check, *primary_server(ep)): index
                    for index, (_, _, _, ep) in enumerate(chunk)}
                for future in future_map:
                    try:
                        latencies[future_map[future]] = future.result()
                    except Exception:
                        latencies[future_map[future]] = 0

            alive = [(latencies[i], speed, country, short, ep)
                     for i, (speed, country, short, ep) in enumerate(chunk)
                     if (latencies.get(i) or 0) > 0]
            alive.sort(key=lambda item: item[0])
            nodes = [_node(speed, country, short, ep, latency)
                     for latency, speed, country, short, ep in alive]
            if nodes:
                break

    if real_topk and real_topk > 0 and nodes:
        dial = dial_fn if dial_fn is not None else (
            lambda node: measure_real_latency(node["endpoint"], singbox_bin, dial_timeout,
                                             target_host=target_host, target_port=target_port, path=target_path))
        target = min(real_topk, len(nodes))
        with ThreadPoolExecutor(max_workers=dial_workers) as executor:
            idx = 0
            measured = 0
            while measured < target and idx < len(nodes):
                batch = nodes[idx:idx + max(1, target - measured)]
                idx += len(batch)
                future_map = {executor.submit(_safe_dial, dial, node): node
                              for node in batch}
                for future in future_map:
                    future_map[future]["real_latency_ms"] = future.result()
                measured = sum(1 for n in nodes[:idx]
                               if n.get("real_latency_ms") is not None)
        if only_verified:
            verified = [n for n in nodes if n.get("real_latency_ms") is not None]
            if verified:
                nodes = verified
        nodes.sort(key=lambda n: (0, n["real_latency_ms"])
                   if n["real_latency_ms"] is not None
                   else (1, n["latency_ms"] if n["latency_ms"] is not None else 10 ** 9))

    if limit:
        nodes = nodes[:limit]
    return nodes


def nodes_to_endpoints(nodes: list[dict], tag_prefix: str = "vpngate") -> list[dict]:
    """Assign tags and return clean sing-box endpoint dicts (no metadata keys).

    Endpoints that already carry a tag (stable refresh mapping) keep it;
    only untagged endpoints take the next free ``tag_prefix-N`` slot.
    """
    used = {str(n.get("endpoint", {}).get("tag") or "")
            for n in nodes} - {""}
    next_index = 0
    endpoints = []
    for node in nodes:
        endpoint = dict(node["endpoint"])
        if not endpoint.get("tag"):
            while f"{tag_prefix}-{next_index}" in used:
                next_index += 1
            endpoint["tag"] = f"{tag_prefix}-{next_index}"
            used.add(endpoint["tag"])
            next_index += 1
        node["endpoint"] = endpoint
        endpoints.append(endpoint)
    return endpoints


def snapshot_to_endpoints(
    csv_text: str,
    limit: int | None = 0,
    tag_prefix: str = "vpngate",
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    probe: bool = True,
    probe_fn=None,
    probe_timeout: int = 5,
    probe_workers: int = 30,
    probe_pool: int = 60,
    real_topk: int = 0,
    dial_fn=None,
    dial_workers: int = 20,
    dial_timeout: int = 15,
    target_host: str = "opencode.ai",
    target_port: int = 443,
    target_path: str = "/",
    only_verified: bool = True,
    singbox_bin: str = "sing-box",
) -> list[dict]:
    """Parse a VPNGate CSV snapshot into tagged sing-box endpoints.

    Prefers nodes with a working TCP handshake, ranked by measured latency.
    With real_topk>0 the top-K are re-ranked by real tunnel latency.
    limit=0/None means all nodes.
    """
    nodes = snapshot_to_nodes(
        csv_text, limit=limit, probe=probe, probe_fn=probe_fn,
        probe_timeout=probe_timeout, probe_workers=probe_workers,
        probe_pool=probe_pool, real_topk=real_topk, dial_fn=dial_fn,
        dial_workers=dial_workers, dial_timeout=dial_timeout,
        target_host=target_host, target_port=target_port,
        target_path=target_path, only_verified=only_verified,
        singbox_bin=singbox_bin, username=username, password=password)
    if not nodes:
        raise ValueError("snapshot contains no reachable nodes")
    return nodes_to_endpoints(nodes, tag_prefix)


def build_singbox_config(
    endpoints: list[dict],
    mixed_listen: str | None = None,
    mixed_port: int | None = None,
    mixed_users: list[tuple[str, str]] | None = None,
    final: str = "auto",
    preferred: str | None = None,
    backup: str | None = None,
    vless_uuid: str | None = None,
    vless_direct_port: int = 8080,
    vless_direct_path: str = "/ws-node",
    vless_chain_port: int = 8082,
    vless_chain_path: str = "/ws-chain",
) -> dict:
    """Wrap endpoints in a minimal checkable sing-box config.

    route.final defaults to the "auto" urltest group so traffic fails over
    across healthy nodes automatically; pass an endpoint tag to pin one.
    The urltest group is VPN-only (fail-closed): "direct" must NOT be in it
    because a local direct outlet always wins urltest on speed and would
    silently route all serving traffic around the VPN. "direct" stays in the
    manual "proxy" selector as an explicit user-chosen fallback.
    The urltest re-picks every 15s (tolerance 150ms) so a dead tunnel fails
    over within seconds instead of minutes.

    When vless_uuid is set, two VLESS+WS inbounds are added for Cloudflare
    Tunnel use: "vless-direct" (Railway-local exit via "direct") and
    "vless-chain" (VPNGate exit via "auto", or via the "chain" selector
    when preferred). Route rules split by inbound tag, so the
    two paths never mix. Requires the mixed inbound (the $PORT mux target).

    When preferred names one of the endpoint tags, a "chain" selector
    ([preferred, "auto"]) becomes route.final instead of the bare tag, so a
    pinned node keeps hot-standby failover: preferred first, urltest group
    the instant it goes unhealthy. No serving config ever pins route.final
    to a single endpoint. Pass backup (a second endpoint tag, distinct from
    preferred) to insert it between preferred and "auto": the chain then
    serves best first, second as the guaranteed backup, urltest last.
    """
    tags = [ep["tag"] for ep in endpoints]
    if preferred is not None and preferred not in tags:
        preferred = None
    if backup is not None and (backup not in tags or backup == preferred):
        backup = None
    route_final = "chain" if preferred else final
    config: dict = {
        "log": {"level": "info"},
        "endpoints": endpoints,
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": tags + ["direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": tags,
             "interval": "15s", "tolerance": 150},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": route_final, "auto_detect_interface": True},
    }
    if preferred:
        config["outbounds"].append(
            {"type": "selector", "tag": "chain",
             "outbounds": ([preferred] + ([backup] if backup else [])
                           + ["auto"])})
    if mixed_listen is not None and mixed_port is not None:
        inbound: dict = {"type": "mixed", "tag": "mixed-in",
                         "listen": mixed_listen, "listen_port": mixed_port}
        if mixed_users:
            inbound["users"] = [{"username": user, "password": password}
                                for user, password in mixed_users]
        config["inbounds"] = [inbound]
    if vless_uuid is not None:
        if mixed_listen is None or mixed_port is None:
            raise ValueError("vless inbounds need the mixed inbound ($PORT mux target)")
        config.setdefault("inbounds", []).extend([
            {"type": "vless", "tag": "vless-direct",
             "listen": "0.0.0.0", "listen_port": vless_direct_port,
             "users": [{"uuid": vless_uuid}],
             "transport": {"type": "ws", "path": vless_direct_path}},
            {"type": "vless", "tag": "vless-chain",
             "listen": "0.0.0.0", "listen_port": vless_chain_port,
             "users": [{"uuid": vless_uuid}],
             "transport": {"type": "ws", "path": vless_chain_path}},
        ])
        # No loopback hop: vless-chain routes straight into the urltest group
        # (or the "chain" selector when pinned), which is exactly where the
        # old chain-socks -> mixed -> route.final path ended up. One less
        # hop, and a dead mixed inbound no longer kills both VLESS paths.
        chain_target = "chain" if preferred else "auto"
        config["route"]["rules"] = [
            {"inbound": "vless-direct", "outbound": "direct"},
            {"inbound": "vless-chain", "outbound": chain_target},
        ]
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert VPNGate .ovpn (TCP) to sing-box config")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="input .ovpn file")
    group.add_argument("--csv", help="input VPNGate snapshot CSV file")
    parser.add_argument("--output", required=True, help="output sing-box JSON file")
    parser.add_argument("--tag", default="vpngate-0", help="endpoint tag (--input) or prefix (--csv)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max endpoints for --csv mode, 0 = all")
    parser.add_argument("--real-topk", type=int, default=0,
                        help="re-rank top-K by real tunnel latency (0 = off)")
    parser.add_argument("--dial-workers", type=int, default=20,
                        help="concurrent sing-box dial workers for 200 checks")
    parser.add_argument("--no-probe", action="store_true",
                        help="skip TCP handshake probing, rank by Speed instead")
    parser.add_argument("--mixed", default=None, help="optional mixed inbound HOST:PORT for dial tests")
    parser.add_argument("--target-host", default="opencode.ai", help="target host for 200 dial check")
    parser.add_argument("--target-path", default="/", help="target path for 200 dial check")
    parser.add_argument("--target-port", type=int, default=443, help="target port for 200 dial check")
    parser.add_argument("--only-verified", action="store_true", default=True,
                        help="only output nodes that pass real 200 dial check")
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    args = parser.parse_args(argv)

    mixed_listen: str | None = None
    mixed_port: int | None = None
    if args.mixed:
        mixed_listen, _, mixed_port_str = args.mixed.rpartition(":")
        mixed_port = int(mixed_port_str)

    if args.csv:
        csv_text = Path(args.csv).read_text(encoding="utf-8")
        endpoints = snapshot_to_endpoints(
            csv_text, limit=args.limit, tag_prefix=args.tag,
            username=args.username, password=args.password,
            probe=not args.no_probe, real_topk=args.real_topk,
            dial_workers=args.dial_workers,
            target_host=args.target_host, target_port=args.target_port,
            target_path=args.target_path, only_verified=args.only_verified,
        )
        Path(args.output).write_text(
            json.dumps(build_singbox_config(endpoints, mixed_listen, mixed_port), indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.output} with {len(endpoints)} endpoints")
        return 0

    config_text = Path(args.input).read_text(encoding="utf-8")
    endpoint = ovpn_to_endpoint(config_text, tag=args.tag, username=args.username, password=args.password)
    Path(args.output).write_text(
        json.dumps(build_singbox_config([endpoint], mixed_listen, mixed_port), indent=2) + "\n",
        encoding="utf-8",
    )
    host, port = primary_server(endpoint)
    print(f"wrote {args.output} with 1 endpoint ({host}:{port})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
