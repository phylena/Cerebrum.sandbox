"""Egress proxy against real local sockets (no Docker needed)."""
import asyncio
import socket
import threading
import time
import urllib.request

import pytest

from cerebrum_sandbox.egress import EgressProxy
from cerebrum_sandbox.store import Store


@pytest.fixture
def echo():
    """A TCP server that answers HTTP and echoes raw bytes after a magic line."""
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(16)
    seen = []

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = c.recv(65536); seen.append(data)
            if data.startswith(b"GET "):
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            else:
                c.sendall(b"echo:" + data)
            c.close()
    threading.Thread(target=loop, daemon=True).start()
    yield srv.getsockname()[1], seen
    srv.close()


@pytest.fixture
def proxy(tmp_path):
    names = {"allowed.test": ["127.0.0.1"], "other.test": ["127.0.0.1"], "meta.test": ["169.254.169.254"]}
    p = EgressProxy(Store(tmp_path), "127.0.0.1", 0, resolver=lambda h, port: names[h], allow_private=True)
    p.start()
    yield p
    p.stop()


def connect(proxy, target: str, payload: bytes = b"ping") -> bytes:
    s = socket.create_connection(("127.0.0.1", proxy.port), 5)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = s.recv(4096)
    if b" 200 " not in head.split(b"\r\n")[0] + b" ":
        s.close()
        return head
    s.sendall(payload)
    out = b""
    while chunk := s.recv(4096):
        out += chunk
    s.close()
    return head + out


def test_connect_allowed_tunnels_and_logs(proxy, echo):
    port, _ = echo
    proxy.set_policy("127.0.0.1", "sb1", ["allowed.test"], [port])
    out = connect(proxy, f"allowed.test:{port}", b"secret-tls-bytes")
    assert b"200 Connection established" in out and out.endswith(b"echo:secret-tls-bytes")
    time.sleep(0.2)
    row = proxy.store.q("SELECT * FROM netlog WHERE decision='allowed'")[0]
    assert row["sandbox_id"] == "sb1" and row["host"] == "allowed.test" and row["bytes_up"] == 16


@pytest.mark.parametrize("target,why", [("other.test:{p}", "not in allowlist"), ("allowed.test:1", "port 1"),
                                        ("ALLOWED.TEST.:{p}", None)])
def test_connect_denials(proxy, echo, target, why):
    port, _ = echo
    proxy.set_policy("127.0.0.1", "sb1", ["allowed.test"], [port])
    out = connect(proxy, target.format(p=port))
    if why is None:
        assert b"200" in out.split(b"\r\n")[0]          # case/trailing dot normalised, still exact match
    else:
        assert b"403" in out and why.encode() in out


def test_unknown_source_denied(proxy, echo):
    out = connect(proxy, f"allowed.test:{echo[0]}")
    assert b"403" in out and b"unknown source" in out


def test_metadata_address_blocked_even_if_name_allowed(tmp_path, echo):
    p = EgressProxy(Store(tmp_path), "127.0.0.1", 0, resolver=lambda h, port: ["169.254.169.254"])
    p.start()
    try:
        p.set_policy("127.0.0.1", "sb1", ["meta.test"], [80])
        out = connect(p, "meta.test:80")
        assert b"403" in out and b"non-public address" in out
        p.set_policy("127.0.0.1", "sb1", ["meta.test"], [80])
        p.resolver = lambda h, port: ["127.0.0.1"]
        assert b"non-public" in connect(p, "meta.test:80")   # loopback is also refused by default
    finally:
        p.stop()


def test_plain_http_forwarded_and_proxy_headers_stripped(proxy, echo):
    port, seen = echo
    proxy.set_policy("127.0.0.1", "sb1", ["allowed.test"], [port])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy.port}"}))
    req = urllib.request.Request(f"http://allowed.test:{port}/x?y=1", headers={"Proxy-Authorization": "Basic c2VjcmV0"})
    assert opener.open(req, timeout=5).read() == b"hello"
    assert seen[-1].startswith(b"GET /x?y=1 HTTP/1.1") and b"Proxy-Authorization" not in seen[-1]


def test_policy_removal(proxy, echo):
    proxy.set_policy("127.0.0.1", "sb1", ["allowed.test"], [echo[0]])
    proxy.remove_sandbox("sb1")
    assert b"unknown source" in connect(proxy, f"allowed.test:{echo[0]}")


def test_upstream_chaining(tmp_path, echo):
    """A fake upstream proxy accepts CONNECT and then echoes."""
    port, _ = echo
    up = socket.socket(); up.bind(("127.0.0.1", 0)); up.listen(4)
    got = []

    def serve():
        c, _ = up.accept()
        head = c.recv(4096); got.append(head)
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        c.sendall(b"echo:" + c.recv(4096)); c.close()
    threading.Thread(target=serve, daemon=True).start()
    p = EgressProxy(Store(tmp_path), "127.0.0.1", 0, upstream=f"http://127.0.0.1:{up.getsockname()[1]}")
    p.start()
    try:
        p.set_policy("127.0.0.1", "sb1", ["pypi.org"], [443])
        assert connect(p, "pypi.org:443", b"x").endswith(b"echo:x")
        assert got[0].startswith(b"CONNECT pypi.org:443 ")
        assert b"403" in connect(p, "evil.com:443")                    # still enforced before upstream
    finally:
        p.stop(); up.close()


def test_plain_http_host_header_is_forced_to_the_vetted_target(proxy, echo):
    port, seen = echo
    proxy.set_policy("127.0.0.1", "sb1", ["allowed.test"], [port])
    s = socket.create_connection(("127.0.0.1", proxy.port), 5)
    s.sendall(f"GET http://allowed.test:{port}/ HTTP/1.1\r\nHost: evil.example\r\n\r\n".encode())
    while s.recv(4096):
        pass
    s.close()
    req = seen[-1].decode()
    assert f"Host: allowed.test:{port}" in req and "evil.example" not in req
