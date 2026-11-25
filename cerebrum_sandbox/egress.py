"""Egress proxy (own implementation) for `allowlist` network profiles.

Enforcement is at the network layer: allowlist sandboxes sit on an `--internal` Docker network
that cannot route anywhere (no external IPs, no external DNS). The only reachable endpoint is
this proxy, listening on that network's gateway address. The proxy then:
  * identifies the sandbox by its source IP (registered by the controller when it starts),
  * allows CONNECT (HTTPS, end-to-end TLS, no interception) and plain-HTTP requests only to
    the sandbox's exact allowlisted hostnames and ports,
  * resolves names itself and refuses private / loopback / link-local / metadata addresses
    (no pivoting to the cloud metadata service or internal hosts via an allowed name),
  * logs every connection attempt (allowed or denied, bytes, duration) to `netlog`.
It can chain through an upstream HTTP proxy (SANDBOX_EGRESS_UPSTREAM_PROXY) for hosts that
themselves only have proxied egress.
"""
import asyncio
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

MAX_HEADER = 64 * 1024


@dataclass
class Policy:
    sandbox_id: str
    domains: set[str]
    ports: set[int]
    log: bool = True


@dataclass
class Stats:
    allowed: int = 0
    denied: int = 0
    by_sandbox: dict = field(default_factory=dict)


def _default_resolver(host: str, port: int) -> list[str]:
    return list({i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


class EgressProxy:
    def __init__(self, store, bind_host: str, port: int = 3128, *, upstream: str | None = None,
                 resolver=None, allow_private: bool = False, connect_timeout: float = 15):
        self.store, self.bind_host, self.port = store, bind_host, port
        self.upstream = urlparse(upstream) if upstream else None
        self.resolver = resolver or _default_resolver
        self.allow_private, self.connect_timeout = allow_private, connect_timeout
        self.policies: dict[str, Policy] = {}
        self.stats = Stats()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server = None
        self._ready = threading.Event()

    # ---- policy table (called by the controller) ------------------------------------------
    def set_policy(self, ip: str, sandbox_id: str, domains, ports, log: bool = True) -> None:
        self.policies[ip] = Policy(sandbox_id, set(domains), set(ports), log)

    def remove_sandbox(self, sandbox_id: str) -> None:
        for ip in [ip for ip, p in self.policies.items() if p.sandbox_id == sandbox_id]:
            del self.policies[ip]

    # ---- lifecycle ------------------------------------------------------------------------
    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="egress-proxy").start()
        if not self._ready.wait(10):
            raise RuntimeError("egress proxy did not start")

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(
            asyncio.start_server(self._handle, self.bind_host, self.port, limit=MAX_HEADER))
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    def stop(self) -> None:
        if self._loop and self._server:
            async def _close():
                self._server.close()
                await self._server.wait_closed()
            asyncio.run_coroutine_threadsafe(_close(), self._loop).result(5)
            self._loop.call_soon_threadsafe(self._loop.stop)

    # ---- decision ---------------------------------------------------------------------------
    def _decide(self, src: str, host: str, port: int) -> tuple[Policy | None, str | None, list[str]]:
        pol = self.policies.get(src)
        if pol is None:
            return None, "unknown source (not a registered allowlist sandbox)", []
        host = host.lower().rstrip(".")
        if host not in pol.domains:
            return pol, f"host '{host}' not in allowlist", []
        if port not in pol.ports:
            return pol, f"port {port} not allowed", []
        if self.upstream:
            return pol, None, []  # the upstream proxy resolves; it is the trusted egress
        try:
            addrs = self.resolver(host, port)
        except OSError:
            return pol, "DNS resolution failed", []
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if not self.allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local or
                                           ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                return pol, f"'{host}' resolves to a non-public address {a}", []
        return pol, None, addrs

    def _log(self, pol: Policy | None, src: str, method: str, host: str, port: int, decision: str,
             reason: str | None, up: int = 0, down: int = 0, dur: float = 0.0) -> None:
        sid = pol.sandbox_id if pol else None
        if decision == "allowed":
            self.stats.allowed += 1
        else:
            self.stats.denied += 1
        if sid:
            d = self.stats.by_sandbox.setdefault(sid, {"allowed": 0, "denied": 0})
            d[decision] += 1
        if pol is None or pol.log or decision == "denied":
            try:
                self.store.x("INSERT INTO netlog(ts,sandbox_id,src,method,host,port,decision,reason,bytes_up,"
                             "bytes_down,duration_s) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                             (time.time(), sid, src, method, host[:255], port, decision, reason, up, down,
                              round(dur, 3)))
            except Exception:  # noqa: BLE001  logging must never break traffic handling
                pass

    # ---- connection handling ----------------------------------------------------------------
    async def _open(self, host: str, port: int, addrs: list[str]):
        if self.upstream:
            r, w = await asyncio.wait_for(asyncio.open_connection(self.upstream.hostname, self.upstream.port or 80),
                                          self.connect_timeout)
            w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            await w.drain()
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), self.connect_timeout)
            if b" 200" not in head.split(b"\r\n", 1)[0]:
                w.close()
                raise OSError("upstream proxy refused: " + head.split(b"\r\n", 1)[0].decode(errors="replace"))
            return r, w
        last = None
        for a in addrs:  # connect to the vetted address, never re-resolve
            try:
                return await asyncio.wait_for(asyncio.open_connection(a, port), self.connect_timeout)
            except OSError as e:
                last = e
        raise last or OSError("no address")

    @staticmethod
    async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter, counter: list) -> None:
        try:
            while chunk := await r.read(65536):
                counter[0] += len(chunk)
                w.write(chunk)
                await w.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        src = cw.get_extra_info("peername")[0]
        t0 = time.monotonic()
        try:
            head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 30)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
            cw.close()
            return
        first, _, rest = head.partition(b"\r\n")
        try:
            method, target, _ver = first.decode("latin-1").split(" ", 2)
        except ValueError:
            await self._reply(cw, 400, "bad request line")
            return
        if method == "CONNECT":
            host, _, p = target.rpartition(":")
            host = host.strip("[]")
            port = int(p) if p.isdigit() else 443
            forward = None
        else:
            u = urlparse(target)
            if u.scheme != "http" or not u.hostname:
                await self._reply(cw, 400, "only absolute http:// URLs or CONNECT are supported")
                return
            host, port = u.hostname, u.port or 80
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            # drop hop-by-hop/proxy headers and any client Host header: the vetted target IS the Host
            # (prevents fronting another site behind an allowlisted shared host)
            headers = [h for h in rest.split(b"\r\n") if h and not h.lower().startswith(
                (b"proxy-", b"connection:", b"keep-alive:", b"host:"))]
            host_hdr = host if port == 80 else f"{host}:{port}"
            forward = (f"{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\n".encode() + b"\r\n".join(headers) +
                       b"\r\nConnection: close\r\n\r\n")
        pol, why, addrs = self._decide(src, host, port)
        if why:
            self._log(pol, src, method, host, port, "denied", why)
            await self._reply(cw, 403, f"blocked by Cerebrum.sandbox egress policy: {why}")
            return
        try:
            ur, uw = await self._open(host, port, addrs)
        except (OSError, asyncio.TimeoutError) as e:
            self._log(pol, src, method, host, port, "denied", f"connect failed: {type(e).__name__}")
            await self._reply(cw, 502, "upstream connection failed")
            return
        up, down = [0], [0]
        if forward is None:
            cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await cw.drain()
        else:
            uw.write(forward)
            up[0] += len(forward)
            await uw.drain()
        await asyncio.gather(self._pipe(cr, uw, up), self._pipe(ur, cw, down))
        self._log(pol, src, method, host, port, "allowed", None, up[0], down[0], time.monotonic() - t0)

    @staticmethod
    async def _reply(w: asyncio.StreamWriter, code: int, msg: str) -> None:
        body = (msg + "\n").encode()
        reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(code, "Error")
        try:
            w.write(f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + body)
            await w.drain()
        except ConnectionError:
            pass
        finally:
            w.close()


def ensure_network(docker_bin: str, name: str, subnet: str) -> str:
    """Create the internal (non-routable) Docker network if needed; return its gateway IP."""
    import json
    import subprocess
    r = subprocess.run([docker_bin, "network", "inspect", name], capture_output=True, text=True)
    if r.returncode != 0:
        c = subprocess.run([docker_bin, "network", "create", "--internal", "--subnet", subnet,
                            "--label", "cerebrum.sandbox=1", name], capture_output=True, text=True)
        if c.returncode != 0:
            raise RuntimeError(f"cannot create egress network: {c.stderr.strip()[:200]}")
        r = subprocess.run([docker_bin, "network", "inspect", name], capture_output=True, text=True)
    info = json.loads(r.stdout)[0]
    if not info.get("Internal"):
        raise RuntimeError(f"network '{name}' exists but is not --internal; refusing to use it")
    return info["IPAM"]["Config"][0]["Gateway"]
