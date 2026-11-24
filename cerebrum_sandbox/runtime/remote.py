"""Remote worker runtime: another node running this same service, driven through its public API.

This is the fleet layer (the role Sandstorm plays elsewhere) built on the one API we already
have, so adding workers needs no new protocol: the master calls the worker's /api/v1 with the
worker's operator key and the *same sandbox id*, so ids match on both sides. The worker applies
its own quotas, isolation floor and GPU allocation. Custom (non built-in) profiles must already
exist on the worker under the same name.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from .base import ExecResult, Runtime, RuntimeError_, SandboxSpec

_BLOCKED_HOSTS = {"metadata.google.internal", "instance-data", "metadata"}


def validate_worker_url(url: str) -> str:
    """Workers are registered by admins, but still never let the controller be pointed at
    cloud metadata endpoints or link-local addresses (SSRF / credential theft)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("worker url must be http(s)://host[:port] without credentials")
    host = u.hostname.lower()
    if host in _BLOCKED_HOSTS:
        raise ValueError("worker url points at a metadata service")
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)}
        except OSError:
            addrs = set()  # unresolvable now: it will simply fail to connect
    for a in addrs:
        if a.is_link_local or a.is_multicast or a.is_unspecified:
            raise ValueError("worker url resolves to a link-local/metadata address")
    return f"{u.scheme}://{u.netloc}"


class RemoteRuntime(Runtime):
    name = "remote"

    def __init__(self, http, key: str):
        """http: an httpx.Client-like object with base_url set to the worker."""
        self.http, self.headers = http, {"Authorization": f"Bearer {key}"}

    def _req(self, method: str, path: str, json=None, ok=(200, 201)) -> dict:
        try:
            r = self.http.request(method, path, headers=self.headers, json=json)
        except Exception as e:  # network errors of any httpx flavour
            raise RuntimeError_(f"worker unreachable: {type(e).__name__}") from e
        if r.status_code not in ok:
            try:
                detail = r.json().get("detail", "")
            except ValueError:
                detail = r.text[:200]
            raise RuntimeError_(f"worker returned {r.status_code}: {detail}")
        return r.json() if r.content else {}

    def create(self, spec: SandboxSpec) -> None:
        self._req("POST", "/api/v1/sandboxes", {
            "id": spec.sandbox_id, "profile": spec.profile.name, "env": spec.env,
            "isolation": spec.profile.isolation.value})

    def _state(self, sid: str) -> str:
        return self._req("GET", f"/api/v1/sandboxes/{sid}")["state"]

    def start(self, sid: str) -> None:
        if self._state(sid) != "running":  # remote create already started it
            self._req("POST", f"/api/v1/sandboxes/{sid}/start")

    def stop(self, sid: str) -> None:
        self._req("POST", f"/api/v1/sandboxes/{sid}/stop")

    def pause(self, sid: str) -> None:
        self._req("POST", f"/api/v1/sandboxes/{sid}/pause")

    def resume(self, sid: str) -> None:
        self._req("POST", f"/api/v1/sandboxes/{sid}/resume")

    def destroy(self, sid: str, *, delete_workspace: bool) -> None:
        try:
            self._req("DELETE", f"/api/v1/sandboxes/{sid}", ok=(200, 404))
        except RuntimeError_:
            raise

    def status(self, sid: str) -> str:
        try:
            state = self._state(sid)
        except RuntimeError_ as e:
            if "404" in str(e):
                return "missing"
            raise
        return {"running": "running", "paused": "paused", "stopped": "stopped"}.get(state, "missing")

    def logs(self, sid: str, tail: int = 200) -> str:
        return self._req("GET", f"/api/v1/sandboxes/{sid}/logs?tail={int(tail)}").get("logs", "")

    def health(self) -> dict:
        try:
            h = self._req("GET", "/health")
        except RuntimeError_ as e:
            return {"runtime": "remote", "ok": False, "detail": str(e)}
        return {"runtime": "remote", "ok": h.get("status") == "ok", "detail": h.get("status", "")}

    def execute(self, sid, argv, *, workdir, env, timeout_s, max_output_bytes) -> ExecResult:
        r = self._req("POST", f"/api/v1/sandboxes/{sid}/execute",
                      {"argv": argv, "workdir": workdir, "env": env, "timeout_s": timeout_s})
        return ExecResult(r["exit_code"], r["stdout"], r["stderr"], r["timed_out"], r["truncated"], r["duration_s"])
