"""Small synchronous client for the Cerebrum.sandbox API (stdlib + httpx only).

    from cerebrum_sandbox.client import SandboxClient
    with SandboxClient("http://127.0.0.1:8300", key) as sb:
        with sb.sandbox("development") as box:          # destroyed on exit
            box.write("main.py", b"print(6*7)")
            print(box.run(["python3", "main.py"]).stdout)
        job = sb.submit_job(["python3", "-c", "print(1)"])
        print(sb.wait_job(job["id"])["state"])
"""
import base64
import time
from dataclasses import dataclass

import httpx


class SandboxError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


@dataclass
class Result:
    status: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_s: float

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class SandboxClient:
    def __init__(self, url: str, key: str, timeout: float = 660, transport=None, client: httpx.Client | None = None):
        self.http = client or httpx.Client(base_url=url.rstrip("/"), timeout=timeout,
                                           headers={"Authorization": f"Bearer {key}"}, transport=transport)
        if client is not None:
            self.http.headers["Authorization"] = f"Bearer {key}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.http.close()

    def _call(self, method: str, path: str, **kw):
        r = self.http.request(method, path, **kw)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            raise SandboxError(r.status_code, str(detail))
        if r.headers.get("content-type", "").startswith("application/json"):
            return r.json()
        return r.content

    # ---- sandboxes ----
    def create(self, profile: str = "basic", **kw) -> "Sandbox":
        return Sandbox(self, self._call("POST", "/api/v1/sandboxes", json={"profile": profile, **kw})["id"])

    def sandbox(self, profile: str = "basic", **kw) -> "Sandbox":
        return self.create(profile, **kw)

    def list_sandboxes(self, state: str | None = None) -> list[dict]:
        return self._call("GET", "/api/v1/sandboxes", params={"state": state} if state else None)

    # ---- jobs ----
    def submit_job(self, argv: list[str], *, files: dict[str, bytes] | None = None, outputs: list[str] | None = None,
                   **kw) -> dict:
        body = {"argv": argv, "files": {k: base64.b64encode(v).decode() for k, v in (files or {}).items()},
                "outputs": outputs or [], **kw}
        return self._call("POST", "/api/v1/jobs", json=body)

    def job(self, jid: str) -> dict:
        return self._call("GET", f"/api/v1/jobs/{jid}")

    def wait_job(self, jid: str, timeout: float = 3600, poll: float = 1.0) -> dict:
        end = time.monotonic() + timeout
        while True:
            j = self.job(jid)
            if j["state"] in ("succeeded", "failed", "cancelled") or time.monotonic() > end:
                return j
            time.sleep(poll)

    def cancel_job(self, jid: str) -> dict:
        return self._call("DELETE", f"/api/v1/jobs/{jid}")

    def health(self) -> dict:
        return self._call("GET", "/health")


class Sandbox:
    def __init__(self, client: SandboxClient, sid: str):
        self.c, self.id = client, sid

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.destroy()

    def _p(self, suffix: str = "") -> str:
        return f"/api/v1/sandboxes/{self.id}{suffix}"

    def info(self) -> dict:
        return self.c._call("GET", self._p())

    def run(self, argv: list[str], *, workdir: str | None = None, env: dict | None = None,
            timeout_s: int | None = None, stdin: bytes | None = None) -> Result:
        body = {"argv": argv, "workdir": workdir, "env": env or {}, "timeout_s": timeout_s}
        if stdin is not None:
            body["stdin_b64"] = base64.b64encode(stdin).decode()
        d = self.c._call("POST", self._p("/execute"), json=body)
        return Result(d["status"], d["exit_code"], d["stdout"], d["stderr"], d["timed_out"], d["truncated"],
                      d["duration_s"])

    def write(self, path: str, data: bytes) -> None:
        self.c._call("POST", self._p("/files/upload"), params={"path": path}, content=data)

    def read(self, path: str) -> bytes:
        return self.c._call("GET", self._p("/files/download"), params={"path": path})

    def ls(self, path: str = "/workspace") -> list[dict]:
        return self.c._call("GET", self._p("/files"), params={"path": path})

    def git_clone(self, url: str, **kw) -> dict:
        return self.c._call("POST", self._p("/git/clone"), json={"url": url, **kw})

    def git_branch(self, name: str, repo: str | None = None) -> dict:
        return self.c._call("POST", self._p("/git/branch"), json={"name": name, "repo": repo})

    def git_commit(self, message: str, repo: str | None = None) -> dict:
        return self.c._call("POST", self._p("/git/commit"), json={"message": message, "repo": repo})

    def git_report(self, repo: str | None = None) -> dict:
        return self.c._call("GET", self._p("/git/report"), params={"repo": repo} if repo else None)

    def snapshot(self, label: str | None = None) -> dict:
        return self.c._call("POST", self._p("/snapshots"), json={"label": label})

    def restore(self, snapshot_id: str, clear: bool = True) -> dict:
        return self.c._call("POST", self._p("/restore"), json={"snapshot_id": snapshot_id, "clear": clear})

    def stop(self) -> dict:
        return self.c._call("POST", self._p("/stop"))

    def start(self) -> dict:
        return self.c._call("POST", self._p("/start"))

    def destroy(self) -> dict:
        return self.c._call("DELETE", self._p())
