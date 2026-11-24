"""Git integration.

Clone happens HOST-SIDE in the controller (hardened git: https only, no hooks, fsck, no
submodules, token only via environment, never in argv or .git/config), then the working tree
is streamed into the sandbox as a tar. The sandbox therefore needs no network and never sees
a credential. Everything after the clone (branch, checkout, status, diff, commit, log, patch)
runs INSIDE the sandbox as argv vectors. Nothing is ever pushed: results leave as a diff,
patch and report, and the production repository is never modified directly.
"""
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from .redact import redact
from .runtime.base import RuntimeError_, safe_path

REF = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)(?!.*\.lock$)(?!.*[./]$)[A-Za-z0-9._/-]{1,200}$")
SHA = re.compile(r"^[0-9a-f]{7,40}$")
_SEG = r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
AUTHOR = {"GIT_AUTHOR_NAME": "Cerebrum", "GIT_AUTHOR_EMAIL": "cerebrum@sandbox.invalid",
          "GIT_COMMITTER_NAME": "Cerebrum", "GIT_COMMITTER_EMAIL": "cerebrum@sandbox.invalid"}
NOPAGER = {"GIT_PAGER": "cat", "PAGER": "cat", "GIT_TERMINAL_PROMPT": "0"}


class GitError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def check_ref(name: str) -> str:
    if not name or not REF.match(name):
        raise GitError(422, f"invalid ref/branch name '{name}'")
    return name


def parse_repo_url(url: str, allowed_hosts: list[str], allowed_repos: list[str]) -> tuple[str, str, str]:
    """-> (normalised url, host, 'owner/repo'). https only, allowlisted host, no creds/query."""
    u = urlparse(url)
    if u.scheme != "https" or u.username or u.password or u.query or u.fragment or u.port:
        raise GitError(422, "repository url must be https://host/owner/repo without credentials, port or query")
    host = (u.hostname or "").lower()
    if host not in allowed_hosts:
        raise GitError(403, f"host '{host}' is not allowed (SANDBOX_GIT_ALLOWED_HOSTS={allowed_hosts})")
    m = re.fullmatch(rf"/({_SEG})/({_SEG}?)(?:\.git)?/?", u.path)
    if not m:
        raise GitError(422, "repository path must be /owner/repo")
    repo = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
    if allowed_repos and not any(repo == a or (a.endswith("/") and repo.startswith(a)) for a in allowed_repos):
        raise GitError(403, f"repository '{repo}' is not allowed (SANDBOX_GIT_ALLOWED_REPOS)")
    return f"https://{host}/{repo}.git", host, repo


def hardened_env(home: str, header: str | None) -> dict[str, str]:
    cfg = [("protocol.allow", "never"), ("protocol.https.allow", "always"), ("core.hooksPath", "/dev/null"),
           ("transfer.fsckObjects", "true"), ("credential.helper", ""), ("submodule.recurse", "false"),
           ("core.symlinks", "true"), ("advice.detachedHead", "false")]
    if header:
        cfg.append(("http.extraHeader", header))
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
           "GIT_CONFIG_COUNT": str(len(cfg)), "LANG": "C.UTF-8"}
    for i, (k, v) in enumerate(cfg):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    for k in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "GIT_SSL_CAINFO"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def host_clone(url: str, branch: str | None, depth: int, header: str | None, *, workdir: Path,
               max_bytes: int, timeout_s: int) -> tuple[bytes, str]:
    """Clone on the controller host; return (tar of the tree incl. .git, HEAD sha)."""
    workdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="clone-", dir=workdir))
    try:
        env = hardened_env(str(tmp), header)
        dest = tmp / "repo"
        cmd = ["git", "clone", "--depth", str(depth), "--single-branch", "--no-tags",
               "--no-recurse-submodules", "--quiet"]
        if branch:
            cmd += ["--branch", check_ref(branch)]
        cmd += ["--", url, str(dest)]
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout_s, cwd=tmp)
        except subprocess.TimeoutExpired as e:
            raise GitError(504, "git clone timed out") from e
        if r.returncode:
            raise GitError(502, "git clone failed: " + redact(r.stderr.strip())[-300:])
        size = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file() and not f.is_symlink())
        if size > max_bytes:
            raise GitError(413, f"repository too large ({size} > {max_bytes} bytes)")
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], env=env, capture_output=True,
                              text=True, timeout=30).stdout.strip()
        cfg = (dest / ".git" / "config").read_text()
        if "extraheader" in cfg.lower() or "x-access-token" in cfg:  # must never be persisted
            raise GitError(500, "credential leaked into .git/config; refusing to continue")
        return tar_tree(dest), head
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def tar_tree(root: Path) -> bytes:
    """Tar a directory for the sandbox: owner 10001, no setuid/setgid/sticky bits, symlinks kept
    as links (never followed on the host)."""
    def clean(ti: tarfile.TarInfo):
        ti.uid = ti.gid = 10001
        ti.uname = ti.gname = ""
        ti.mode &= 0o755 if ti.isdir() else 0o775
        return ti
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(root, arcname=".", filter=clean)
    return buf.getvalue()


# ---- inside the sandbox ---------------------------------------------------------------------
class SandboxGit:
    """Builds and runs git argv inside a sandbox through a Runtime's execute()."""

    def __init__(self, rt, sid: str, timeout_s: int = 120, max_output: int = 2 * 2**20):
        self.rt, self.sid, self.timeout, self.max_output = rt, sid, timeout_s, max_output

    def run(self, repo: str, *args: str, env: dict | None = None, check: bool = True):
        r = self.rt.execute(self.sid, ["git", "--no-pager", "-c", "core.hooksPath=/dev/null", "-C", repo, *args],
                            workdir="/workspace", env={**NOPAGER, **(env or {})}, timeout_s=self.timeout,
                            max_output_bytes=self.max_output)
        if check and r.exit_code != 0:
            raise GitError(409 if r.exit_code == 1 else 422, f"git {args[0]} failed: {r.stderr.strip()[:400]}")
        return r

    def extract(self, tar: bytes, dest: str) -> None:
        dest = safe_path(dest)
        r = self.rt.execute(self.sid, ["sh", "-c", 'if [ -e "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; then '
                                       'echo "destination exists and is not empty" >&2; exit 17; fi; '
                                       'mkdir -p "$1" && tar -x --no-same-owner --no-same-permissions -C "$1"',
                                       "sh", dest],
                            workdir="/workspace", env={}, timeout_s=self.timeout, max_output_bytes=65536, stdin=tar)
        if r.exit_code == 17:
            raise GitError(409, "destination exists and is not empty")
        if r.exit_code != 0:
            raise GitError(502, f"extract failed: {r.stderr.strip()[:300]}")

    def status(self, repo: str) -> dict:
        out = self.run(repo, "status", "--porcelain=v1", "--branch", "--untracked-files=all").stdout
        lines = out.splitlines()
        head = lines[0][3:] if lines and lines[0].startswith("## ") else ""
        files = [{"status": l[:2], "path": l[3:]} for l in lines[1:] if l]
        return {"branch": head.split("...")[0], "tracking": head, "clean": not files, "files": files}

    def create_branch(self, repo: str, name: str, start: str | None = None) -> dict:
        args = ["switch", "-c", check_ref(name)]
        if start:
            args.append(check_ref(start))
        self.run(repo, *args)
        return self.status(repo)

    def checkout(self, repo: str, ref: str) -> dict:
        if SHA.match(ref):
            self.run(repo, "switch", "--detach", ref)
        else:
            self.run(repo, "switch", check_ref(ref))
        return self.status(repo)

    def branches(self, repo: str) -> list[str]:
        return [b.strip() for b in self.run(repo, "branch", "--format=%(refname:short)").stdout.splitlines() if b.strip()]

    def diff(self, repo: str, *, staged: bool = False, base: str | None = None, stat: bool = False) -> str:
        args = ["diff", "--no-color", "--no-ext-diff"]
        if stat:
            args.append("--stat")
        if staged:
            args.append("--cached")
        if base:
            args.append(base if SHA.match(base) else check_ref(base))
        args.append("--")
        return self.run(repo, *args).stdout

    def commit(self, repo: str, message: str, add_all: bool = True) -> dict:
        if not message.strip() or len(message) > 10000:
            raise GitError(422, "commit message required (max 10000 chars)")
        if add_all:
            self.run(repo, "add", "-A")
        r = self.run(repo, "commit", "--no-verify", "-m", message, env=AUTHOR, check=False)
        if r.exit_code != 0:
            raise GitError(409, "nothing to commit" if "nothing to commit" in r.stdout + r.stderr
                           else f"git commit failed: {r.stderr.strip()[:300]}")
        return {"sha": self.run(repo, "rev-parse", "HEAD").stdout.strip()}

    def log(self, repo: str, n: int = 20, base: str | None = None) -> list[dict]:
        args = ["log", f"-n{max(1, min(n, 500))}", "--format=%H%x1f%an%x1f%ae%x1f%at%x1f%s"]
        if base:
            args.append(f"{base}..HEAD")
        out = []
        for line in self.run(repo, *args).stdout.splitlines():
            sha, an, ae, at, subj = line.split("\x1f", 4)
            out.append({"sha": sha, "author": an, "email": ae, "time": int(at), "subject": subj})
        return out

    def patch(self, repo: str, base: str) -> str:
        return self.run(repo, "format-patch", "--stdout", "--no-color", f"{base}..HEAD").stdout
