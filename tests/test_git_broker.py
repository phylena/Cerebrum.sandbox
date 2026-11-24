import base64
import json
import os
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.broker import Broker, BrokerError
from cerebrum_sandbox.git_ops import GitError, check_ref, hardened_env, host_clone, parse_repo_url, tar_tree
from cerebrum_sandbox.redact import redact
from cerebrum_sandbox.settings import Settings
from cerebrum_sandbox.store import Store
from conftest import ADM, OP, VW, FakeRuntime

KEY = Fernet.generate_key().decode()


# ---- validation ----
@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://u:p@github.com/a/b", "https://github.com/a/b?x=1",
                                 "https://github.com:22/a/b", "ssh://github.com/a/b", "file:///etc", "git@github.com:a/b",
                                 "https://github.com/a", "https://github.com/a/b/c", "https://github.com/../a/b",
                                 "https://github.com/-a/b"])
def test_bad_repo_urls(url):
    with pytest.raises(GitError):
        parse_repo_url(url, ["github.com"], [])


def test_repo_url_allowlists():
    assert parse_repo_url("https://github.com/CerveauAnalytique/Cerebrum.model", ["github.com"], []) == \
        ("https://github.com/CerveauAnalytique/Cerebrum.model.git", "github.com", "CerveauAnalytique/Cerebrum.model")
    with pytest.raises(GitError) as e:
        parse_repo_url("https://gitlab.com/a/b", ["github.com"], [])
    assert e.value.status == 403
    assert parse_repo_url("https://github.com/org/x.git", ["github.com"], ["org/"])[2] == "org/x"
    with pytest.raises(GitError):
        parse_repo_url("https://github.com/evil/x", ["github.com"], ["org/", "a/b"])


@pytest.mark.parametrize("ref,ok", [("main", True), ("feature/x-1", True), ("-x", False), ("a..b", False),
                                    ("a.lock", False), ("a/", False), ("a//b", False), ("x@{1}", False), ("", False),
                                    ("--upload-pack=evil", False)])
def test_ref_validation(ref, ok):
    if ok:
        assert check_ref(ref) == ref
    else:
        with pytest.raises(GitError):
            check_ref(ref)


def test_hardened_env_keeps_token_out_of_argv_and_config():
    env = hardened_env("/tmp/h", "Authorization: Basic abc")
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert pairs["protocol.allow"] == "never" and pairs["protocol.https.allow"] == "always"
    assert pairs["core.hooksPath"] == "/dev/null" and pairs["transfer.fsckObjects"] == "true"
    assert pairs["http.extraHeader"] == "Authorization: Basic abc"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_TERMINAL_PROMPT"] == "0"


def test_tar_tree_strips_setuid_and_owner(tmp_path):
    import io, tarfile
    (tmp_path / "s").write_text("x"); os.chmod(tmp_path / "s", 0o4777)
    (tmp_path / "l").symlink_to("/etc/passwd")
    t = tarfile.open(fileobj=io.BytesIO(tar_tree(tmp_path)))
    m = {i.name: i for i in t.getmembers()}
    assert m["./s"].mode & 0o7000 == 0 and m["./s"].mode & 0o002 == 0 and m["./s"].uid == 10001
    assert m["./l"].issym() and m["./l"].linkname == "/etc/passwd"  # kept as a link, host file not read


# ---- broker ----
@pytest.fixture
def broker(tmp_path):
    st = Settings(data_dir=tmp_path, secret_key=KEY)
    return Broker(st, Store(tmp_path)), st


def test_broker_disabled_without_key(tmp_path):
    b = Broker(Settings(data_dir=tmp_path), Store(tmp_path))
    with pytest.raises(BrokerError) as e:
        b.add("gh", "token", "ghp_secretsecretsecret1", ["github.com"], ["git:clone"], 600, "a")
    assert e.value.status == 503


def test_broker_lease_rules_and_encryption(broker, tmp_path):
    b, st = broker
    tok = "ghp_TopSecretValue1234567890"
    c = b.add("gh", "token", tok, ["github.com"], ["git:clone"], 600, "adm")
    assert "secret" not in c and tok.encode() not in (tmp_path / "sandbox.db").read_bytes()  # encrypted at rest
    lease = b.lease(c["id"], "aaaaaaaaaaaa", "git:clone", 99999, "op")
    assert lease["expires_at"] - time.time() <= 601                                    # clamped to max_ttl
    with pytest.raises(BrokerError, match="scope"):
        b.lease(c["id"], "aaaaaaaaaaaa", "git:push", 60, "op")
    for args, why in ((("bbbbbbbbbbbb", "github.com"), "another sandbox"), (("aaaaaaaaaaaa", "gitlab.com"), "host")):
        with pytest.raises(BrokerError, match=why):
            b.resolve_git_header(lease["id"], *args, "o/r", "op")
    h = b.resolve_git_header(lease["id"], "aaaaaaaaaaaa", "github.com", "o/r", "op")
    assert h == "Authorization: Basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode()
    assert tok not in redact(f"oops {tok} leaked") and h.split()[-1] not in redact(h)  # scrubbed everywhere
    b.store.x("UPDATE leases SET expires_at=1 WHERE id=?", (lease["id"],))
    with pytest.raises(BrokerError, match="expired"):
        b.resolve_git_header(lease["id"], "aaaaaaaaaaaa", "github.com", "o/r", "op")
    l2 = b.lease(c["id"], "aaaaaaaaaaaa", "git:clone", 60, "op")
    b.revoke(c["id"], "adm")
    with pytest.raises(BrokerError, match="revoked"):
        b.resolve_git_header(l2["id"], "aaaaaaaaaaaa", "github.com", "o/r", "op")
    assert any(a["action"] == "lease.use" and a["outcome"] == "denied" for a in b.store.q("SELECT * FROM audit"))


def test_github_app_minting(tmp_path):
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        return httpx.Response(201, json={"token": "ghs_MintedShortLivedToken123", "expires_at": "2099-01-01T00:00:00Z"})
    st = Settings(data_dir=tmp_path, secret_key=KEY, github_api_url="https://api.example")
    b = Broker(st, Store(tmp_path), http_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    c = b.add("app", "github_app", json.dumps({"app_id": "42", "installation_id": "7", "private_key_pem": pem}),
              ["github.com"], ["git:clone"], 3600, "adm")
    lid = b.lease(c["id"], "aaaaaaaaaaaa", "git:clone", 600, "op")["id"]
    h1 = b.resolve_git_header(lid, "aaaaaaaaaaaa", "github.com", "org/repo", "op")
    b.resolve_git_header(lid, "aaaaaaaaaaaa", "github.com", "org/repo", "op")
    assert len(seen) == 1                                                       # cached until near expiry
    req = seen[0]
    assert req.url.path == "/app/installations/7/access_tokens"
    assert json.loads(req.content) == {"repositories": ["repo"], "permissions": {"contents": "read"}}
    head, body, sig = req.headers["authorization"].split()[1].split(".")
    pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
    pk.public_key().verify(base64.urlsafe_b64decode(pad(sig)), f"{head}.{body}".encode(), padding.PKCS1v15(),
                           hashes.SHA256())                                     # valid RS256 JWT
    assert json.loads(base64.urlsafe_b64decode(pad(body)))["iss"] == "42"
    assert "ghs_MintedShortLivedToken123" in base64.b64decode(h1.split()[-1]).decode()
    with pytest.raises(BrokerError):
        b.add("bad", "github_app", "{}", ["github.com"], ["git:clone"], 600, "adm")


# ---- API with a fake fetcher ----
def local_repo(tmp_path) -> Path:
    r = tmp_path / "origin"
    r.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-qm", "init"]):
        if cmd[0] == "add":
            (r / "README.md").write_text("hello\n"); (r / "app.py").write_text("print(1)\n")
        subprocess.run(["git", "-C", str(r), *cmd], check=True, env=env)
    return r


def fake_fetcher(repo: Path, seen: list):
    def f(url, branch, depth, header, **kw):
        seen.append((url, branch, depth, header))
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        return tar_tree(repo), head
    return f


def test_clone_api_with_lease_and_tenancy(tmp_path):
    st = Settings(data_dir=tmp_path / "d", admin_key="adm", operator_key="op", viewer_key="vw", secret_key=KEY)
    c = TestClient(create_app(st, runtimes={"docker": FakeRuntime()}))
    ctl, seen = c.app.state.controller, []
    ctl.git_fetcher = fake_fetcher(local_repo(tmp_path), seen)
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    cred = c.post("/api/v1/credentials", json={"name": "gh", "kind": "token", "secret": "ghp_abcdefghijklmnopqrs"},
                  headers=ADM).json()
    assert "secret" not in cred and c.post("/api/v1/credentials", json={"name": "x", "kind": "token",
                                                                         "secret": "12345678"}, headers=OP).status_code == 403
    lease = c.post(f"/api/v1/sandboxes/{sid}/leases", json={"credential_id": cred["id"]}, headers=OP).json()
    r = c.post(f"/api/v1/sandboxes/{sid}/git/clone",
               json={"url": "https://github.com/acme/widget", "credential_lease": lease["id"]}, headers=OP)
    assert r.status_code == 201 and r.json()["path"] == "/workspace/widget" and len(r.json()["head"]) == 40
    assert seen[0][3].startswith("Authorization: Basic ")                       # injected host-side only
    assert "ghp_abcdefghijklmnopqrs" not in json.dumps(c.get("/api/v1/audit", headers=ADM).json())
    assert c.post(f"/api/v1/sandboxes/{sid}/git/clone", json={"url": "https://evil.com/a/b"}, headers=OP).status_code == 403
    other = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    r = c.post(f"/api/v1/sandboxes/{other}/git/clone",                           # lease is bound to its sandbox
               json={"url": "https://github.com/acme/widget", "credential_lease": lease["id"]}, headers=OP)
    assert r.status_code == 403
    c.delete(f"/api/v1/sandboxes/{sid}", headers=OP)
    assert c.get(f"/api/v1/sandboxes/{sid}/leases", headers=VW).json()[0]["revoked_at"]  # died with the sandbox


def _network_ok():
    try:
        return subprocess.run(["git", "ls-remote", "https://github.com/octocat/Hello-World.git", "HEAD"],
                              capture_output=True, timeout=30).returncode == 0
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _network_ok(), reason="github.com not reachable")
def test_host_clone_real_public_repo(tmp_path):
    tar, head = host_clone("https://github.com/octocat/Hello-World.git", None, 1, "X-Test: secret-header-value",
                           workdir=tmp_path, max_bytes=50 * 2**20, timeout_s=120)
    import io, tarfile
    t = tarfile.open(fileobj=io.BytesIO(tar))
    names = t.getnames()
    assert "./README" in names and "./.git/config" in names and len(head) == 40
    cfg = t.extractfile("./.git/config").read().decode()
    assert "secret-header-value" not in cfg and "extraheader" not in cfg.lower()
    assert list(tmp_path.iterdir()) == []                                       # temp clone removed
    with pytest.raises(GitError) as e:
        host_clone("https://github.com/octocat/Hello-World.git", None, 1, None, workdir=tmp_path, max_bytes=10,
                   timeout_s=120)
    assert e.value.status == 413
