"""Credential broker. Secrets never enter a sandbox, an image, a workspace file, a log or an
API response. Flow:
  1. admin stores a credential (encrypted at rest with SANDBOX_SECRET_KEY) with allowed hosts,
     allowed scopes and a maximum lease TTL;
  2. an operator (Cerebrum) asks for a *lease*: bound to one sandbox, one scope, a short TTL;
  3. the controller resolves the lease host-side when it performs the operation (e.g. a git
     clone) and injects the secret only into that host-side process' environment.
Leases expire, can be revoked, die with their sandbox, and every use is audited.

Kinds:
  token       a static token (e.g. a fine-grained GitHub PAT); sent as HTTP basic x-access-token
  github_app  {"app_id", "installation_id", "private_key_pem"}: the broker mints a GitHub App
              installation token restricted to the one repository and to contents:read, valid
              ~1h, cached until shortly before it expires.
"""
import base64
import json
import re
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken

from .redact import register_secret

SCOPES = {"git:clone"}
KINDS = {"token", "github_app"}


class BrokerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def github_app_jwt(app_id: str, private_key_pem: str, now: float | None = None) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(now or time.time())
    head = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}).encode())
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{_b64url(sig)}"


class Broker:
    def __init__(self, st, store, http_factory=None):
        self.st, self.store = st, store
        self._fernet = Fernet(st.secret_key.encode()) if st.secret_key else None
        self._http = http_factory or (lambda: __import__("httpx").Client(timeout=20))
        self._cache: dict[tuple[str, str], tuple[str, float]] = {}

    # ---- credentials (admin) ----------------------------------------------------------
    def _need(self):
        if not self._fernet:
            raise BrokerError(503, "credential broker disabled: set SANDBOX_SECRET_KEY")
        return self._fernet

    def add(self, name: str, kind: str, secret: str, hosts: list[str], scopes: list[str],
            max_ttl_s: int, actor: str) -> dict:
        f = self._need()
        if kind not in KINDS:
            raise BrokerError(422, f"kind must be one of {sorted(KINDS)}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}", name):
            raise BrokerError(422, "bad credential name")
        bad = set(scopes) - SCOPES
        if bad or not scopes:
            raise BrokerError(422, f"scopes must be a non-empty subset of {sorted(SCOPES)}")
        if not hosts or any(not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", h) for h in hosts):
            raise BrokerError(422, "hosts: exact lowercase hostnames")
        if not 60 <= max_ttl_s <= 86400:
            raise BrokerError(422, "max_ttl_s must be 60..86400")
        if kind == "github_app":
            try:
                cfg = json.loads(secret)
                assert {"app_id", "installation_id", "private_key_pem"} <= set(cfg)
                github_app_jwt(cfg["app_id"], cfg["private_key_pem"])  # validates the key now
            except Exception as e:  # noqa: BLE001
                raise BrokerError(422, "github_app secret must be JSON with app_id, installation_id, "
                                       "private_key_pem (an RSA PEM key)") from e
        if self.store.q("SELECT 1 FROM credentials WHERE name=?", (name,)):
            raise BrokerError(409, f"credential '{name}' exists")
        cid = "cred_" + secrets.token_hex(6)
        self.store.x("INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,NULL)",
                     (cid, name, kind, f.encrypt(secret.encode()).decode(), json.dumps(sorted(hosts)),
                      json.dumps(sorted(scopes)), max_ttl_s, time.time()))
        self.store.audit(actor, "credential.add", cid, "ok", {"name": name, "kind": kind, "hosts": hosts})
        return self.get(cid)

    @staticmethod
    def _view(r) -> dict:
        return {"id": r["id"], "name": r["name"], "kind": r["kind"], "hosts": json.loads(r["hosts"]),
                "scopes": json.loads(r["scopes"]), "max_ttl_s": r["max_ttl_s"], "created_at": r["created_at"],
                "revoked_at": r["revoked_at"]}

    def get(self, cid: str) -> dict:
        rows = self.store.q("SELECT * FROM credentials WHERE id=?", (cid,))
        if not rows:
            raise BrokerError(404, "credential not found")
        return self._view(rows[0])

    def list_credentials(self) -> list[dict]:
        return [self._view(r) for r in self.store.q("SELECT * FROM credentials ORDER BY name")]

    def revoke(self, cid: str, actor: str) -> None:
        self.get(cid)
        now = time.time()
        self.store.x("UPDATE credentials SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, cid))
        self.store.x("UPDATE leases SET revoked_at=? WHERE credential_id=? AND revoked_at IS NULL", (now, cid))
        self._cache = {k: v for k, v in self._cache.items() if k[0] != cid}
        self.store.audit(actor, "credential.revoke", cid, "ok")

    # ---- leases (operator) -----------------------------------------------------------------
    def lease(self, cid: str, sandbox_id: str, scope: str, ttl_s: int, actor: str) -> dict:
        self._need()
        c = self.get(cid)
        if c["revoked_at"]:
            raise BrokerError(409, "credential is revoked")
        if scope not in c["scopes"]:
            raise BrokerError(403, f"credential does not allow scope '{scope}'")
        ttl = min(max(30, ttl_s), c["max_ttl_s"])
        lid, now = "lease_" + secrets.token_hex(12), time.time()
        self.store.x("INSERT INTO leases(id,credential_id,sandbox_id,scope,created_at,expires_at) VALUES (?,?,?,?,?,?)",
                     (lid, cid, sandbox_id, scope, now, now + ttl))
        self.store.audit(actor, "lease.create", lid, "ok", {"credential": cid, "sandbox": sandbox_id, "scope": scope,
                                                            "ttl_s": ttl})
        return {"id": lid, "credential_id": cid, "sandbox_id": sandbox_id, "scope": scope, "expires_at": now + ttl}

    def leases(self, sandbox_id: str | None = None) -> list[dict]:
        q = "SELECT * FROM leases" + (" WHERE sandbox_id=?" if sandbox_id else "") + " ORDER BY created_at DESC"
        return [dict(r) for r in self.store.q(q, (sandbox_id,) if sandbox_id else ())]

    def revoke_lease(self, lid: str, actor: str) -> None:
        self.store.x("UPDATE leases SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), lid))
        self.store.audit(actor, "lease.revoke", lid, "ok")

    def revoke_for_sandbox(self, sandbox_id: str) -> None:
        self.store.x("UPDATE leases SET revoked_at=? WHERE sandbox_id=? AND revoked_at IS NULL",
                     (time.time(), sandbox_id))

    # ---- resolution (controller only, host side) ----------------------------------------------
    def resolve_git_header(self, lid: str, sandbox_id: str, host: str, repo: str, actor: str) -> str:
        """Returns the value for `http.extraHeader` (never stored, never sent to the sandbox)."""
        f = self._need()
        rows = self.store.q("SELECT * FROM leases WHERE id=?", (lid,))
        why = None
        if not rows:
            why = "unknown lease"
        else:
            l = rows[0]
            if l["revoked_at"]:
                why = "lease revoked"
            elif l["expires_at"] < time.time():
                why = "lease expired"
            elif l["sandbox_id"] != sandbox_id:
                why = "lease belongs to another sandbox"
            elif l["scope"] != "git:clone":
                why = "lease scope is not git:clone"
        if why is None:
            cr = self.store.q("SELECT * FROM credentials WHERE id=?", (rows[0]["credential_id"],))[0]
            if cr["revoked_at"]:
                why = "credential revoked"
            elif host not in json.loads(cr["hosts"]):
                why = f"credential not allowed for host '{host}'"
        if why:
            self.store.audit(actor, "lease.use", lid, "denied", {"reason": why, "sandbox": sandbox_id})
            raise BrokerError(403, f"credential lease refused: {why}")
        try:
            secret = f.decrypt(cr["secret"].encode()).decode()
        except InvalidToken as e:
            raise BrokerError(500, "credential cannot be decrypted (SANDBOX_SECRET_KEY changed?)") from e
        token = self._github_app_token(cr["id"], json.loads(secret), repo) if cr["kind"] == "github_app" else secret
        register_secret(token)
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        register_secret(basic)
        self.store.x("UPDATE leases SET uses=uses+1 WHERE id=?", (lid,))
        self.store.audit(actor, "lease.use", lid, "ok", {"sandbox": sandbox_id, "host": host, "repo": repo})
        return f"Authorization: Basic {basic}"

    def _github_app_token(self, cid: str, cfg: dict, repo: str) -> str:
        key = (cid, repo)
        hit = self._cache.get(key)
        if hit and hit[1] - 300 > time.time():
            return hit[0]
        jwt = github_app_jwt(cfg["app_id"], cfg["private_key_pem"])
        register_secret(jwt)
        name = repo.split("/", 1)[1] if "/" in repo else repo
        with self._http() as http:
            r = http.post(f"{self.st.github_api_url}/app/installations/{cfg['installation_id']}/access_tokens",
                          headers={"Authorization": f"Bearer {jwt}", "Accept": "application/vnd.github+json"},
                          json={"repositories": [name], "permissions": {"contents": "read"}})
        if r.status_code != 201:
            raise BrokerError(502, f"GitHub refused to mint a token ({r.status_code})")
        data = r.json()
        token = data["token"]
        register_secret(token)
        exp = time.time() + 3000
        try:
            from datetime import datetime
            exp = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")).timestamp()
        except (KeyError, ValueError):
            pass
        self._cache[key] = (token, exp)
        return token
