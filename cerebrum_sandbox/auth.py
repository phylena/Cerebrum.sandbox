"""Authentication: static role keys (env) + admin-issued scoped keys (DB, stored as SHA-256).

admin > operator > viewer. A *scoped* key carries an owner: it only ever sees and acts on
sandboxes of that owner (tenant isolation, e.g. one key per Cerebrum user or agent). Static
keys are unscoped. No key configured anywhere = every request is refused (fail closed).
"""
import hashlib
import secrets
import time
from dataclasses import dataclass

from fastapi import Header, HTTPException

RANK = {"viewer": 1, "operator": 2, "admin": 3}


@dataclass(frozen=True)
class Principal:
    role: str
    name: str                 # who, for the audit log
    owner: str | None = None  # None = unscoped (may see every sandbox)

    def may_see(self, sandbox_owner: str) -> bool:
        return self.owner is None or self.owner == sandbox_owner


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_key() -> str:
    return "csb_" + secrets.token_urlsafe(32)


def resolve(authorization: str | None, static_keys: dict[str, str], store) -> Principal | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip()
    if not token:
        return None
    found = None
    for role, key in static_keys.items():  # check every key so timing doesn't reveal the role
        if key and secrets.compare_digest(token.encode(), key.encode()):
            found = found or Principal(role, role)
    if found:
        return found
    rows = store.q("SELECT * FROM api_keys WHERE hash=? AND revoked_at IS NULL", (hash_key(token),))
    if rows:
        r = rows[0]
        if r["expires_at"] and r["expires_at"] < time.time():
            return None
        return Principal(r["role"], f"key:{r['name']}", r["owner"])
    return None


def require(min_role: str, get_keys, store):
    def dep(authorization: str | None = Header(default=None)) -> Principal:
        p = resolve(authorization, get_keys(), store)
        if p is None:
            raise HTTPException(401, "Missing or invalid API key")
        if RANK[p.role] < RANK[min_role]:
            raise HTTPException(403, f"Role '{p.role}' may not do this (needs {min_role})")
        return p
    return dep
