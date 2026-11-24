"""API keys -> roles. admin > operator > viewer. No key configured = everything refused."""
import secrets

from fastapi import Header, HTTPException

RANK = {"viewer": 1, "operator": 2, "admin": 3}


def role_for(authorization: str | None, keys: dict[str, str]) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip().encode()
    found = None
    for role, key in keys.items():  # check every key so timing doesn't reveal the role
        if key and secrets.compare_digest(token, key.encode()):
            found = found or role
    return found


def require(min_role: str, get_keys):
    def dep(authorization: str | None = Header(default=None)) -> str:
        role = role_for(authorization, get_keys())
        if role is None:
            raise HTTPException(401, "Missing or invalid API key")
        if RANK[role] < RANK[min_role]:
            raise HTTPException(403, f"Role '{role}' may not do this (needs {min_role})")
        return role
    return dep
