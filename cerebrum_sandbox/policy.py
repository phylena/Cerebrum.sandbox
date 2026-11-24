"""Network policy model. Enforcement happens in the runtime adapter, never only here."""
import re
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class NetworkMode(StrEnum):
    NONE = "none"            # no network interface at all
    ALLOWLIST = "allowlist"  # outbound HTTP(S) only, via the egress proxy, to listed domains


class NetworkPolicy(BaseModel):
    mode: NetworkMode = NetworkMode.NONE
    allowed_domains: list[str] = Field(default_factory=list, max_length=64)
    allowed_ports: list[int] = Field(default_factory=lambda: [443], max_length=8)
    log_requests: bool = True

    @field_validator("allowed_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        out = []
        for d in v:
            d = d.strip().lower()
            if not _DOMAIN.match(d):  # exact hostnames only: no wildcards, no IPs, no schemes
                raise ValueError(f"invalid domain '{d}' (exact lowercase hostnames only)")
            out.append(d)
        return sorted(set(out))

    @field_validator("allowed_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("invalid port")
        return v

    def model_post_init(self, _ctx) -> None:
        if self.mode == NetworkMode.ALLOWLIST and not self.allowed_domains:
            raise ValueError("allowlist mode needs at least one domain")
        if self.mode == NetworkMode.NONE and self.allowed_domains:
            raise ValueError("network mode 'none' cannot list domains")
