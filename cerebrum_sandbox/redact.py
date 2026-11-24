"""Secret redaction for everything that is logged, audited or stored."""
import re

_PATTERNS = [
    re.compile(r"(?i)\b(?:sk|pk|rk|ghp|gho|ghs|ghu|github_pat|xox[abp])[-_A-Za-z0-9]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)\S+"),
    re.compile(r"(?i)\b((?:api[_-]?key|token|password|passwd|secret|credential)s?\s*[:=]\s*)\S{4,}"),
    re.compile(r"(?i)(https?://[^/\s:@]+:)[^@\s/]+(@)"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
]


_KNOWN: set[str] = set()  # exact secret values the broker handed out: always scrubbed


def register_secret(value: str) -> None:
    if value and len(value) >= 8:
        _KNOWN.add(value)


def redact(text: str) -> str:
    if not text:
        return text
    for v in _KNOWN:
        if v in text:
            text = text.replace(v, "[REDACTED]")
    for rx in _PATTERNS:
        if rx.groups == 0:
            text = rx.sub("[REDACTED]", text)
        elif rx.groups == 1:
            text = rx.sub(lambda m: m.group(1) + "[REDACTED]", text)
        else:
            text = rx.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(2), text)
    return text
