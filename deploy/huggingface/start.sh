#!/usr/bin/env bash
set -euo pipefail
if [ -z "${SANDBOX_ADMIN_KEY:-}" ] || [ -z "${SANDBOX_OPERATOR_KEY:-}" ]; then
  echo "FATAL: set SANDBOX_ADMIN_KEY and SANDBOX_OPERATOR_KEY as Space secrets." >&2
  exit 1
fi
if [ -z "${SANDBOX_DATA_DIR:-}" ]; then
  if [ -d /data ] && [ -w /data ]; then SANDBOX_DATA_DIR=/data/sandbox; else SANDBOX_DATA_DIR="$HOME/data"; fi
fi
mkdir -p "$SANDBOX_DATA_DIR"
export SANDBOX_DATA_DIR
cd /home/user/app
# Report which isolation layers this host really offers, before serving anything.
python - <<'PY'
from cerebrum_sandbox.settings import load
from cerebrum_sandbox.runtime.process import ProcessRuntime
h = ProcessRuntime(load()).health()
print(f"[start] process runtime: ok={h['ok']} mode={h['mode']} layers={h['layers']} ({h['detail']})", flush=True)
PY
exec python -m cerebrum_sandbox
