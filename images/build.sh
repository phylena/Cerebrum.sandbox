#!/usr/bin/env bash
# Build the sandbox images. Usage: images/build.sh [base research mcp browser training]   (default: all but training)
# Behind a TLS-intercepting proxy: CA_FILE=/path/ca.pem images/build.sh ...  (passed as a build secret, never stored)
set -euo pipefail
cd "$(dirname "$0")"
targets=("$@"); [ ${#targets[@]} -eq 0 ] && targets=(base research mcp browser)
extra=(); [ -n "${CA_FILE:-}" ] && extra=(--secret "id=ca,src=$CA_FILE" --network host)
for t in "${targets[@]}"; do
  echo "==> cerebrum-sandbox/$t"
  docker build "${extra[@]}" -t "cerebrum-sandbox/$t:latest" -f "$t.Dockerfile" .
done
