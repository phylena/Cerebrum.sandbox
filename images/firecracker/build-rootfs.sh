#!/usr/bin/env bash
# Build the Firecracker guest rootfs (ext4) from the base sandbox image + guest agent.
# Needs root, docker, and mkfs.ext4. You also need a Firecracker-compatible guest kernel
# (vmlinux) - see Firecracker's docs/getting-started. NOT run in the authoring environment.
set -euo pipefail
out=${1:?usage: build-rootfs.sh /path/rootfs.ext4 [size_mb]}; size=${2:-1024}
here=$(cd "$(dirname "$0")" && pwd)
docker build -t cerebrum-sandbox/base:latest -f "$here/../base.Dockerfile" "$here/.."
cid=$(docker create cerebrum-sandbox/base:latest); stage=$(mktemp -d)
trap 'docker rm -f "$cid" >/dev/null; rm -rf "$stage"' EXIT
docker export "$cid" | tar -x -C "$stage"
install -m 0755 "$here/csb_agent.py" "$stage/usr/local/bin/csb-agent"
install -m 0755 "$here/csb-init" "$stage/sbin/csb-init"
mkdir -p "$stage"/{proc,sys,dev,tmp,run,workspace,home/sandbox}
truncate -s "${size}M" "$out"; mkfs.ext4 -q -F -d "$stage" "$out"
echo "rootfs written to $out"
