---
title: Cerebrum Sandbox
emoji: 🧪
colorFrom: gray
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
short_description: Isolated code execution for the Cerebrum AI ecosystem
---

# Cerebrum.sandbox

Isolated execution for Cerebrum: the agent's `run_code` tool, research experiments and evaluation
of model-written code run here, never in the model service. API at `/api/v1` (OpenAPI at `/docs`),
dashboard at `/dashboard`. Every endpoint except `/health` needs a role key.

**Isolation on this Space: the `process` runtime.** A Space has no Docker daemon, KVM or gVisor, so each
command runs as a restricted, unprivileged process tree: Landlock (files and TCP), seccomp (no IPv4/IPv6
sockets, no ptrace/mount/namespaces/io_uring/bpf, no signals to the controller), memory/CPU/file-size/
process limits, a clean environment without any secret, and bubblewrap namespaces when the platform allows
them. `GET /api/v1/runtimes` lists the layers that are active right now. This is weaker than the hardened
container / gVisor / Firecracker runtimes of a self-hosted deployment (see the repository's
docs/security.md), and sandboxes here have **no network**.

Source of truth: GitHub `phylena/Cerebrum.sandbox` (deployed with `deploy/huggingface/push_space.py`).

Secrets: `SANDBOX_ADMIN_KEY`, `SANDBOX_OPERATOR_KEY` (used by Cerebrum.model, research and evaluation),
`SANDBOX_VIEWER_KEY`, `SANDBOX_SECRET_KEY` (Fernet key for the credential broker).
