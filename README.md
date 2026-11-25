# Cerebrum.sandbox

Self-hosted, isolated execution infrastructure for [Cerebrum.model](https://github.com/CerveauAnalytique/Cerebrum.model).
Cerebrum stays the brain (gpt-oss, LangGraph, Mem0, Cognee are untouched); this service only runs what Cerebrum
asks, inside sandboxes, and reports back.

**What works today (verified against a real Docker daemon):** sandbox lifecycle, hardened containers, argv-only
execution with timeouts, files and workspaces with quotas, git (host-side hardened clone, in-sandbox
branch/commit/diff, patch report, never pushes), credential broker with leases, an allowlist egress proxy
enforced at the network layer, jobs with a priority queue and retries, workspace snapshots, monitoring/events/metrics,
scoped tenant keys, a dashboard, and an API of 59 operations.
**Implemented but not verified on real hardware here:** gVisor (`runsc` not installed), Firecracker microVMs (no KVM),
GPU passthrough (no GPU). See [docs/architecture.md](docs/architecture.md) for the exact status of every part.

## Quick start (single server)
```bash
pip install -e '.[test]'
docker build -t cerebrum-sandbox/base:latest -f images/base.Dockerfile images
export SANDBOX_ADMIN_KEY=$(openssl rand -hex 32) SANDBOX_OPERATOR_KEY=$(openssl rand -hex 32)
python -m cerebrum_sandbox            # API + dashboard on http://127.0.0.1:8300 (/docs, /dashboard)
python -m pytest                      # 140+ tests; live Docker tests run when the daemon + image exist
```
Or `docker compose up -d --build` (see `docker-compose.yml`), the systemd unit in `deploy/systemd/`, or AWS via
`deploy/aws/cerebrum-sandbox.yaml` (CloudFormation; never created automatically).

## Using it
```bash
K="Authorization: Bearer $SANDBOX_OPERATOR_KEY"; J=content-type:application/json; U=localhost:8300/api/v1
S=$(curl -s -XPOST $U/sandboxes -H "$K" -H $J -d '{"profile":"development"}' | jq -r .id)
curl -s -XPOST $U/sandboxes/$S/execute -H "$K" -H $J -d '{"argv":["python3","-c","print(6*7)"]}'
curl -s -XPOST $U/sandboxes/$S/git/clone -H "$K" -H $J -d '{"url":"https://github.com/owner/repo"}'
curl -s "$U/sandboxes/$S/git/report" -H "$K"         # commits, diffstat and a patch; nothing is pushed
curl -s -XDELETE $U/sandboxes/$S -H "$K"
```
One-shot work goes through jobs: `POST /api/v1/jobs {"argv": [...], "files": {...}, "outputs": [...]}`.

| Doc | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | inspection results, OSS evaluation, components and their verification status, roadmap |
| [docs/security.md](docs/security.md) | threat model, every isolation control and how it is tested, known limits |
| [docs/runtimes.md](docs/runtimes.md) | isolation levels, gVisor, Firecracker, GPU workers, worker fleet, adding a runtime |
| [docs/operations.md](docs/operations.md) | configuration, deployment (single server, AWS), monitoring, backups, recovery |
| [docs/cerebrum-integration.md](docs/cerebrum-integration.md) | how Cerebrum.model uses the sandbox |
| [docs/openapi.json](docs/openapi.json) | the full API (also live at `/docs`) |
