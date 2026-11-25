# Operations

## Configuration
All settings are environment variables (`SANDBOX_*`), listed with defaults in `.env.example` and
`cerebrum_sandbox/settings.py`. The essentials:

| Variable | Purpose |
|---|---|
| `SANDBOX_ADMIN_KEY`, `SANDBOX_OPERATOR_KEY`, `SANDBOX_VIEWER_KEY` | role keys; none set = API refuses everything. Give Cerebrum the operator key or an admin-issued scoped key (`POST /api/v1/keys`) |
| `SANDBOX_RUNTIMES`, `SANDBOX_MIN_ISOLATION` | enabled runtimes (`docker,gvisor,firecracker`) and the isolation floor |
| `SANDBOX_MAX_*` | hard ceilings: sandboxes, total CPU/memory, per-sandbox CPU/memory, exec seconds, output, files, GPU sandboxes, jobs, workers |
| `SANDBOX_EGRESS_ENABLED`, `SANDBOX_EGRESS_UPSTREAM_PROXY` | built-in egress proxy for allowlist profiles |
| `SANDBOX_SECRET_KEY` | Fernet key for the credential broker (empty = broker disabled) |
| `SANDBOX_GIT_ALLOWED_HOSTS`, `SANDBOX_GIT_ALLOWED_REPOS` | which repositories may be cloned |
| `SANDBOX_JOB_HOURS_BUDGET_DAILY` | job-hours budget; jobs wait when it is used up |
| `SANDBOX_ALERT_WEBHOOK` | POST target for warning/critical events |

## Deployment
- **Single server:** `docker compose up -d --build` or the systemd unit. The API listens on 127.0.0.1; put Caddy/TLS
  or an SSH/SSM tunnel in front. Build `cerebrum-sandbox/base:latest` (and any other profile images) on the host.
- **Behind a TLS-intercepting proxy** (some corporate networks, this repo's CI host): pass the proxy CA as a
  BuildKit secret: `docker build --secret id=ca,src=ca.pem ...`. It is used for the build only.
- **AWS:** `deploy/aws/cerebrum-sandbox.yaml` creates one EC2 instance (no inbound ports, IMDSv2 hop limit 1,
  encrypted gp3 data volume with snapshot-on-delete, SSM/CloudWatch-only role, optional private versioned backup
  bucket). Choose `g5/g6` + an NVIDIA AMI for GPU jobs or a `.metal` type for Firecracker. Review and create it
  yourself (`aws cloudformation deploy ...`); nothing in this repository creates AWS resources.
- **More capacity:** run the same service on more machines and register them as workers
  (`POST /api/v1/workers`). Placement is automatic; pin with `worker`.

## Running continuously
`python -m cerebrum_sandbox` starts the API, `SANDBOX_MAX_CONCURRENT_JOBS` job runners and the maintenance loop
(every `SANDBOX_MAINTENANCE_INTERVAL_S`): TTL cleanup, quota enforcement, drift reconciliation (lost sandboxes ->
failed + critical event), worker health, host memory/disk checks, network-violation and failure events,
retention purges (audit, executions, netlog, events) and a daily metadata backup in `data/backups/` (last
`SANDBOX_BACKUP_KEEP` kept; the AWS template syncs them to S3).

On restart the controller reconciles stored state with the runtime, re-registers egress policies and re-queues
interrupted jobs (or fails them when out of retries). Metadata is SQLite in WAL mode (`data/sandbox.db`, mode 0600).
To restore: stop the service, copy a backup over `sandbox.db`, start it; reconciliation fixes state drift.

## Monitoring
- `GET /health` (unauthenticated, no secrets), `GET /metrics` (Prometheus, viewer key), `GET /api/v1/events`,
  `GET /api/v1/audit` (admin), `GET /api/v1/network/log` (admin), the dashboard at `/dashboard`.
- Access logs are one JSON object per request on stdout (no headers, no bodies).
