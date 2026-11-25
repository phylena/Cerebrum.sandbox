# Security model

**Threat model.** Everything that runs in a sandbox is untrusted: it is written or chosen by an AI model and may be
wrong or hostile. The controller and the host are trusted. API callers are authenticated; scoped keys are tenants
that must not see each other.

## Controls and how they are verified
"Live" = asserted against a real Docker daemon in `tests/test_docker_live.py`; "unit" = asserted against fakes.

| Control | Where | Verified |
|---|---|---|
| Commands are argv vectors; the platform never builds shell strings | controller, runtimes | unit |
| Runs as uid 10001; PID 1 runs as `nobody` so the sandbox user cannot kill the sandbox | docker adapter | live |
| Zero effective and bounding capabilities, `no-new-privileges`, Docker's default seccomp filter | docker adapter | live |
| Read-only root filesystem; `noexec` `/tmp`; no host bind mounts; no Docker socket | docker adapter | live |
| Memory (no swap), CPU, pids limits; fork bombs and memory hogs are contained | docker adapter | live |
| Workspace confined to `/workspace` (path normalisation); temporary workspaces are size-limited tmpfs (kernel quota) | base runtime | live |
| Persistent workspace quota: checked before writes + periodic scan that stops over-quota sandboxes | controller, maintenance | live |
| Timeouts kill the whole process group; output is bounded in memory; `setsid`-escaped processes can be reaped | runtime, `processes/kill` | live |
| No network by default (`--network none`, only `lo`) | docker adapter | live |
| Allowlist networking: internal Docker network (no route, no DNS) + our proxy: exact hosts/ports, no private/metadata IPs, every attempt logged | egress proxy | live + unit |
| IMDS unreachable from containers on AWS (hop limit 1 + `DOCKER-USER` drop) | CloudFormation | template only |
| Isolation can only be strengthened per request; per-node floor; runtimes refuse other levels; no silent fallback | controller, runtimes | unit |
| gVisor (`runsc`): user-space kernel; identity, caps, read-only root, no network, quotas, memory limit, timeouts, files, pause/resume, isolation floor | gvisor runtime | **live** (runsc 20261123) |
| Firecracker microVMs (no NIC, block-device workspace quota) | firecracker runtime | fake Firecracker + real agent only |
| GPUs assigned exclusively by device index, never `all` | scheduler, docker adapter | unit |
| Fail-closed auth; role keys; admin-issued scoped keys stored as SHA-256, expiring, revocable; other tenants' objects return 404 | auth, API | unit |
| Credentials encrypted at rest (Fernet); leases bound to one sandbox + scope + short TTL; injected host-side only; never in sandbox, image, workspace, `.git/config`, logs or responses; GitHub App tokens minted per repo, read-only | broker, git | unit + live (clone) |
| Git: https + allowlisted hosts/repos, no hooks, fsck, no submodules, ref-name validation, tar sanitised (no setuid), nothing is pushed | git_ops | unit + live |
| Secret redaction of outputs, logs, audit (patterns + exact values handed out by the broker) | redact | unit |
| Audit log of every mutating action; structured access logs without headers/bodies | store, API | unit |
| Dashboard: no embedded secrets, key in sessionStorage, textContent rendering only, strict CSP | dashboard | browser test |
| Worker URLs cannot target metadata/link-local addresses; worker keys never returned | workers | unit |

## Known limits (read before production)
- **Container isolation shares the host kernel.** For hostile code set `SANDBOX_MIN_ISOLATION=gvisor` (verified live) or use `microvm` (not yet run on real KVM).
- The controller can drive the Docker daemon, so it is root-equivalent on its host. Keep it on a dedicated machine; never run other workloads under its account.
- Firecracker: no `jailer` yet (run the service as a dedicated user with `/dev/kvm` access), no networking, no memory snapshots.
- `allowed_executables` is a policy aid, not a boundary: an allowed interpreter can run anything inside the sandbox.
- Background processes may keep running inside a sandbox after an execution (bounded by its limits); call `processes/kill` or stop the sandbox.
- Remote workers are trusted nodes; use TLS between them. Custom profiles must exist on each worker.
- Egress allowlisting is by hostname at CONNECT time; TLS is not intercepted, so a client could present a different SNI/Host inside the tunnel to a shared front (domain fronting on CDNs). Plain HTTP has its Host header forced to the vetted target. Allowlist only hosts you trust end-to-end.
- Env vars passed to `execute` are visible in the host's process list for the duration of the call; pass secrets only through the broker.
