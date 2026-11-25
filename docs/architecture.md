# Cerebrum.sandbox: architecture and plan

## 1. Inspection (2026-11-24)

**Cerebrum.model** (`CerveauAnalytique/Cerebrum.model`, inspected at `4a55c54`; the repo is the real source of truth, not its docs):
- `brain/` is a FastAPI, OpenAI-compatible API (`/v1/chat/completions`, memory, knowledge). Auth: one static `Authorization: Bearer <CEREBRUM_API_KEY>`. If the key is unset the brain is **open** (dev only).
- Agent tools live in `brain/app/tools.py` (`SPECS` + `run()`: calculator, current_time, search_haiti_docs). It has **no code-execution tool today**, which is the natural integration point.
- `research/` (Research Engine) uses role-based bearer keys (`admin/operator/viewer/feedback`), fails closed with no keys, and runs model-written code only in a *limited subprocess* gated by `EVAL_ALLOW_CODE_EXEC=0`. It states this "is not a full sandbox". Cerebrum.sandbox is the proper replacement for that path.
- Deployment is docker-compose (`ollama`, `brain`, optional `caddy`, GPU override, `research` profile) with a separate `research/docs/aws.md`.
- Conventions copied here: env-var settings, role keys, fail-closed auth, data-dir persistence.

**This build host:** 4 vCPU, 16 GB RAM, ~60 GB free disk, **no GPU, no `/dev/kvm`**, Docker CLI present but **no Docker daemon**, running as root, Python 3.13. Consequences:
- Nothing that needs a container daemon or KVM can be exercised here. The Docker adapter's hardening is verified at the command-construction level only; the live test (`tests/test_docker_live.py`) skips here and **must be run on the target host**.
- Firecracker/microVM runtimes cannot be tested here at all.
- AWS: no credentials or infrastructure were created or modified. Nothing was discovered beyond the local host. See section 5.

## 2. Open-source evaluation

Evidence: github.com repository pages fetched on 2026-11-24. The GitHub API was blocked (403) and open-sandbox.ai did not resolve from this environment, so **push dates / maintenance activity are unverified** and benchmark claims are the projects' own. Stars are context, not a quality signal.

| Project | Verified facts | Decision |
|---|---|---|
| **OpenSandbox** (`opensandbox-group/OpenSandbox`, Apache-2.0) | Agent sandbox runtime; local Docker server, Kubernetes operator; egress policies; Firecracker on K8s. README SDK paths reference `alibaba` namespaces; README discloses release images lack signing/provenance (issue #2463). | **Candidate adapter (phase 14)**, after we have an own Docker baseline. Supply-chain gap must be re-checked before use. |
| **E2B** SDK (`e2b-dev/E2B`, Apache-2.0) | Client SDK/CLI for E2B (hosted cloud). | Not a runtime. API shape is a useful reference; not integrated. |
| **E2B runtime** (`e2b-dev/infra` redirects to `e2b-dev/runtime`, Apache-2.0) | Go control plane + orchestrator; one Firecracker microVM per sandbox, cgroup+netns, nftables egress; self-host "Embed" compose on one KVM Linux host, Terraform for AWS. | **Reference for a microVM tier.** Requires KVM: on AWS that means `.metal` instances (or nested virt where available). Heavy; deferred. |
| **OpenHands** (`OpenHands/OpenHands`, MIT) | Now centred on "Agent Canvas"; default runs agent on the host with full filesystem access; optional per-conversation Docker. | **Architecture reference only** (as instructed). Its default is *not* a sandbox: we never run it unsandboxed. Possible later: run it *inside* a sandbox. |
| **Sandstorm** (`deeplethe/sandstorm`, Apache-2.0) | Single binary master/node; pause/snapshot/restore; gVisor or Firecracker per sandbox; cgroup v2. | **Reference for fleet/snapshot design (phases 12/17).** Not adopted as a dependency until we review its code and maturity. |
| **gVisor** (`google/gvisor` -> `gvisor/gvisor`, Apache-2.0) | `runsc` OCI runtime; user-space kernel; not a VM. | **Adopt as stronger isolation tier** on Docker (`isolation: gvisor` already supported). Needs `runsc` installed on host; not verified here. |
| **Firecracker** (Apache-2.0) | KVM microVM; seccomp + jailer; snapshots. | **Target for strongest tier**; needs KVM host. Phase 14. |
| **microsandbox** (canonical: `superradcompany/microsandbox`; the `microsandbox/` and `zerocore-ai/` names both resolve to it; Apache-2.0) | Local-first libkrun microVMs, `msb` CLI + SDKs, needs KVM; README labels it **beta**. | Watch; possible Phase 14 adapter. Not adopted (beta). |
| **Kubernetes agent-sandbox** (`kubernetes-sigs/agent-sandbox`, Apache-2.0) | CRDs (Sandbox, Template, Claim, WarmPool); isolation delegated to RuntimeClass (gVisor/Kata). | **Right shape for a multi-node (EKS) future.** Not needed for single-server start. |
| **Docker / moby** (`moby/moby`, Apache-2.0) | Engine toolkit; API and CLI. | **Baseline runtime today** via the `docker` CLI. |
| **Kata Containers** (Apache-2.0) | VM-per-container via `kata-deploy`. | Alternative microVM-ish tier on Kubernetes; later. |
| **Cloud Hypervisor** | Rust VMM, needs host kernel 6.8+; license not confirmed from fetched text. | Not needed. |
| **bubblewrap** (LGPL-2.1) | Unprivileged namespace+seccomp sandbox, no VM. | Possible inner layer for the MCP profile; not now. |

Deno, WebAssembly, Landlock, containerd: not researched in this pass (listed in the brief; no evidence gathered, so no decision recorded).

### Runtime decision
Isolation tiers behind one `Runtime` interface:
1. **Hardened Docker (runc)**: implemented. Fine for trusted-ish agent code with no network; *not* adequate alone for hostile code (shared kernel).
2. **Docker + gVisor**: flag implemented, unverified on a real host.
3. **microVM (Firecracker via E2B-runtime/Sandstorm patterns, or microsandbox)**: roadmap; needs KVM hosts.
Because AI-generated code is untrusted, the recommended production default on AWS is tier 2 minimum, tier 3 for anything with network access or secrets.

## 3. Components and verification status

"Live" means exercised against a real Docker daemon (Docker 29, this repo's build host) by `tests/test_docker_live.py`.

| Module | What it does | Verified |
|---|---|---|
| `api/app.py` | 59 operations, OpenAPI at `/docs`, dashboard at `/dashboard` | unit + live + browser |
| `auth.py` | role keys + scoped, hashed, expiring, revocable tenant keys | unit |
| `controller.py`, `lifecycle.py` | lifecycle state machine, quotas, execution, files, git, snapshots, recovery | unit + live |
| `scheduler.py` | placement on local/remote workers, exclusive GPU assignment | unit |
| `runtime/docker.py` | hardened containers | **live** |
| `runtime/gvisor.py` | Docker + `runsc`; refuses without it | unit (no `runsc` here) |
| `runtime/firecracker.py` + `images/firecracker/` | own Firecracker driver + vsock guest agent | fake Firecracker + real agent; **no KVM here** |
| `runtime/remote.py` | worker fleet over the same public API | unit (two in-process services) |
| `egress.py` | allowlist proxy on an internal network | unit + **live** |
| `git_ops.py`, `broker.py` | hardened host-side clone, in-sandbox git, credential leases, GitHub App tokens | unit + live (+ real public clone) |
| `jobs.py` | priority queue, retries, cancel, budget, recovery | unit + live |
| `monitor.py` | events, alert webhook, maintenance loop, Prometheus metrics, backups | unit |
| `resources.py` | CPU/memory/disk/KVM/GPU discovery | unit; GPU path untested (no GPU) |
| Deployment | controller image, compose, systemd, CloudFormation, CI | image run live; template `cfn-lint` clean, never deployed |

Not implemented: memory-state snapshots, Firecracker jailer/networking/snapshots, an OpenSandbox adapter,
automatic rescheduling from dead workers, multi-tenant quotas per owner (limits are per node).

## 4. Security model
See [security.md](security.md): every control, how it is tested, and the known limits.

## 5. AWS deployment
Implemented as `deploy/aws/cerebrum-sandbox.yaml` (CloudFormation, `cfn-lint` clean, **never deployed**): one EC2
instance (`m7i/c7i` CPU, `g5/g6` GPU, `.metal` for Firecracker), no inbound ports (SSM port forwarding), IMDSv2 with
hop limit 1 and a `DOCKER-USER` drop for 169.254.169.254, SSM/CloudWatch-only instance role, encrypted gp3 data
volume with snapshot-on-delete, optional private versioned backup bucket with TLS-only policy. Scale-out = more
instances registered as workers. No billing, budget or network configuration outside the stack is touched.
See [operations.md](operations.md).

## 6. Roadmap
Phases 1-18 of the brief are implemented to the level stated in section 3. Remaining work, in order of value:
1. Run `pytest -m docker` with `runsc` installed and on a KVM host (`.metal`) to verify gVisor and Firecracker for real; add the Firecracker jailer.
2. Verify GPU passthrough on a `g5`/`g6` instance with the NVIDIA container toolkit.
3. Per-owner quotas; automatic rescheduling of jobs from dead workers.
4. Build and publish the research/training/browser/mcp images that those profiles reference.
