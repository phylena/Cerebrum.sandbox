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

## 3. Components (implemented now vs planned)

| Module | State |
|---|---|
| `settings`, `auth` (admin/operator/viewer, fail closed) | done |
| `lifecycle` (validated state machine) | done |
| `profiles` (basic, development, research, training, browser, mcp + admin custom; extra fields forbidden) | done; training/browser/mcp/research images not yet built |
| `policy` (network model, strict domain validation) | model done; **enforcement only for `none`**. Allowlist needs an internal Docker network + egress proxy (phase 9); until configured the adapter refuses (fail closed) |
| `runtime/base` + `runtime/docker` | done, hardening unit-tested, live behaviour unverified |
| `runtime/gvisor`, `runtime/firecracker` (+ guest agent), `runtime/remote`, `runtime/registry`, `scheduler` (placement, exclusive GPU assignment) | done and tested against fakes / real agent code; **not run on real runsc, KVM or GPU hardware**. See [runtimes.md](runtimes.md) |
| `controller` (create/start/stop/pause/resume/destroy, quotas, execute, recovery, TTL cleanup) | done |
| `store` (SQLite WAL metadata, audit, online backup) | done |
| `redact` | done |
| `resources` (CPU/mem/disk/KVM/GPU detection) | done |
| `api` (sandboxes, execute, executions, logs, profiles, resources, audit, health) | done |
| files/workspace API, git, credential broker, job queue/retries, snapshots, metrics, dashboard, Cerebrum tool, AWS IaC, Firecracker jailer/network, OpenSandbox adapter | **not started** (see roadmap) |

## 4. Security model (current)
- Commands are **argv vectors** only: no shell string is built by the platform.
- Containers: non-root 10001, read-only rootfs, `--cap-drop ALL`, no-new-privileges, pids/memory(+no swap)/cpu limits, `--network none` default, tmpfs `/tmp`, no host bind mounts, no Docker socket, image prefix allowlist, working dir confined to `/workspace`.
- Temporary workspaces are size-limited tmpfs (kernel-enforced); persistent ones are named volumes whose byte quota is **not yet enforced** (phase 6).
- Known limits: no seccomp profile beyond Docker's default; env vars passed at exec are visible in host process listings (credential broker will replace this); `Profile.allowed_executables` is a policy aid, not a security boundary (a permitted interpreter can run anything); there is no per-owner access isolation between operator-key holders yet (single operator key = Cerebrum).
- Audit log + redaction on stored output/logs; retention purge on cleanup.

## 5. AWS deployment design (not created)
Start: **one EC2 instance** (e.g. m7i/c7i for CPU; `g5/g6` for GPU; a `.metal` type only if microVMs are enabled), encrypted gp3 EBS for `SANDBOX_DATA_DIR`, API bound to localhost behind Caddy/ALB with TLS, security group with no inbound except the proxy, IAM instance role with **no** permissions beyond CloudWatch/SSM, IMDSv2 required and **blocked from sandboxes** (iptables rule on the docker bridge to 169.254.169.254; the default `--network none` already prevents it). S3 for snapshot/backups later. Scale-out: workers on additional instances registered with the controller, or EKS + agent-sandbox. Nothing is provisioned by this repo; IaC will be CDK/CloudFormation, delivered for review and never applied without approval.

## 6. Roadmap (phases from the brief)
Done in this change: **1** (repo + architecture), **2** (API+controller), **3** (Docker runtime), **4** (lifecycle), **5** (execution engine, core), parts of **8** (hardening), **10** (audit/redaction), **16** (tests).
Added since: **12** (placement across local + remote workers; queue/retries still open), **13** (GPU workers), **14** (gVisor, Firecracker, remote-worker adapters; OpenSandbox not done).
Next, in order: 6 workspaces+files API (quota enforcement) -> 7 git (clone/branch/diff/commit in sandbox; credential broker with short-lived tokens, creds never in sandbox) -> 9 allowlist egress proxy + netlog -> 11 Cerebrum integration (a `sandbox` tool in `brain/app/tools.py`, minimal PR to Cerebrum.model, uses the operator key) -> 12 scheduler/queue/jobs/workers -> 13 GPU workers -> 14 gVisor verification, OpenSandbox/Firecracker adapters -> 15 dashboard -> 17 AWS IaC -> 18 docs.
