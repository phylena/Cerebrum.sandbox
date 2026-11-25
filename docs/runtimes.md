# Runtimes, GPU workers and the worker fleet

Cerebrum only ever says *what* it needs (a profile, optionally a stronger `isolation`, optionally a `worker`).
It never names a runtime class, so runtimes, GPUs and workers can be added or changed without touching the
API or the Cerebrum.model integration. All new request fields are optional; old clients work unchanged.

```
POST /api/v1/sandboxes {"profile":"basic","isolation":"gvisor"}          # stronger isolation
POST /api/v1/sandboxes {"profile":"training"}                             # lands on a node with a free GPU
POST /api/v1/sandboxes {"profile":"basic","worker":"gpu-1"}               # pin to a worker
GET  /api/v1/runtimes   GET/POST/DELETE /api/v1/workers   GET /api/v1/resources
```

## Isolation levels
| `isolation` | Runtime | Boundary | Network | GPU | Status |
|---|---|---|---|---|---|
| `container` | `docker` | shared kernel + hardening flags | none or proxy allowlist | yes | **verified live** (Docker 29); GPU flag unit-tested only |
| `gvisor` | `gvisor` | `runsc` user-space kernel (same Docker flags) | none or proxy allowlist | **refused** | **verified live** with runsc release 20261123 (`tests/test_docker_live.py`) |
| `microvm` | `firecracker` | KVM microVM, own kernel | **none only** (no NIC attached) | **refused** | API sequence, vsock protocol, lifecycle and guest agent tested against a fake Firecracker + the real agent; **never booted a real VM** (no `/dev/kvm` here) |

Rules enforced in code:
- A request may only *strengthen* a profile's isolation (weaker -> 422). `SANDBOX_MIN_ISOLATION` upgrades weaker profiles to a floor.
- A runtime refuses profiles of another isolation level, so nothing silently runs weaker. If gVisor/Firecracker prerequisites are missing the create fails with the reason; there is no fallback to plain Docker.
- Unavailable level on this node and on every online worker -> 503.

## Firecracker (own implementation)
Per sandbox: private rootfs copy mounted **read-only**, a separate ext4 **workspace disk whose size is the quota**, Firecracker driven over its API socket, and our own stdlib guest agent (`images/firecracker/csb_agent.py`) reached over vsock for execution (argv only, own process group, killed on timeout, bounded output, minimal environment, workdir confined to `/workspace`, drops to uid 10001 when started as root).
Setup on a KVM host: build the rootfs with `images/firecracker/build-rootfs.sh`, provide a Firecracker guest kernel, set `SANDBOX_RUNTIMES=docker,firecracker`, `SANDBOX_FC_KERNEL`, `SANDBOX_FC_ROOTFS`. On AWS this means a `.metal` instance (or one with nested virtualization) - not available on ordinary EC2 sizes.
Not done: the Firecracker **jailer** (chroot/cgroup/uid drop for the VMM itself), VM memory snapshots, network devices + egress enforcement. Until the jailer is added, run the service as a dedicated unprivileged user that has `/dev/kvm` access.

## GPU workers
A GPU worker is any node (local or remote) that reports GPUs. The scheduler assigns **whole devices exclusively by index**, passes exactly those to Docker (`--gpus "device=N"`, never `all`), never exceeds free devices, and enforces `SANDBOX_MAX_GPU_SANDBOXES` platform-wide. `SANDBOX_GPU_INDICES` reserves devices for other uses. CPU-only nodes work normally; a GPU request with no GPU anywhere fails with 429 and says why. Needs the NVIDIA container toolkit on the host (**not verified here**: no GPU). GPU utilisation/memory come from `nvidia-smi` via `/api/v1/resources`.

## Worker fleet (our own Sandstorm-style layer)
A worker is another node running this same service. The master registers it (admin only: `POST /api/v1/workers` with the worker's *operator* key, stored in the 0600 metadata DB and never returned), probes `/health`, `/api/v1/runtimes` and `/api/v1/resources`, and then drives sandboxes on it through the same public API using the **same sandbox id**. The worker applies its own quotas, isolation floor and GPU allocation. Placement picks the least-loaded node that has the runtime and capacity (local wins ties). Unreachable workers are marked offline, get no new sandboxes, and their existing sandboxes keep their recorded state (never guessed as failed).
Limits: worker URLs are validated (http/https, no credentials, no metadata/link-local addresses); custom (non built-in) profiles must exist on the worker under the same name; a worker is only as trustworthy as its key/transport (use TLS between nodes); no automatic rescheduling of sandboxes from a dead worker, no snapshot migration.

## Sandstorm
Not integrated and not needed: the fleet layer above covers worker orchestration with our own code and one API. If Sandstorm (Apache-2.0, `deeplethe/sandstorm`) is later evaluated, it would be one more `Runtime` adapter registered in `runtime/registry.py` with its isolation level, with no API change.

## Adding another runtime
1. Implement `Runtime` (`runtime/base.py`) in `runtime/<name>.py`, set `isolation`, refuse profiles of other levels, fail closed when prerequisites are missing.
2. Add it to `runtime/registry.FACTORIES` and map its isolation in `profiles.RUNTIME_FOR` (or reuse an existing level).
3. Enable it per node with `SANDBOX_RUNTIMES`. No API, controller or Cerebrum change.
