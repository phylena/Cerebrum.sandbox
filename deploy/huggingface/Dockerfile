# Cerebrum.sandbox on a Hugging Face Docker Space.
#
# A Space is itself an unprivileged container: there is no Docker daemon, KVM or gVisor inside it.
# Sandboxes therefore use the "process" runtime (cerebrum_sandbox/runtime/process.py): every command
# runs as a restricted process tree with Landlock, seccomp, resource limits and a clean environment,
# plus bubblewrap namespaces when the platform allows unprivileged user namespaces.
# GET /api/v1/runtimes shows which of these layers are active on the running Space.
FROM python:3.12-slim

# bubblewrap: namespaces (used when the platform allows them); libseccomp2: the syscall filter;
# git: host-side clones; nodejs: run_code "javascript"; tar/coreutils: files and snapshots.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap libseccomp2 git nodejs ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*
# Libraries sandboxed code may import (the "research" profile: data analysis and experiments).
RUN pip install --no-cache-dir numpy pandas scipy sympy matplotlib scikit-learn

RUN useradd -m -u 1000 user
WORKDIR /home/user/app
COPY pyproject.toml README.md ./
COPY cerebrum_sandbox ./cerebrum_sandbox
RUN pip install --no-cache-dir . && chown -R 1000:1000 /home/user/app
COPY start.sh /home/user/app/start.sh
RUN chmod 755 /home/user/app/start.sh

ENV HOME=/home/user PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    SANDBOX_HOST=0.0.0.0 SANDBOX_PORT=7860 \
    SANDBOX_RUNTIMES=process SANDBOX_MIN_ISOLATION=process SANDBOX_PROCESS_FALLBACK=1 SANDBOX_PROCESS_MODE=auto \
    SANDBOX_MAX_SANDBOXES=6 SANDBOX_MAX_TOTAL_CPU=2 SANDBOX_MAX_TOTAL_MEMORY_MB=8192 SANDBOX_MAX_SANDBOX_MEMORY_MB=4096 \
    SANDBOX_MAX_EXEC_SECONDS=300 SANDBOX_MAX_CONCURRENT_JOBS=1

USER user
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s CMD curl -sf http://127.0.0.1:7860/health || exit 1
CMD ["/home/user/app/start.sh"]
