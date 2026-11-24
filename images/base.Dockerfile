# Base sandbox image: Python, Node, git, bash. Non-root uid 10001, nothing privileged.
# NOT built or tested in the authoring environment (no Docker daemon there): build and run
# tests/test_docker_live.py on the target host before trusting it.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs npm ca-certificates coreutils procps \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -s /bin/bash sandbox \
    && mkdir -p /workspace /home/sandbox && chown 10001:10001 /workspace /home/sandbox
USER 10001:10001
WORKDIR /workspace
CMD ["sleep", "infinity"]
