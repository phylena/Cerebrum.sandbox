# Base sandbox image: Python 3.12, Node 22, git, bash, coreutils. Non-root uid 10001.
# No apt at build time (works on networks that only allow container registries).
FROM node:22-bookworm-slim AS node
FROM python:3.12-bookworm
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -s /bin/bash sandbox \
 && mkdir -p /workspace /home/sandbox && chown 10001:10001 /workspace /home/sandbox \
 && git --version && node --version && python3 --version
USER 10001:10001
WORKDIR /workspace
CMD ["sleep", "infinity"]
