# Cerebrum.sandbox controller (API + scheduler + maintenance + egress proxy).
# It drives the HOST Docker daemon through the mounted socket: this container is therefore
# root-equivalent on the host and must never run sandbox workloads itself (it does not).
ARG DOCKER_CLI_IMAGE=docker:27-cli
FROM ${DOCKER_CLI_IMAGE} AS dockercli
FROM python:3.12-bookworm
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY pyproject.toml README.md ./
COPY cerebrum_sandbox ./cerebrum_sandbox
# Behind a TLS-intercepting proxy: --secret id=ca,src=/path/ca.pem (used for the build only, never stored)
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir . && rm -rf /root/.cache
ENV SANDBOX_DATA_DIR=/data SANDBOX_HOST=127.0.0.1 SANDBOX_PORT=8300 PYTHONUNBUFFERED=1
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"SANDBOX_PORT\"]}/health',timeout=4)"
CMD ["python3", "-m", "cerebrum_sandbox"]
