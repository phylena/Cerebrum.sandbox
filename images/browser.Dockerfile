# Browser profile: Microsoft's Playwright image (Chromium/Firefox/WebKit preinstalled) + the matching
# `playwright` Python package (the image ships browsers, not the package),
# re-owned to the sandbox user. Chromium runs without its own setuid sandbox (Playwright's default);
# the container (or gVisor) is the boundary. Browser profiles live in the tmpfs HOME and vanish with it.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    python3 -m pip install --no-cache-dir --break-system-packages playwright==1.55.0 && rm -rf /root/.cache
RUN groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -s /bin/bash sandbox \
 && mkdir -p /workspace /home/sandbox && chown 10001:10001 /workspace /home/sandbox \
 && chmod -R a+rX /ms-playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
USER 10001:10001
WORKDIR /workspace
CMD ["sleep", "infinity"]
