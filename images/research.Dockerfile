# Research profile: base + scientific Python. Installed system-wide at build time (sandboxes have no network).
FROM cerebrum-sandbox/base:latest
USER root
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir numpy pandas scipy scikit-learn matplotlib sympy networkx pyarrow statsmodels \
    && rm -rf /root/.cache
ENV MPLBACKEND=Agg MPLCONFIGDIR=/tmp/mpl
USER 10001:10001
