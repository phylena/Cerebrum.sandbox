# MCP profile: base + the MCP Python SDK (pinned; v2 API: mcp.server.mcpserver.MCPServer) and uv (for stdio MCP servers that are copied into the workspace).
FROM cerebrum-sandbox/base:latest
USER root
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir "mcp==2.3.0" uv && rm -rf /root/.cache
USER 10001:10001
