# Cerebrum.model integration

Cerebrum.model stays the brain. It decides; Cerebrum.sandbox executes. Nothing in the brain's inference,
LangGraph graphs, Mem0 memory or Cognee knowledge changes.

## What was inspected (Cerebrum.model @ `4a55c54`)
- `brain/` is an OpenAI-compatible FastAPI service with a single bearer key. Agent tools are declared per mode
  (`config.Mode.tools`) and executed by `tools.run()`. Only `cerebrum-agent` (and `cerebrum-haiti`) use the agent graph.
- `research/` runs model-written evaluation code in a *limited subprocess*, off by default (`EVAL_ALLOW_CODE_EXEC=0`),
  and documents that this is not a real sandbox.

## The integration (branch `claude/cerebrum-sandbox-tool` in Cerebrum.model, 6 files, +47 lines)
- A `run_code` tool for `cerebrum-agent`: Python, JavaScript or Bash. Each call gets a short-lived sandbox
  (`SANDBOX_PROFILE`, default `basic`: no network, 0.5 CPU, 256 MB, 60 s), the code is uploaded as a file, run as
  an argv vector and the sandbox is deleted, also on errors. Owner = the verified user id.
- **Off by default.** The tool only exists when both `SANDBOX_URL` and `SANDBOX_API_KEY` are set; with them unset the
  brain behaves exactly as before. Failures (sandbox busy, timeouts) are returned to the model as text, never raised.
- Tests: `brain/tests/test_sandbox_tool.py` (fake sandbox). Verified end-to-end here against a real
  Cerebrum.sandbox + Docker: Python/JS/Bash ran as uid 10001 without network, an infinite loop was stopped at the
  timeout, sandboxes were owned by the user id and none were left behind.

## Configuration
On the sandbox host, issue a key for the brain. A scoped key keeps the brain's sandboxes separate from everything else:
```bash
curl -s -XPOST localhost:8300/api/v1/keys -H "Authorization: Bearer $SANDBOX_ADMIN_KEY" \
     -H content-type:application/json -d '{"name":"cerebrum-brain","role":"operator","owner":"cerebrum"}'
```
In Cerebrum.model's `.env`: `SANDBOX_URL=http://host.docker.internal:8300` (with
`extra_hosts: ["host.docker.internal:host-gateway"]` on the brain service on Linux) and `SANDBOX_API_KEY=<key>`.

## Beyond run_code
Everything else Cerebrum may need is in the API and in `cerebrum_sandbox/client.py`:
- **Software development:** `sandbox("development")` -> `git_clone` -> `git_branch` -> edit/run tests -> `git_commit`
  -> `git_report()` (commits, diffstat, patch). The production repository is never pushed to; credentials come from
  broker leases and never enter the sandbox.
- **Research / evaluation:** the Research Engine's `EVAL_ALLOW_CODE_EXEC` path can be pointed at `submit_job()` instead of
  a local subprocess (not changed yet: that is a decision for the Cerebrum.model owner).
- **Training jobs:** `submit_job(..., profile="training")` lands on a node with a free GPU (whole devices, exclusive).
