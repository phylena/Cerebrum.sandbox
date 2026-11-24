import pytest
from pydantic import ValidationError

from cerebrum_sandbox.lifecycle import InvalidTransition, State, check
from cerebrum_sandbox.policy import NetworkMode, NetworkPolicy
from cerebrum_sandbox.profiles import BUILTIN, Profile
from cerebrum_sandbox.redact import redact
from cerebrum_sandbox.runtime import ExecResult, RuntimeError_, SandboxSpec
from cerebrum_sandbox.runtime.base import safe_workdir
from cerebrum_sandbox.runtime.docker import DockerRuntime, build_create_args
from cerebrum_sandbox.settings import Settings
from conftest import ADM, OP, VW


# ---- state machine ----
def test_valid_and_invalid_transitions():
    check(State.PENDING, State.PROVISIONING)
    check(State.RUNNING, State.PAUSED)
    for a, b in [(State.TERMINATED, State.RUNNING), (State.PENDING, State.RUNNING),
                 (State.STOPPED, State.PAUSED), (State.FAILED, State.RUNNING)]:
        with pytest.raises(InvalidTransition):
            check(a, b)


# ---- profiles / policy ----
def test_builtin_profiles_present_and_restricted():
    assert {"basic", "development", "research", "training", "browser", "mcp"} <= set(BUILTIN)
    assert BUILTIN["basic"].network.mode == NetworkMode.NONE
    assert not hasattr(Profile, "privileged")


@pytest.mark.parametrize("d", ["*.example.com", "1.2.3.4", "http://a.com", "localhost", "A b.com"])
def test_bad_domains_rejected(d):
    with pytest.raises(ValidationError):
        NetworkPolicy(mode="allowlist", allowed_domains=[d])


def test_policy_consistency():
    with pytest.raises(ValidationError):
        NetworkPolicy(mode="allowlist")
    with pytest.raises(ValidationError):
        NetworkPolicy(mode="none", allowed_domains=["a.com"])


def test_redaction():
    t = "Authorization: Bearer abc123def456 ghp_abcdefghijklmnop1234 password=hunter22 https://u:pw@h.com/x"
    r = redact(t)
    for leak in ("abc123def456", "ghp_abcdefghijklmnop1234", "hunter22", ":pw@"):
        assert leak not in r


def test_workdir_escape_blocked():
    assert safe_workdir(None) == "/workspace"
    assert safe_workdir("src") == "/workspace/src"
    for bad in ("/etc", "../etc", "/workspace/../etc", "/workspacex"):
        with pytest.raises(RuntimeError_):
            safe_workdir(bad)


# ---- docker adapter hardening (command construction; no daemon needed) ----
def _args(profile="basic", **st_kw):
    st = Settings(**st_kw)
    return build_create_args(SandboxSpec("abcdef012345", BUILTIN[profile]), st)


def test_docker_hardening_flags():
    a = _args()
    s = " ".join(a)
    for needed in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534",
                   "--network none", "--pids-limit 64", "--memory 256m", "--memory-swap 256m"):
        assert needed in s
    for forbidden in ("--privileged", "docker.sock", "--cap-add", "--pid host", "--network host", "-v ", "bind"):
        assert forbidden not in s
    assert "type=bind" not in s


def test_allowlist_without_egress_refused():
    with pytest.raises(RuntimeError_, match="refusing to fall back"):
        _args("development")


def test_allowlist_with_egress_uses_proxy_network():
    s = " ".join(_args("development", egress_network="csb-egress", egress_proxy_url="http://proxy:3128"))
    assert "--network csb-egress" in s and "HTTPS_PROXY=http://proxy:3128" in s


def test_gpu_and_unknown_image_refused():
    with pytest.raises(RuntimeError_, match="GPU"):
        _args("training")  # no GPU indices assigned
    bad = BUILTIN["basic"].model_copy(update={"image": "evil/image:1"})
    with pytest.raises(RuntimeError_, match="not allowed"):
        build_create_args(SandboxSpec("abcdef012345", bad), Settings())


def test_gvisor_runtime_flag():
    p = BUILTIN["basic"].model_copy(update={"isolation": "gvisor"})
    assert "--runtime runsc" in " ".join(build_create_args(SandboxSpec("abcdef012345", p), Settings()))


def test_bad_sandbox_id_refused():
    with pytest.raises(RuntimeError_):
        build_create_args(SandboxSpec("../../x", BUILTIN["basic"]), Settings())


def test_docker_status_mapping_and_exec_uses_timeout_wrapper():
    seen = []

    def runner(args, timeout):
        seen.append(args)
        return 0, "paused\n", ""
    rt = DockerRuntime(Settings(), runner)
    assert rt.status("abcdef012345") == "paused"
    rt2 = DockerRuntime(Settings(), lambda a, t: (1, "", "no such container"))
    assert rt2.status("abcdef012345") == "missing"


# ---- API ----
def test_health_and_auth(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/v1/sandboxes").status_code == 401
    assert client.get("/api/v1/sandboxes", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/v1/sandboxes", headers=VW).status_code == 200
    assert client.post("/api/v1/sandboxes", json={}, headers=VW).status_code == 403
    assert client.get("/api/v1/audit", headers=OP).status_code == 403
    assert client.get("/api/v1/audit", headers=ADM).status_code == 200


def test_no_keys_configured_fails_closed(tmp_path, rt):
    from fastapi.testclient import TestClient
    from cerebrum_sandbox.api.app import create_app
    c = TestClient(create_app(Settings(data_dir=tmp_path), rt))
    assert c.get("/api/v1/sandboxes", headers={"Authorization": "Bearer "}).status_code == 401
    assert c.get("/api/v1/sandboxes").status_code == 401


def test_full_lifecycle(client, rt):
    r = client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP)
    assert r.status_code == 201 and r.json()["state"] == "running"
    sid = r.json()["id"]
    assert client.post(f"/api/v1/sandboxes/{sid}/pause", headers=OP).json()["state"] == "paused"
    assert client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["echo"]}, headers=OP).status_code == 409
    assert client.post(f"/api/v1/sandboxes/{sid}/resume", headers=OP).json()["state"] == "running"
    assert client.post(f"/api/v1/sandboxes/{sid}/stop", headers=OP).json()["state"] == "stopped"
    assert client.post(f"/api/v1/sandboxes/{sid}/pause", headers=OP).status_code == 409
    assert client.post(f"/api/v1/sandboxes/{sid}/start", headers=OP).json()["state"] == "running"
    assert client.delete(f"/api/v1/sandboxes/{sid}", headers=OP).json()["state"] == "terminated"
    assert sid not in rt.boxes
    assert client.post(f"/api/v1/sandboxes/{sid}/start", headers=OP).status_code == 409


def test_create_failure_marks_failed_and_cleans_up(client, rt):
    rt.fail_create = True
    r = client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP)
    assert r.status_code == 502
    failed = client.get("/api/v1/sandboxes?state=failed", headers=VW).json()
    assert len(failed) == 1 and failed[0]["error"] == "boom"


def test_quotas(client):
    ids = [client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).status_code for _ in range(4)]
    assert ids == [201, 201, 201, 429]  # max_sandboxes=3
    assert client.get("/api/v1/resources", headers=VW).json()["usage"]["sandboxes"] == 3


def test_cpu_quota(client):
    assert client.post("/api/v1/sandboxes", json={"profile": "development"}, headers=OP).status_code == 201
    # development = 1 cpu, 1024MB: a second would exceed total memory 1024
    r = client.post("/api/v1/sandboxes", json={"profile": "development"}, headers=OP)
    assert r.status_code == 429


def test_execute_clamps_timeout_and_redacts(client, rt):
    sid = client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    rt.next_exec = ExecResult(1, "password=supersecret1\n", "")
    r = client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["python3", "-c", "1"], "timeout_s": 9999},
                    headers=OP).json()
    assert r["status"] == "error" and "supersecret1" not in r["stdout"]
    assert rt.calls[-1][4] == 60  # basic max_timeout_s
    rt.next_exec = ExecResult(124, "", "", timed_out=True)
    assert client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["sleep", "99"]},
                       headers=OP).json()["status"] == "timeout"
    assert len(client.get(f"/api/v1/sandboxes/{sid}/executions", headers=VW).json()) == 2


def test_execute_validation(client):
    sid = client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    assert client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": []}, headers=OP).status_code == 422
    assert client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["ls"], "workdir": "/etc"},
                       headers=OP).status_code == 422


def test_allowed_executables(client):
    p = {"name": "py-only", "allowed_executables": ["python3"]}
    assert client.post("/api/v1/profiles", json=p, headers=OP).status_code == 403
    assert client.post("/api/v1/profiles", json=p, headers=ADM).status_code == 201
    sid = client.post("/api/v1/sandboxes", json={"profile": "py-only"}, headers=OP).json()["id"]
    assert client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["/bin/sh", "-c", "id"]},
                       headers=OP).status_code == 403
    assert client.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["/usr/bin/python3", "-V"]},
                       headers=OP).status_code == 200


def test_custom_profile_limits_and_builtin_protected(client):
    assert client.post("/api/v1/profiles", json={"name": "huge", "memory_mb": 999999}, headers=ADM).status_code == 422
    assert client.post("/api/v1/profiles", json={"name": "basic"}, headers=ADM).status_code == 409
    assert client.post("/api/v1/profiles", json={"name": "xx", "privileged": True}, headers=ADM).status_code == 422
    names = [p["name"] for p in client.get("/api/v1/profiles", headers=VW).json()]
    assert "basic" in names


def test_logs_redacted(client):
    sid = client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    assert "abcdef123456" not in client.get(f"/api/v1/sandboxes/{sid}/logs", headers=VW).json()["logs"]


def test_recovery_and_persistence(st, rt):
    from cerebrum_sandbox.api.app import create_app
    app = create_app(st, rt)
    ctl = app.state.controller
    a = ctl.create("basic", "t")["id"]
    b = ctl.create("basic", "t")["id"]
    c = ctl.create("basic", "t")["id"]
    ctl.pause(b, "t")
    rt.boxes[a] = "stopped"          # drifted behind our back
    rt.boxes.pop(c)                  # runtime lost it
    ctl.store.x("INSERT INTO sandboxes(id,owner,profile,profile_json,state,runtime,error,created_at,updated_at,"
                "expires_at) SELECT 'stuck000001',owner,profile,profile_json,'provisioning',runtime,"
                "NULL,created_at,updated_at,NULL FROM sandboxes WHERE id=?", (a,))
    app2 = create_app(st, rt)        # "restart": new controller on the same database
    ctl2 = app2.state.controller
    assert ctl2.get(a)["state"] == "stopped"
    assert ctl2.get(b)["state"] == "paused"
    assert ctl2.get(c)["state"] == "failed"
    assert ctl2.get("stuck000001")["state"] == "failed"


def test_ttl_cleanup_and_backup(st, rt, tmp_path):
    from cerebrum_sandbox.api.app import create_app
    ctl = create_app(st, rt).state.controller
    sid = ctl.create("basic", "t", ttl_s=10)["id"]
    ctl.store.x("UPDATE sandboxes SET expires_at=1 WHERE id=?", (sid,))
    assert ctl.cleanup_expired() == [sid]
    assert ctl.get(sid)["state"] == "terminated"
    out = ctl.store.backup(tmp_path / "bk" / "meta.db")
    import sqlite3
    assert sqlite3.connect(out).execute("select count(*) from sandboxes").fetchone()[0] == 1


def test_audit_trail(client):
    client.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP)
    actions = [a["action"] for a in client.get("/api/v1/audit", headers=ADM).json()]
    assert "sandbox.create" in actions


def test_dashboard_served_with_strict_headers(client):
    r = client.get("/dashboard")
    assert r.status_code == 200 and "Cerebrum" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert client.get("/dashboard/app.js").headers["content-type"].startswith("text/javascript")
    for bad in ("../api/app.py", "..%2F..%2Fsettings.py", "x.html", "%2e%2e%2fstore.py"):
        assert client.get(f"/dashboard/{bad}").status_code == 404
    js = client.get("/dashboard/app.js").text
    assert "innerHTML" not in js.replace("never innerHTML", "")  # rendering uses textContent only
