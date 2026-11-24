#!/usr/bin/env python3
"""Cerebrum.sandbox guest agent. Runs as PID-1's child inside a Firecracker microVM and executes
commands for the host over vsock. Standard library only (it ships inside the rootfs).

Protocol: one JSON object per line, one request per connection.
  {"op":"ping"}                                        -> {"ok":true}
  {"op":"exec","argv":[..],"workdir":"/workspace","env":{..},"timeout_s":N,"max_output_bytes":N}
       -> {"exit_code":int,"stdout":str,"stderr":str,"timed_out":bool,"truncated":bool,"duration_s":float}
Commands are argv vectors (no shell string), run in their own process group, as an unprivileged
user when started as root, with a minimal environment (the host's/agent's environment is not passed).
"""
import json
import os
import posixpath
import resource
import signal
import socket
import subprocess
import sys
import threading
import time

MAX_REQUEST = 1 << 20
BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/sandbox", "LANG": "C.UTF-8"}


class Agent:
    def __init__(self, workspace="/workspace", run_as=(10001, 10001), nproc=None):
        self.workspace, self.run_as, self.nproc = workspace, run_as, nproc

    def _workdir(self, wd):
        wd = posixpath.normpath(wd or self.workspace)
        if wd != self.workspace and not wd.startswith(self.workspace.rstrip("/") + "/"):
            raise ValueError(f"workdir must be inside {self.workspace}")
        return wd

    def _preexec(self):
        def f():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
            if self.nproc:
                resource.setrlimit(resource.RLIMIT_NPROC, (self.nproc, self.nproc))
            if self.run_as and os.getuid() == 0:
                os.setgroups([])
                os.setgid(self.run_as[1])
                os.setuid(self.run_as[0])
        return f

    def handle(self, req):
        op = req.get("op")
        if op == "ping":
            return {"ok": True}
        if op != "exec":
            return {"error": f"unknown op {op!r}"}
        argv, env = req.get("argv"), req.get("env") or {}
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and "\0" not in a for a in argv):
            return {"error": "argv must be a non-empty list of strings"}
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            return {"error": "env must be a string map"}
        try:
            wd = self._workdir(req.get("workdir"))
        except ValueError as e:
            return {"error": str(e)}
        stdin = None
        if req.get("stdin_b64") is not None:
            import base64
            try:
                stdin = base64.b64decode(req["stdin_b64"], validate=True)
            except (ValueError, TypeError):
                return {"error": "stdin_b64 is not valid base64"}
        timeout = max(1, int(req.get("timeout_s") or 60))
        limit = max(1, int(req.get("max_output_bytes") or 262144))
        t0 = time.monotonic()
        try:
            p = subprocess.Popen(argv, cwd=wd, env={**BASE_ENV, **env},
                                 stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                 preexec_fn=self._preexec())
        except (OSError, subprocess.SubprocessError) as e:
            return {"exit_code": 127, "stdout": "", "stderr": f"cannot start: {e}\n", "timed_out": False,
                    "truncated": False, "duration_s": 0.0}
        bufs, over = {"o": bytearray(), "e": bytearray()}, {"o": False, "e": False}

        def drain(stream, k):  # bounded memory: keep the first `limit` bytes, discard the rest
            for chunk in iter(lambda: stream.read(8192), b""):
                room = limit - len(bufs[k])
                if room > 0:
                    bufs[k] += chunk[:room]
                if len(chunk) > room:
                    over[k] = True

        if stdin is not None:
            def feed():
                try:
                    p.stdin.write(stdin)
                except OSError:
                    pass
                finally:
                    try:
                        p.stdin.close()
                    except OSError:
                        pass
            threading.Thread(target=feed, daemon=True).start()
        ts = [threading.Thread(target=drain, args=(p.stdout, "o"), daemon=True),
              threading.Thread(target=drain, args=(p.stderr, "e"), daemon=True)]
        for t in ts:
            t.start()
        timed_out = False
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        # always kill the whole process group: children that outlive the command are runaway processes
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        for t in ts:
            t.join(timeout=5)
        return {"exit_code": 124 if timed_out else p.returncode,
                "stdout": bufs["o"].decode("utf-8", "replace"), "stderr": bufs["e"].decode("utf-8", "replace"),
                "timed_out": timed_out, "truncated": over["o"] or over["e"],
                "duration_s": round(time.monotonic() - t0, 3)}


def serve_connection(conn, agent):
    with conn:
        buf = b""
        while b"\n" not in buf and len(buf) < MAX_REQUEST:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        try:
            resp = agent.handle(json.loads(buf.split(b"\n", 1)[0]))
        except (ValueError, TypeError) as e:
            resp = {"error": f"bad request: {e}"}
        conn.sendall(json.dumps(resp).encode() + b"\n")


def serve(port, agent):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, port))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=serve_connection, args=(conn, agent), daemon=True).start()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 5252, Agent())
