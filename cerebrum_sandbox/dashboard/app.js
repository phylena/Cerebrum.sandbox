"use strict";
// Cerebrum.sandbox dashboard. All data is rendered with textContent (never innerHTML).
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  let KEY = null, ME = null, view = "overview", detail = null, timer = null;
  try { KEY = sessionStorage.getItem("csb-key"); } catch (_) {}

  const rank = { viewer: 1, operator: 2, admin: 3 };
  const can = (role) => ME && rank[ME.role] >= rank[role];

  function el(tag, attrs = {}, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v;
      else if (k === "style") e.style.cssText = v;  // CSSOM: allowed under the strict CSP (no style attributes)
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false)
      e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    return e;
  }
  const pill = (s) => el("span", { class: "pill s-" + String(s).replace(/[^a-z]/g, "") }, s);
  const ago = (t) => { if (!t) return "—"; const s = Date.now() / 1000 - t;
    return s < 60 ? Math.round(s) + "s ago" : s < 3600 ? Math.round(s / 60) + "m ago" :
      s < 86400 ? Math.round(s / 3600) + "h ago" : new Date(t * 1000).toLocaleString(); };
  const bytes = (n) => n == null ? "—" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" :
    n < 1073741824 ? (n / 1048576).toFixed(1) + " MiB" : (n / 1073741824).toFixed(2) + " GiB";
  function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show");
    clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 3500); }

  async function api(method, path, body, raw) {
    const opt = { method, headers: { Authorization: "Bearer " + KEY } };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    if (r.status === 401) { logout("Key rejected"); throw new Error("unauthorized"); }
    if (!r.ok) { let d = r.statusText; try { d = (await r.json()).detail || d; } catch (_) {}
      throw new Error(typeof d === "string" ? d : JSON.stringify(d)); }
    if (raw) return r.text();
    return r.status === 204 ? null : r.json();
  }
  const act = (fn, ok) => async (ev) => { if (ev) ev.preventDefault(); try { await fn(); if (ok) toast(ok); render(); }
    catch (e) { toast("Error: " + e.message); } };

  function table(cols, rows, onclick) {
    return el("table", {}, el("thead", {}, el("tr", {}, cols.map(c => el("th", {}, c[0])))),
      el("tbody", {}, rows.length ? rows.map(r => el("tr", onclick ? { class: "click", onclick: () => onclick(r) } : {},
        cols.map(c => el("td", {}, c[1](r))))) : el("tr", {}, el("td", { colspan: cols.length, class: "muted" }, "Nothing here."))));
  }
  function tile(label, value, sub, frac) {
    return el("div", { class: "tile" }, el("div", { class: "label" }, label), el("div", { class: "value" }, value),
      sub ? el("div", { class: "sub" }, sub) : null,
      frac != null ? el("div", { class: "bar" }, el("i", { style: `width:${Math.min(100, Math.round(frac * 100))}%` })) : null);
  }

  const TABS = [["overview", "Overview"], ["sandboxes", "Sandboxes"], ["jobs", "Jobs"], ["workers", "Workers"],
    ["profiles", "Profiles"], ["events", "Events"], ["network", "Network", "admin"], ["audit", "Audit", "admin"]];

  function renderTabs() {
    const nav = $("#tabs"); nav.replaceChildren();
    for (const [id, label, need] of TABS) if (!need || can(need))
      nav.append(el("button", { class: view === id ? "active" : "", onclick: () => { view = id; detail = null; render(); } }, label));
  }

  // ---- views ---------------------------------------------------------------------------------
  async function overview() {
    const [res, sbs, jobs, evs] = await Promise.all([api("GET", "/api/v1/resources"), api("GET", "/api/v1/sandboxes"),
      api("GET", "/api/v1/jobs?limit=200"), api("GET", "/api/v1/events?limit=50")]);
    const n = (s) => sbs.filter(x => x.state === s).length, u = res.usage, L = res.limits, h = res.host;
    const gpus = h.gpus || [];
    const out = [el("div", { class: "tiles" },
      tile("Running", n("running"), `${n("paused")} paused · ${n("stopped")} stopped`),
      tile("Failed", n("failed"), `${n("terminated")} terminated`),
      tile("CPU reserved", `${u.cpu} / ${L.max_total_cpu}`, `host ${h.cpu_count} vCPU · load ${h.load_avg.map(x => x.toFixed(2)).join(" ")}`, u.cpu / L.max_total_cpu),
      tile("Memory reserved", `${bytes(u.memory_mb * 1048576)}`, `limit ${bytes(L.max_total_memory_mb * 1048576)} · host free ${bytes((h.memory.available_mb || 0) * 1048576)}`, u.memory_mb / L.max_total_memory_mb),
      tile("GPUs", `${u.gpus_assigned} / ${gpus.length}`, gpus.length ? gpus.map(g => g.name).join(", ") : "CPU-only host", gpus.length ? u.gpus_assigned / gpus.length : null),
      tile("Disk free", bytes(h.disk.free_mb * 1048576), `of ${bytes(h.disk.total_mb * 1048576)}`, 1 - h.disk.free_mb / h.disk.total_mb),
      tile("Jobs", jobs.filter(j => j.state === "queued").length + " queued", jobs.filter(j => j.state === "running").length + " running"),
      tile("Workers", res.workers.filter(w => w.state === "online").length + " online", res.workers.length + " registered"))];
    out.push(el("div", { class: "card" }, el("h2", {}, "Recent events"),
      table([["When", r => ago(r.last_ts)], ["Severity", r => pill(r.severity)], ["Kind", r => r.kind],
        ["Target", r => el("code", {}, r.target || "")], ["Message", r => r.message], ["×", r => r.count]], evs.slice(0, 10))));
    return out;
  }

  async function sandboxes() {
    if (detail) return sandboxDetail(detail);
    const [sbs, profiles] = await Promise.all([api("GET", "/api/v1/sandboxes"), api("GET", "/api/v1/profiles")]);
    const out = [];
    if (can("operator")) {
      const prof = el("select", {}, profiles.map(p => el("option", { value: p.name }, p.name)));
      const iso = el("select", {}, el("option", { value: "" }, "profile isolation"), ["container", "gvisor", "microvm"].map(i => el("option", { value: i }, i)));
      const ttl = el("input", { type: "number", min: 10, placeholder: "TTL seconds (optional)" });
      out.push(el("div", { class: "card" }, el("h2", {}, "Create sandbox"), el("form", { class: "inline", onsubmit: act(async () => {
        const body = { profile: prof.value }; if (iso.value) body.isolation = iso.value; if (ttl.value) body.ttl_s = +ttl.value;
        const s = await api("POST", "/api/v1/sandboxes", body); detail = s.id; }, "Sandbox created") }, prof, iso, ttl, el("button", {}, "Create"))));
    }
    out.push(el("div", { class: "card" }, el("h2", {}, `Sandboxes (${sbs.length})`), table([
      ["ID", r => el("code", {}, r.id)], ["State", r => pill(r.state)], ["Profile", r => r.profile],
      ["Isolation", r => r.profile_snapshot.isolation], ["Runtime", r => r.runtime], ["Worker", r => r.worker],
      ["Owner", r => r.owner], ["GPUs", r => (r.gpu_indices || []).join(",") || "—"], ["Created", r => ago(r.created_at)],
      ["Error", r => r.error || ""]], sbs, r => { detail = r.id; render(); })));
    return out;
  }

  async function sandboxDetail(id) {
    const s = await api("GET", `/api/v1/sandboxes/${id}`);
    const get = (p, d = null) => api("GET", p).catch(() => d);
    const running = s.state === "running";
    const [metrics, execs, logs, files, net, snaps] = await Promise.all([get(`/api/v1/sandboxes/${id}/metrics`),
      get(`/api/v1/sandboxes/${id}/executions?limit=20`, []), get(`/api/v1/sandboxes/${id}/logs?tail=200`, { logs: "" }),
      running ? get(`/api/v1/sandboxes/${id}/files`, []) : [], get(`/api/v1/sandboxes/${id}/network?limit=50`, { log: [] }),
      get(`/api/v1/sandboxes/${id}/snapshots`, [])]);
    const op = (verb, label, cls) => el("button", { class: cls || "ghost", onclick: act(() => api("POST", `/api/v1/sandboxes/${id}/${verb}`), label + " ok") }, label);
    const actions = el("div", { class: "actions" }, el("button", { class: "ghost", onclick: () => { detail = null; render(); } }, "← back"));
    if (can("operator")) {
      if (s.state === "running") actions.append(op("pause", "Pause"), op("stop", "Stop"), op("snapshots", "Snapshot"), op("processes/kill", "Kill processes"));
      if (s.state === "paused") actions.append(op("resume", "Resume"), op("stop", "Stop"));
      if (s.state === "stopped") actions.append(op("start", "Start"));
      if (s.state !== "terminated") actions.append(el("button", { class: "danger", onclick: act(async () => {
        if (!confirm("Destroy sandbox " + id + " and its workspace?")) throw new Error("cancelled");
        await api("DELETE", `/api/v1/sandboxes/${id}`); }, "Destroyed") }, "Destroy"));
    }
    const p = s.profile_snapshot;
    const out = [el("div", { class: "card" }, actions, el("h2", {}, "Sandbox ", el("code", {}, id), " ", pill(s.state)),
      el("div", { class: "grid2" },
        el("div", {}, table([["Field", r => r[0]], ["Value", r => r[1]]], [["Profile", s.profile], ["Isolation", p.isolation],
          ["Runtime / worker", `${s.runtime} / ${s.worker}`], ["Owner", s.owner], ["Limits", `${p.cpu} CPU · ${p.memory_mb} MB · ${p.pids} pids`],
          ["Workspace", `${p.workspace_mb} MB · ${p.persistent_workspace ? "persistent" : "temporary"}`],
          ["Network", p.network.mode + (p.network.allowed_domains.length ? ": " + p.network.allowed_domains.join(", ") : "")],
          ["GPUs", (s.gpu_indices || []).join(",") || "none"], ["Created", ago(s.created_at)], ["Expires", s.expires_at ? ago(s.expires_at) : "never"]])),
        el("div", {}, el("h3", {}, "Live metrics"), el("pre", {}, JSON.stringify(metrics && metrics.live || "not available", null, 2)),
          el("p", { class: "muted" }, "Workspace used: " + bytes(metrics && metrics.workspace_used_bytes)))))];
    if (can("operator") && running) {
      const argv = el("input", { style: "flex:1;min-width:280px", class: "mono", value: '["python3", "-c", "print(6*7)"]' });
      const res = el("pre", {}, "");
      out.push(el("div", { class: "card" }, el("h2", {}, "Run a command"), el("p", { class: "muted" }, "An argv JSON array, executed inside the sandbox (never on the host)."),
        el("form", { class: "inline", onsubmit: async (e) => { e.preventDefault(); try {
          const r = await api("POST", `/api/v1/sandboxes/${id}/execute`, { argv: JSON.parse(argv.value) });
          res.textContent = `[${r.status} · exit ${r.exit_code} · ${r.duration_s}s${r.truncated ? " · truncated" : ""}]\n${r.stdout}${r.stderr ? "\n--- stderr ---\n" + r.stderr : ""}`;
        } catch (err) { res.textContent = "Error: " + err.message; } } }, argv, el("button", {}, "Run")), res));
    }
    out.push(el("div", { class: "grid2" },
      el("div", { class: "card" }, el("h2", {}, "Files (/workspace)"), table([["Name", r => el("code", {}, r.name)], ["Type", r => r.type], ["Size", r => bytes(r.size)]], files)),
      el("div", { class: "card" }, el("h2", {}, "Snapshots"), table([["ID", r => el("code", {}, r.id)], ["Label", r => r.label], ["Size", r => bytes(r.size)], ["When", r => ago(r.created_at)],
        ["", r => can("operator") && running ? el("button", { class: "ghost", onclick: act(() => api("POST", `/api/v1/sandboxes/${id}/restore`, { snapshot_id: r.id }), "Restored") }, "Restore") : ""]], snaps))));
    out.push(el("div", { class: "card" }, el("h2", {}, "Execution history"), table([["When", r => ago(r.created_at)], ["Status", r => pill(r.status)], ["Exit", r => r.exit_code],
      ["Command", r => el("code", {}, r.argv)], ["Duration", r => r.duration_s + "s"], ["Output", r => el("pre", {}, (r.stdout || "") + (r.stderr ? "\n" + r.stderr : ""))]], execs)));
    out.push(el("div", { class: "grid2" },
      el("div", { class: "card" }, el("h2", {}, "Logs"), el("pre", {}, logs.logs || "(empty)")),
      el("div", { class: "card" }, el("h2", {}, "Network log"), table([["When", r => ago(r.ts)], ["Decision", r => pill(r.decision)], ["Host", r => `${r.host}:${r.port}`], ["Reason", r => r.reason || ""]], net.log))));
    return out;
  }

  async function jobs() {
    const list = await api("GET", "/api/v1/jobs?limit=200");
    const out = [];
    if (can("operator")) {
      const argv = el("input", { class: "mono", style: "flex:1;min-width:260px", value: '["python3", "-c", "print(1)"]' });
      const prof = el("input", { value: "basic", size: 12 }), prio = el("input", { type: "number", min: 0, max: 9, value: 5, style: "width:70px" });
      out.push(el("div", { class: "card" }, el("h2", {}, "Submit job"), el("form", { class: "inline", onsubmit: act(() =>
        api("POST", "/api/v1/jobs", { argv: JSON.parse(argv.value), profile: prof.value, priority: +prio.value }), "Job queued") },
        argv, prof, prio, el("button", {}, "Submit"))));
    }
    out.push(el("div", { class: "card" }, el("h2", {}, "Job queue"), table([["ID", r => el("code", {}, r.id)], ["State", r => pill(r.state)],
      ["Priority", r => r.priority], ["Profile", r => r.spec.profile], ["Command", r => el("code", {}, JSON.stringify(r.spec.argv))],
      ["Attempts", r => `${r.attempts} / ${r.max_retries + 1}`], ["Waiting for", r => r.wait_reason || ""], ["Result", r => r.error || (r.result ? `exit ${r.result.exit_code}` : "")],
      ["Created", r => ago(r.created_at)], ["", r => can("operator") && !["succeeded", "failed", "cancelled"].includes(r.state) ?
        el("button", { class: "ghost", onclick: act(() => api("DELETE", `/api/v1/jobs/${r.id}`), "Cancelled") }, "Cancel") : ""]], list)));
    return out;
  }

  async function workers() {
    const [ws, rts] = await Promise.all([api("GET", "/api/v1/workers"), api("GET", "/api/v1/runtimes")]);
    const out = [el("div", { class: "card" }, el("h2", {}, "Local runtimes"), table([["Runtime", r => r.name], ["Isolation", r => r.isolation],
      ["Health", r => pill(r.ok ? "ok" : "failed")], ["Detail", r => r.detail]], rts))];
    out.push(el("div", { class: "card" }, el("h2", {}, "Workers"), el("div", { class: "actions" }, el("button", { class: "ghost", onclick: act(() => api("GET", "/api/v1/workers?refresh=true"), "Refreshed") }, "Refresh health")),
      table([["Name", r => r.name], ["State", r => pill(r.state)], ["URL", r => el("code", {}, r.url)], ["Runtimes", r => (r.caps.runtimes || []).join(", ")],
        ["Capacity", r => `${r.caps.cpu} CPU · ${r.caps.memory_mb} MB · ${r.caps.gpus} GPU`], ["Last seen", r => ago(r.last_seen)], ["Error", r => r.last_error || ""],
        ["", r => can("admin") ? el("button", { class: "ghost", onclick: act(() => api("DELETE", `/api/v1/workers/${r.name}`), "Removed") }, "Remove") : ""]], ws)));
    if (can("admin")) {
      const name = el("input", { placeholder: "name" }), url = el("input", { placeholder: "https://worker:8300", size: 30 }), key = el("input", { type: "password", placeholder: "worker operator key" });
      out.push(el("div", { class: "card" }, el("h2", {}, "Register worker"), el("form", { class: "inline", onsubmit: act(() =>
        api("POST", "/api/v1/workers", { name: name.value, url: url.value, key: key.value }), "Worker registered") }, name, url, key, el("button", {}, "Register"))));
    }
    return out;
  }

  async function profiles() {
    const list = await api("GET", "/api/v1/profiles");
    const out = [el("div", { class: "card" }, el("h2", {}, "Profiles"), table([["Name", r => el("b", {}, r.name)], ["", r => r.builtin ? pill("builtin") : pill("custom")],
      ["Isolation", r => r.isolation], ["CPU", r => r.cpu], ["Memory", r => r.memory_mb + " MB"], ["PIDs", r => r.pids],
      ["Workspace", r => `${r.workspace_mb} MB ${r.persistent_workspace ? "(persistent)" : ""}`], ["Network", r => r.network.mode + (r.network.allowed_domains.length ? ": " + r.network.allowed_domains.join(", ") : "")],
      ["GPUs", r => r.gpus], ["Timeout", r => `${r.default_timeout_s}s / ${r.max_timeout_s}s`], ["Description", r => r.description]], list))];
    if (can("admin")) {
      const ta = el("textarea", {}, JSON.stringify({ name: "my-profile", description: "", isolation: "gvisor", cpu: 1, memory_mb: 1024,
        network: { mode: "allowlist", allowed_domains: ["pypi.org", "files.pythonhosted.org"], allowed_ports: [443] } }, null, 2));
      out.push(el("div", { class: "card" }, el("h2", {}, "Create or replace a custom profile"), ta,
        el("div", { class: "actions" }, el("button", { onclick: act(() => api("POST", "/api/v1/profiles", JSON.parse(ta.value)), "Profile saved") }, "Save"))));
    }
    return out;
  }

  async function events() {
    const list = await api("GET", "/api/v1/events?limit=500");
    return [el("div", { class: "card" }, el("h2", {}, "Events & security"), table([["First", r => ago(r.ts)], ["Last", r => ago(r.last_ts)], ["Severity", r => pill(r.severity)],
      ["Kind", r => r.kind], ["Target", r => el("code", {}, r.target || "")], ["Message", r => r.message], ["Count", r => r.count]], list))];
  }

  async function network() {
    const d = await api("GET", "/api/v1/network/log?limit=500");
    return [el("div", { class: "card" }, el("h2", {}, "Egress"), el("p", { class: "muted" }, d.stats ? `allowed ${d.stats.allowed} · denied ${d.stats.denied} (since start)` : "Egress proxy disabled (allowlist profiles are refused)."),
      table([["When", r => ago(r.ts)], ["Sandbox", r => el("code", {}, r.sandbox_id || r.src)], ["Decision", r => pill(r.decision)], ["Method", r => r.method],
        ["Host", r => `${r.host}:${r.port}`], ["Reason", r => r.reason || ""], ["Up/down", r => `${bytes(r.bytes_up)} / ${bytes(r.bytes_down)}`]], d.log))];
  }

  async function audit() {
    const list = await api("GET", "/api/v1/audit?limit=500");
    return [el("div", { class: "card" }, el("h2", {}, "Audit log"), table([["When", r => ago(r.ts)], ["Actor", r => r.actor], ["Action", r => r.action],
      ["Target", r => el("code", {}, r.target || "")], ["Outcome", r => pill(r.outcome)], ["Detail", r => el("code", {}, r.detail || "")]], list))];
  }

  const VIEWS = { overview, sandboxes, jobs, workers, profiles, events, network, audit };

  async function render() {
    if (!ME) return;
    renderTabs();
    const root = $("#views");
    try { root.replaceChildren(...await VIEWS[view]()); }
    catch (e) { if (e.message !== "unauthorized") root.replaceChildren(el("div", { class: "card error" }, "Could not load: " + e.message)); }
  }

  async function login(key) {
    KEY = key;
    try { ME = await api("GET", "/api/v1/whoami"); } catch (e) { ME = null; $("#login-error").textContent = "Could not sign in: " + e.message; return; }
    try { sessionStorage.setItem("csb-key", key); } catch (_) {}
    $("#login").hidden = true; $("#views").hidden = false;
    $("#who").replaceChildren(el("span", {}, `${ME.name} · ${ME.role}${ME.owner ? " · owner " + ME.owner : ""} `),
      el("button", { class: "ghost", onclick: () => logout() }, "Sign out"));
    render(); clearInterval(timer); timer = setInterval(() => { if (!detail && !document.hidden) render(); }, 10000);
  }
  function logout(msg) {
    KEY = ME = null; try { sessionStorage.removeItem("csb-key"); } catch (_) {}
    clearInterval(timer); $("#login").hidden = false; $("#views").hidden = true; $("#tabs").replaceChildren(); $("#who").replaceChildren();
    $("#login-error").textContent = msg || "";
  }
  $("#login-form").addEventListener("submit", (e) => { e.preventDefault(); login($("#key").value.trim()); });
  if (KEY) login(KEY);
})();
