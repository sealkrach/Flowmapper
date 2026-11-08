/* FlowMapper UI — Cytoscape graph of Illumio flows.
 * Works against the FastAPI backend, or fully offline when window.FLOWMAPPER_EMBEDDED holds a dataset. */
(function () {
  "use strict";

  const EMBEDDED = window.FLOWMAPPER_EMBEDDED || null;
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const ROLE_GROUP = {
    web: "web", edge: "web",
    api: "app", app: "app", worker: "app",
    database: "data", storage: "data",
    cache: "mid", messaging: "mid", search: "mid", coordination: "mid",
    directory: "infra", infra: "infra", monitoring: "infra", security: "infra", platform: "infra", admin: "infra", mail: "infra",
  };
  const ROLE_SHAPE = {
    database: "barrel", storage: "barrel", cache: "hexagon", messaging: "diamond", search: "hexagon", coordination: "hexagon",
    edge: "round-tag", web: "round-rectangle", api: "round-rectangle", app: "round-rectangle", worker: "round-rectangle",
    directory: "octagon", infra: "octagon", monitoring: "octagon", security: "octagon", platform: "octagon", admin: "octagon", mail: "octagon",
    client: "ellipse", unknown: "ellipse",
  };
  const AGENT_SERVICES = new Set(["ssh", "rdp", "winrm", "winrm-https", "vnc", "telnet", "zabbix-agent", "node-exporter", "nrpe", "msrpc", "netbios-ns", "netbios-dgm", "netbios-ssn", "icmp", "snmp", "kubelet", "kube-proxy"]);
  const DECISION_LABEL = { allowed: "allowed", potentially_blocked: "potentially blocked", blocked: "blocked", unknown: "unknown" };
  const SEVERITY = { allowed: 0, unknown: 1, potentially_blocked: 2, blocked: 3 };

  const state = {
    level: "app",
    raw: { app: null, workload: null },
    cy: null,
    threadId: null,
    stats: null,
    apps: [],
  };

  // ------------------------------------------------------------------ helpers
  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  function toast(msg, ms = 2600) {
    const el = $("#toast");
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(el._t);
    el._t = setTimeout(() => (el.hidden = true), ms);
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function fmt(n) {
    return Number(n || 0).toLocaleString("en-US");
  }
  async function api(path, opts = {}) {
    const res = await fetch(path, opts);
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (_) { /* ignore */ }
      throw new Error(detail);
    }
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res.text();
  }
  function download(name, content, type = "text/plain") {
    if (EMBEDDED) {
      // Static snapshots may run in sandboxed viewers that refuse downloads: copy instead.
      if (content.startsWith("data:")) {
        openDetails(`<h2>PNG export</h2><div class="kind">Long-press / right-click the image to save it.</div><img src="${content}" alt="graph" style="max-width:100%;border:1px solid var(--border);border-radius:6px">`);
        return;
      }
      navigator.clipboard.writeText(content).then(() => toast(`${name} copied to the clipboard`), () => openDetails(`<h2>${esc(name)}</h2><pre>${esc(content)}</pre>`));
      return;
    }
    const a = document.createElement("a");
    a.href = content.startsWith("data:") ? content : URL.createObjectURL(new Blob([content], { type }));
    a.download = name;
    a.click();
  }

  // ------------------------------------------------------------------ filters
  function readFilters() {
    const decisions = new Set($$("[data-decision]").filter((c) => c.checked).map((c) => c.dataset.decision));
    const ports = new Set(($("#f-ports").value || "").split(/[,\s;]+/).map((p) => parseInt(p, 10)).filter((p) => !isNaN(p)));
    const minLog = parseFloat($("#f-min").value);
    return {
      env: $("#f-env").value,
      app: $("#f-app").value,
      search: ($("#f-search").value || "").trim().toLowerCase(),
      hideInfra: $("#f-hide-infra").checked,
      hideShared: $("#f-hide-shared").checked,
      hideExternal: $("#f-hide-external").checked,
      hideAgents: $("#f-hide-agents").checked,
      decisions,
      ports,
      minConnections: Math.round(Math.pow(10, minLog)),
      tiers: $("#f-tiers").checked,
      labels: $("#f-labels").checked,
    };
  }

  /* One raw edge (all services between two nodes) becomes up to three drawn edges, one per
   * policy outcome, so a blocked ssh attempt never repaints the main https traffic red. */
  function edgesAfterFilter(edge, f) {
    const services = (edge.data.services || []).filter((s) => {
      if (!f.decisions.has(s.decision)) return false;
      if (f.ports.size && !f.ports.has(parseInt((s.service || "").split("/")[1], 10))) return false;
      if (f.hideAgents && AGENT_SERVICES.has(s.name)) return false;
      return true;
    });
    const groups = { allowed: [], potentially_blocked: [], blocked: [] };
    for (const s of services) groups[s.decision === "unknown" ? "allowed" : s.decision].push(s);
    const out = [];
    for (const [decision, list] of Object.entries(groups)) {
      if (!list.length) continue;
      const connections = list.reduce((a, s) => a + s.connections, 0);
      if (connections < f.minConnections) continue;
      const names = list.slice(0, 3).map((s) => (s.name.startsWith("tcp/") || s.name.startsWith("udp/") ? s.service : s.name));
      const label = names.join(", ") + (list.length > 3 ? ` +${list.length - 3}` : "");
      const color = { allowed: cssVar("--allowed"), potentially_blocked: cssVar("--potentially"), blocked: cssVar("--blocked") }[decision];
      const lineStyle = decision === "blocked" ? "dashed" : decision === "potentially_blocked" ? "dotted" : "solid";
      out.push({ data: { ...edge.data, id: decision === "allowed" ? edge.data.id : `${edge.data.id}#${decision}`, services: list, connections, decision, label, color, lineStyle, width: 1 + Math.log10(Math.max(connections, 1)) } });
    }
    return out;
  }

  function applyFilters(raw, f) {
    const nodes = raw.elements.nodes;
    const edges = raw.elements.edges;
    const appNodes = nodes.filter((n) => n.data.type === "app");
    const keep = new Set();
    for (const n of appNodes) {
      const d = n.data;
      if (f.env && d.kind === "labeled" && d.env !== f.env) continue;
      if (f.hideExternal && d.kind === "unmanaged") continue;
      if (d.shared && f.hideShared) continue;
      if (d.shared && f.hideInfra && d.shared_kind === "infra") continue;
      keep.add(d.id);
    }
    // Focus: keep the application and its direct neighbours (computed on app-level edges).
    if (f.app) {
      const focus = appNodes.filter((n) => n.data.group === f.app).map((n) => n.data.id);
      const appEdges = (state.raw.app ? state.raw.app.elements.edges : []).flatMap((e) => edgesAfterFilter(e, f));
      const neighbours = new Set(focus);
      for (const e of appEdges) {
        if (focus.includes(e.data.source) && keep.has(e.data.target)) neighbours.add(e.data.target);
        if (focus.includes(e.data.target) && keep.has(e.data.source)) neighbours.add(e.data.source);
      }
      for (const id of Array.from(keep)) if (!neighbours.has(id)) keep.delete(id);
    }
    const outNodes = [];
    const nodeIds = new Set();
    for (const n of nodes) {
      const d = n.data;
      if (d.type === "env") continue; // added later, only if used
      if (d.type === "app" && !keep.has(d.id)) continue;
      if (d.type === "workload" && !keep.has(d.parent)) continue;
      const data = { ...d };
      if (d.type === "workload") {
        const grp = ROLE_GROUP[d.role] || "unknown";
        data.color = cssVar(`--role-${grp}`);
        data.shape = ROLE_SHAPE[d.role] || "ellipse";
        data.focus = !!f.app && d.group === f.app;
      } else if (d.type === "app") {
        data.color = d.kind === "unmanaged" ? cssVar("--role-unknown") : d.shared ? cssVar("--role-infra") : d.kind === "cluster" ? cssVar("--role-app") : cssVar("--role-web");
        data.size = 36 + 8 * Math.sqrt(d.members || 1);
      }
      outNodes.push({ data, classes: d.type === "app" && d.kind === "cluster" ? "cluster" : "" });
      nodeIds.add(d.id);
    }
    const outEdges = [];
    const focusIds = new Set(outNodes.filter((n) => f.app && (n.data.group === f.app)).map((n) => n.data.id));
    for (const e of edges) {
      if (!nodeIds.has(e.data.source) || !nodeIds.has(e.data.target)) continue;
      // In focus mode only draw the flows that touch the focused application.
      if (f.app && !focusIds.has(e.data.source) && !focusIds.has(e.data.target)) continue;
      outEdges.push(...edgesAfterFilter(e, f));
    }
    const envs = new Set(outNodes.filter((n) => n.data.type === "app").map((n) => n.data.env));
    const envNodes = nodes.filter((n) => n.data.type === "env" && envs.has(n.data.label)).map((n) => ({ data: { ...n.data } }));
    return { nodes: [...envNodes, ...outNodes], edges: outEdges };
  }

  // ------------------------------------------------------------------ cytoscape
  function buildStyle() {
    const text = cssVar("--text-primary"), muted = cssVar("--text-muted"), secondary = cssVar("--text-secondary");
    const s0 = cssVar("--surface-0"), s1 = cssVar("--surface-1"), s2 = cssVar("--surface-2"), border = cssVar("--border");
    return [
      { selector: "node", style: { label: "data(label)", "font-size": 11, color: text, "text-wrap": "wrap", "text-max-width": 130, "min-zoomed-font-size": 4, "text-outline-width": 2, "text-outline-color": s0, "text-outline-opacity": 0.85 } },
      { selector: 'node[type="env"]', style: { shape: "round-rectangle", "background-color": s1, "background-opacity": 0.55, "border-width": 1, "border-style": "dashed", "border-color": cssVar("--env-border"), "text-valign": "top", "text-halign": "center", "font-size": 13, "font-weight": 700, color: muted, padding: 28, "text-margin-y": -4 } },
      { selector: 'node[type="app"]:childless', style: { shape: "round-rectangle", width: "data(size)", height: "data(size)", "background-color": "data(color)", "background-opacity": 0.9, "border-width": 2, "border-color": "data(color)", "text-valign": "bottom", "text-margin-y": 6, "font-weight": 600 } },
      { selector: 'node[type="app"]:parent', style: { shape: "round-rectangle", "background-color": s2, "background-opacity": 0.75, "border-width": 2, "border-color": "data(color)", "text-valign": "top", "text-halign": "center", "font-weight": 700, "font-size": 12, padding: 18, "text-margin-y": -2 } },
      { selector: 'node[type="app"][kind="unmanaged"]', style: { "border-style": "dotted" } },
      { selector: "node.cluster", style: { "border-style": "dashed" } },
      { selector: 'node[type="app"][?shared]', style: { "border-style": "double", "border-width": 4 } },
      { selector: 'node[type="workload"]', style: { shape: "data(shape)", width: 34, height: 34, "background-color": "data(color)", "border-width": 1.5, "border-color": s1, "text-valign": "bottom", "text-margin-y": 4, "font-size": 10 } },
      { selector: 'node[type="workload"][?shared]', style: { "border-width": 3, "border-style": "double", "border-color": cssVar("--role-infra") } },
      { selector: 'node[type="workload"][!managed]', style: { "background-opacity": 0.55, "border-style": "dotted", "border-color": muted } },
      { selector: "edge", style: { "curve-style": "bezier", "control-point-step-size": 30, "target-arrow-shape": "triangle", "arrow-scale": 0.8, width: "data(width)", "line-color": "data(color)", "target-arrow-color": "data(color)", "line-style": "data(lineStyle)", "line-opacity": 0.8, label: "", "font-size": 9, color: secondary, "text-rotation": "autorotate", "text-background-color": s0, "text-background-opacity": 0.9, "text-background-padding": 2, "text-background-shape": "round-rectangle" } },
      { selector: "edge.labels, edge:selected, edge.hover", style: { label: "data(label)" } },
      { selector: 'node[ai="pending"]', style: { "border-color": cssVar("--accent"), "border-width": 3, "border-style": "solid" } },
      { selector: "node.diff-added", style: { "border-color": cssVar("--role-data"), "border-width": 4, "border-style": "solid" } },
      { selector: "node.diff-removed", style: { "border-color": cssVar("--blocked"), "border-width": 4, "border-style": "solid" } },
      { selector: "edge.diff-added", style: { "line-color": cssVar("--role-data"), "target-arrow-color": cssVar("--role-data"), "line-opacity": 1, width: 4, "z-index": 8 } },
      { selector: "edge.diff-removed", style: { "line-color": cssVar("--blocked"), "target-arrow-color": cssVar("--blocked"), "line-opacity": 1, width: 4, "z-index": 8 } },
      { selector: "edge.diff-changed", style: { "line-color": cssVar("--potentially"), "target-arrow-color": cssVar("--potentially"), "line-opacity": 1, width: 4, "z-index": 8 } },
      { selector: ".dim", style: { opacity: 0.12 } },
      { selector: ".match", style: { "border-color": cssVar("--accent"), "border-width": 4, "z-index": 10 } },
      { selector: "node:selected", style: { "border-color": cssVar("--accent"), "border-width": 4, "overlay-opacity": 0.08, "overlay-color": cssVar("--accent") } },
      { selector: "edge:selected", style: { width: 4, "line-opacity": 1, "z-index": 9 } },
      { selector: "node[?focus]", style: { "z-index": 5 } },
    ];
  }

  function layoutOptions() {
    return {
      name: "fcose", quality: "default", randomize: true, animate: false, fit: true, padding: 30,
      nodeDimensionsIncludeLabels: true, packComponents: true, uniformNodeDimensions: false,
      nodeRepulsion: () => (state.level === "app" ? 9000 : 5500), idealEdgeLength: () => (state.level === "app" ? 140 : 80),
      edgeElasticity: () => 0.2, nestingFactor: 0.1, gravity: 0.25, gravityRange: 2.5, gravityCompound: 1.2, gravityRangeCompound: 1.5,
      numIter: 2500, tile: true, tilingPaddingVertical: 18, tilingPaddingHorizontal: 18,
    };
  }

  /* Deterministic "architecture diagram" layout for the workload level:
   * environments side by side → applications shelf-packed inside → workloads in tier rows. */
  function tieredLayout(cy) {
    const GAP_X = 78, GAP_Y = 84, PAD = 34, LABEL = 26, APP_GAP = 46, ENV_GAP = 110, ENV_PAD = 50;
    const apps = {};
    cy.nodes('[type="app"]').forEach((a) => { apps[a.id()] = { id: a.id(), env: a.data("env"), tiers: {}, w: 70, h: 60 }; });
    cy.nodes('[type="workload"]').forEach((n) => {
      const app = apps[n.data("parent")];
      if (!app) return;
      const t = n.data("tier") == null ? 0 : n.data("tier");
      (app.tiers[t] = app.tiers[t] || []).push(n);
    });
    const order = { web: 0, app: 1, mid: 2, data: 3, infra: 4, unknown: 5 };
    for (const app of Object.values(apps)) {
      app.rows = Object.keys(app.tiers).map(Number).sort((a, b) => a - b).map((t) => app.tiers[t].sort((a, b) => (order[ROLE_GROUP[a.data("role")] || "unknown"] - order[ROLE_GROUP[b.data("role")] || "unknown"]) || a.data("label").localeCompare(b.data("label"))));
      if (app.rows.length) {
        const cols = Math.max(...app.rows.map((r) => r.length));
        app.w = Math.max(70, cols * GAP_X + PAD * 2);
        app.h = app.rows.length * GAP_Y + PAD * 2 + LABEL;
      }
    }
    // Shelf-pack applications inside each environment, then environments on the canvas,
    // both aiming for a landscape aspect ratio so the whole picture fits a screen.
    const shelfPack = (items, gap, aspect, keepOrder = false) => {
      if (!keepOrder) items.sort((a, b) => b.h - a.h || b.w - a.w);
      const area = items.reduce((s, it) => s + (it.w + gap) * (it.h + gap), 0);
      const maxW = Math.max(Math.sqrt(area * aspect), ...items.map((it) => it.w));
      let x = 0, y = 0, rowH = 0, totalW = 0;
      for (const it of items) {
        if (x > 0 && x + it.w > maxW) { x = 0; y += rowH + gap; rowH = 0; }
        it.x = x; it.y = y;
        x += it.w + gap; rowH = Math.max(rowH, it.h); totalW = Math.max(totalW, x - gap);
      }
      return { w: totalW, h: y + rowH };
    };
    const envs = {};
    for (const app of Object.values(apps)) (envs[app.env] = envs[app.env] || []).push(app);
    const envBoxes = Object.keys(envs).map((env) => {
      const size = shelfPack(envs[env], APP_GAP, 1.4);
      return { env, apps: envs[env], w: size.w + ENV_PAD * 2, h: size.h + ENV_PAD * 2 };
    });
    // external IP lists first (traffic usually flows from them), unlabeled clusters last
    envBoxes.sort((a, b) => (b.env === "external") - (a.env === "external") || (a.env === "unlabeled") - (b.env === "unlabeled") || a.env.localeCompare(b.env));
    const pinned = envBoxes.map((e) => ({ ...e }));
    shelfPack(pinned, ENV_GAP, 1.7, true);
    const pos = {};
    for (const box of pinned) {
      for (const app of box.apps) {
        app.x = box.x + ENV_PAD + app.x; app.y = box.y + ENV_PAD + app.y;
        if (!app.rows.length) { pos[app.id] = { x: app.x + app.w / 2, y: app.y + app.h / 2 }; continue; }
        app.rows.forEach((row, r) => {
          const rowW = row.length * GAP_X;
          row.forEach((n, c) => { pos[n.id()] = { x: app.x + (app.w - rowW) / 2 + (c + 0.5) * GAP_X, y: app.y + LABEL + PAD + (r + 0.5) * GAP_Y }; });
        });
      }
    }
    cy.nodes().forEach((n) => { if (pos[n.id()]) n.position(pos[n.id()]); });
    cy.fit(undefined, 30);
  }

  function runLayout(f) {
    if (state.level === "workload" && f.tiers) tieredLayout(state.cy);
    else state.cy.layout(layoutOptions()).run();
  }

  function render() {
    const raw = state.raw[state.level];
    if (!raw) return;
    const f = readFilters();
    const elements = applyFilters(raw, f);
    const cy = state.cy;
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements.nodes);
      cy.add(elements.edges);
      cy.edges().toggleClass("labels", f.labels);
    });
    runLayout(f);
    applySearch(f.search);
    applyDiffHighlight();
    $("#empty-state").hidden = true;
    const shownApps = cy.nodes('[type="app"]').length, shownWl = cy.nodes('[type="workload"]').length;
    $("#dataset-summary").textContent = `${fmt(state.stats.flows)} flows · ${fmt(state.stats.workloads)} workloads · ${fmt(state.stats.groups)} applications — shown: ${shownApps} applications${state.level === "workload" ? `, ${shownWl} workloads` : ""}, ${cy.edges().length} aggregated flows`;
  }

  function applySearch(q) {
    const cy = state.cy;
    cy.elements().removeClass("dim match");
    if (!q) return;
    const hits = cy.nodes().filter((n) => {
      const d = n.data();
      if (d.type === "env") return false;
      return (d.label || "").toLowerCase().includes(q) || (d.ips || []).some((ip) => ip.includes(q)) || (d.group || "").toLowerCase().includes(q);
    });
    if (!hits.length) return;
    const keep = hits.union(hits.neighborhood()).union(hits.ancestors()).union(hits.descendants());
    cy.elements().difference(keep).addClass("dim");
    hits.addClass("match");
  }

  function initCy() {
    state.cy = cytoscape({ container: $("#cy"), style: buildStyle(), wheelSensitivity: 0.25, minZoom: 0.1, maxZoom: 4, boxSelectionEnabled: true });
    const cy = state.cy;
    cy.on("tap", "node", (evt) => showNode(evt.target));
    cy.on("tap", "edge", (evt) => showEdge(evt.target));
    cy.on("tap", (evt) => { if (evt.target === cy) clearDetails(); });
    cy.on("mouseover", "edge", (evt) => evt.target.addClass("hover"));
    cy.on("mouseout", "edge", (evt) => evt.target.removeClass("hover"));
    cy.on("dbltap", 'node[type="app"]', (evt) => focusApp(evt.target.data("group")));
  }

  // ------------------------------------------------------------------ data loading
  async function loadLevel(level) {
    if (EMBEDDED) return EMBEDDED.graphs[level];
    return api(`api/graph?level=${level}&hide_infra=false&hide_shared=false&hide_unmanaged=false&min_connections=1`);
  }
  async function reloadAll() {
    try {
      const [app, workload, apps] = await Promise.all([loadLevel("app"), loadLevel("workload"), EMBEDDED ? EMBEDDED.apps : api("api/apps")]);
      state.raw = { app, workload };
      state.stats = app.meta.stats;
      state.apps = apps;
      fillSelects();
      render();
      refreshProposalCount();
    } catch (err) {
      if (!/No flows loaded/.test(err.message)) toast(`Error: ${err.message}`);
      $("#empty-state").hidden = false;
    }
  }
  function fillSelects() {
    const envSel = $("#f-env"), appSel = $("#f-app");
    const envVal = envSel.value, appVal = appSel.value;
    envSel.innerHTML = '<option value="">All</option>' + (state.stats.envs || []).map((e) => `<option value="${esc(e)}">${esc(e)}</option>`).join("");
    appSel.innerHTML = '<option value="">All</option>' + state.apps.filter((a) => a.kind !== "unmanaged").map((a) => `<option value="${esc(a.key)}">${esc(a.name)}${a.env ? ` (${esc(a.env)})` : ""}</option>`).join("");
    envSel.value = envVal; appSel.value = appVal;
    const diffSel = $("#diff-app");
    const diffVal = diffSel.value;
    diffSel.innerHTML = '<option value="">Whole estate</option>' + state.apps.filter((a) => a.kind !== "unmanaged").map((a) => `<option value="${esc(a.key)}">${esc(a.name)}${a.env ? ` (${esc(a.env)})` : ""}</option>`).join("");
    diffSel.value = diffVal;
  }

  // ------------------------------------------------------------------ details panel
  function openDetails(html) {
    const el = $("#details");
    el.innerHTML = html;
    el.classList.add("open");
  }
  function clearDetails() {
    $("#details").innerHTML = '<div class="details-empty">Select an application, a workload or a flow.</div>';
    $("#details").classList.remove("open");
  }
  function pills(services, limit = 8) {
    return services.slice(0, limit).map((s) => `<span class="pill ${esc(s.decision)}" title="${esc(s.service)} · ${fmt(s.connections)} connections${s.processes && s.processes.length ? " · " + esc(s.processes.join(", ")) : ""}">${esc(s.name)} <small>${fmt(s.connections)}</small></span>`).join("") + (services.length > limit ? `<span class="pill">+${services.length - limit}</span>` : "");
  }

  async function showNode(node) {
    const d = node.data();
    if (d.type === "env") return;
    if (d.type === "app") return showApp(d.group);
    return showWorkload(d.id.slice(2));
  }

  async function showApp(key) {
    let info;
    try {
      info = EMBEDDED ? EMBEDDED.appDetails[key] : await api(`api/apps/${encodeURIComponent(key)}`);
    } catch (err) { return toast(err.message); }
    const g = info.group;
    const tiers = {};
    for (const w of info.workloads) (tiers[w.tier ?? "?"] = tiers[w.tier ?? "?"] || []).push(w);
    const deps = info.dependencies;
    const blocked = [];
    for (const d of [...deps.outbound, ...deps.inbound]) for (const s of d.services) if (s.decision !== "allowed") blocked.push({ ...s, dep: d.name });
    let html = `<h2>${esc(g.name)}</h2><div class="kind">${esc(g.kind === "labeled" ? "Labeled application" : g.kind === "cluster" ? "Discovered cluster (no app label)" : "Unmanaged IPs")}${g.env ? " · " + esc(g.env) : ""} · ${g.member_count} workloads${g.shared ? " · <b>shared service</b>" : ""}</div>`;
    if (g.kind === "cluster" && g.evidence) {
      html += `<h4>Evidence</h4><div class="muted">Services served: ${esc((g.evidence.served_services || []).join(", ") || "—")}<br>Talks with: ${esc((g.evidence.peer_groups || []).join(", ") || "—")}${g.evidence.candidate_app ? `<br>Candidate: unlabeled part of <b>${esc(g.evidence.candidate_app)}</b>` : ""}</div>`;
    }
    html += `<h4>Workloads by tier</h4>`;
    for (const t of Object.keys(tiers).sort()) {
      html += `<div class="tier"><span class="t">tier ${esc(t)}</span>` + tiers[t].map((w) => `<span class="wl" data-wl="${esc(w.id)}" title="${esc(w.role_class)} (${esc(w.role_source)})"><i class="sw role-${ROLE_GROUP[w.role_class] || "unknown"}"></i>${esc(w.name)}${w.shared ? " ⚠" : ""}</span>`).join(", ") + `</div>`;
    }
    const depBlock = (list, title) => list.length ? `<h4>${title}</h4>` + list.map((dep) => `<div class="dep"><b data-app="${esc(dep.group)}">${esc(dep.name)}</b>${dep.shared ? ' <span class="pill">shared</span>' : ""} <span class="muted">${fmt(dep.connections)} conn.</span><br>${pills(dep.services, 6)}</div>`).join("") : "";
    html += depBlock(deps.outbound, "Depends on (outbound)");
    html += depBlock(deps.inbound, "Consumed by (inbound)");
    if (blocked.length) html += `<h4>Blocked / at-risk flows</h4>` + blocked.slice(0, 10).map((b) => `<div class="dep"><span class="pill ${esc(b.decision)}">${esc(DECISION_LABEL[b.decision])}</span> ${esc(b.name)} with ${esc(b.dep)} <span class="muted">${fmt(b.connections)}</span></div>`).join("");
    html += `<h4>Actions</h4><div class="row"><button class="btn small" id="d-focus">View workloads</button><button class="btn small ghost" id="d-mermaid">Copy Mermaid</button></div>`;
    if (!EMBEDDED) {
      html += `<form class="rename" id="d-rename"><input name="name" placeholder="New application name" value="${esc(g.name)}" required><input name="app" placeholder="Illumio app label (optional)"><input name="env" placeholder="Illumio env label (optional)" value="${esc(g.env || "")}"><button class="btn small ghost" type="submit">Rename (local model)</button></form>`;
    }
    if (info.proposal) html += `<h4>AI proposal</h4>` + proposalCard({ ...info.proposal, current_name: g.name }, "clusters");
    html += `<h4>Report</h4><pre>${esc(info.markdown)}</pre>`;
    openDetails(html);
    wireReviewButtons(() => showApp(g.key));
    $("#d-focus").onclick = () => focusApp(g.key);
    $("#d-mermaid").onclick = () => navigator.clipboard.writeText(info.mermaid).then(() => toast("Mermaid copied"), () => download(`${g.name}.mmd`, info.mermaid));
    $$("#details [data-app]").forEach((b) => (b.onclick = () => showApp(b.dataset.app)));
    $$("#details [data-wl]").forEach((b) => (b.onclick = () => showWorkload(b.dataset.wl)));
    const form = $("#d-rename");
    if (form) form.onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      try {
        await api(`api/apps/${encodeURIComponent(g.key)}/rename`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: fd.get("name"), app: fd.get("app") || null, env: fd.get("env") || null }) });
        toast("Application renamed");
        await reloadAll();
        showApp(g.key);
      } catch (err) { toast(err.message); }
    };
  }

  async function showWorkload(id) {
    let w;
    try {
      w = EMBEDDED ? EMBEDDED.workloads[id] : await api(`api/workloads/${encodeURIComponent(id)}`);
    } catch (err) { return toast(err.message); }
    const svc = (list, key) => list.map((p) => `<div class="dep"><b>${esc(p[key])}</b><br>${pills(p.services, 5)}</div>`).join("") || '<div class="muted">—</div>';
    let html = `<h2>${esc(w.name)}</h2><div class="kind">${w.managed ? "Managed workload (VEN)" : "Unmanaged IP"} · ${esc(w.application || "no application")}${w.tier != null ? ` · tier ${w.tier}` : ""}${w.shared ? ` · <b>shared (${esc(w.shared_kind)})</b>` : ""}</div>`;
    html += `<table><tr><th>Role</th><td><i class="sw role-${ROLE_GROUP[w.role_class] || "unknown"}"></i>${esc(w.role_class)} ${w.role_label && w.role_source === "ai" ? ` — ${esc(w.role_label)}` : ""} <span class="muted">(${esc(w.role_source === "label" ? "Illumio label" : w.role_source === "ports" ? "inferred from ports" : w.role_source === "hostname" ? "inferred from hostname" : w.role_source === "ai" ? "AI-proposed, validated" : "undetermined")})</span></td></tr>`;
    html += `<tr><th>IP</th><td>${esc((w.ips || []).join(", "))}</td></tr>`;
    html += `<tr><th>Labels</th><td>${Object.entries(w.labels || {}).map(([k, v]) => `<span class="pill">${esc(k)}: ${esc(v)}</span>`).join("") || "—"}</td></tr>`;
    html += `<tr><th>Traffic</th><td>${fmt(w.in_connections)} inbound · ${fmt(w.out_connections)} outbound</td></tr>`;
    html += `<tr><th>Services served</th><td>${(w.served || []).map((s) => `<span class="pill">${esc(s.service)} <small>${fmt(s.connections)}</small></span>`).join("") || "—"}</td></tr></table>`;
    if (w.proposal) html += `<h4>AI proposal</h4>` + proposalCard({ ...w.proposal, hostname: w.name, current_role: w.role_class }, "workloads");
    html += `<h4>Calls (${(w.talks_to || []).length})</h4>` + svc(w.talks_to || [], "to");
    html += `<h4>Called by (${(w.called_by || []).length})</h4>` + svc(w.called_by || [], "from");
    openDetails(html);
    wireReviewButtons(() => showWorkload(id));
  }

  function showEdge(edge) {
    const d = edge.data();
    const src = state.cy.getElementById(d.source).data("label"), dst = state.cy.getElementById(d.target).data("label");
    let html = `<h2>${esc(src)} → ${esc(dst)}</h2><div class="kind">${fmt(d.connections)} connections · ${esc(DECISION_LABEL[d.decision])}${d.pairs ? ` · ${d.pairs} workload pairs` : ""}</div>`;
    html += `<table><tr><th>Service</th><th>Name</th><th>Conn.</th><th>Decision</th><th>Process</th></tr>` + d.services.map((s) => `<tr><td>${esc(s.service)}</td><td>${esc(s.name)}</td><td>${fmt(s.connections)}</td><td><span class="pill ${esc(s.decision)}">${esc(DECISION_LABEL[s.decision])}</span></td><td class="muted">${esc((s.processes || []).join(", "))}</td></tr>`).join("") + `</table>`;
    openDetails(html);
  }

  // ------------------------------------------------------------------ period diff
  function clearDiff() {
    state.diff = null;
    state.cy.elements().removeClass("diff-added diff-removed diff-changed");
    $("#btn-diff-clear").hidden = true;
  }
  function applyDiffHighlight() {
    const d = state.diff;
    if (!d) return;
    const cy = state.cy;
    cy.elements().removeClass("diff-added diff-removed diff-changed");
    const mark = (sel, cls) => { const el = cy.getElementById(sel); if (el.length) el.addClass(cls); };
    for (const w of d.workloads_added) mark(`w:${w.id}`, "diff-added");
    for (const w of d.workloads_removed) mark(`w:${w.id}`, "diff-removed");
    const edgeIds = (src, dst) => [`e:${src}->${dst}`, `e:${src}->${dst}#blocked`, `e:${src}->${dst}#potentially_blocked`];
    for (const x of d.deps_added) edgeIds(x.source_key, x.target_key).forEach((id) => mark(id, "diff-added"));
    for (const x of d.deps_removed) edgeIds(x.source_key, x.target_key).forEach((id) => mark(id, "diff-removed"));
    for (const x of d.volume_changes) edgeIds(x.source_key, x.target_key).forEach((id) => mark(id, "diff-changed"));
    for (const x of d.services_added) edgeIds(x.source_id, x.target_id).forEach((id) => mark(id, "diff-added"));
    for (const x of d.services_removed) edgeIds(x.source_id, x.target_id).forEach((id) => mark(id, "diff-removed"));
    for (const x of d.decision_changes) edgeIds(x.source_id, x.target_id).forEach((id) => mark(id, "diff-changed"));
  }
  function renderDiff(out) {
    const d = out.diff;
    state.diff = d;
    $("#btn-diff-clear").hidden = false;
    const per = (p) => `${p[0].slice(0, 10)} → ${p[1].slice(0, 10)}`;
    let html = `<h2>${d.app ? `Changes — ${esc(d.app)}` : "Changes — whole estate"}</h2><div class="kind">A: ${per(d.period_a)} (${fmt(d.stats_a.flows)} flows) · B: ${per(d.period_b)} (${fmt(d.stats_b.flows)} flows) · <b>${d.total_changes} changes</b></div>`;
    const section = (title, cls, rows) => rows.length ? `<div class="diff-section ${cls}"><h4>${title} (${rows.length})</h4><ul>${rows.map((r) => `<li>${r}</li>`).join("")}</ul></div>` : "";
    const svc = (x) => `${esc(x.name)} <span class="muted">(${esc(x.service)}, ${fmt(x.connections)})</span>`;
    html += section("Applications added", "added", d.apps_added.map((a) => `${esc(a.name)} <span class="muted">${esc(a.kind)}, ${a.workloads} workloads</span>`));
    html += section("Applications removed", "removed", d.apps_removed.map((a) => `${esc(a.name)} <span class="muted">${esc(a.kind)}, ${a.workloads} workloads</span>`));
    html += section("New workloads", "added", d.workloads_added.map((w) => `<b>${esc(w.workload)}</b> — ${esc(w.app)}, ${esc(w.role)}, tier ${w.tier}`));
    html += section("Workloads gone", "removed", d.workloads_removed.map((w) => `<b>${esc(w.workload)}</b> — ${esc(w.app)}, ${esc(w.role)}`));
    html += section("Application changed", "changed", d.workloads_moved.map((w) => `${esc(w.workload)}: ${esc(w.from)} → ${esc(w.to)}`));
    html += section("New dependencies", "added", d.deps_added.map((x) => `<b>${esc(x.source)} → ${esc(x.target)}</b>: ${esc(x.services.join(", "))} <span class="muted">(${fmt(x.connections)}, ${esc(DECISION_LABEL[x.decision])})</span>`));
    html += section("Dependencies gone", "removed", d.deps_removed.map((x) => `<b>${esc(x.source)} → ${esc(x.target)}</b>: ${esc(x.services.join(", "))} <span class="muted">(${fmt(x.connections)})</span>`));
    html += section("Policy decision changes", "changed", d.decision_changes.map((x) => `${esc(x.source)} → ${esc(x.target)} ${esc(x.name)}: <span class="pill ${esc(x.from)}">${esc(DECISION_LABEL[x.from])}</span> → <span class="pill ${esc(x.to)}">${esc(DECISION_LABEL[x.to])}</span>`));
    html += section("Volume variations", "changed", d.volume_changes.map((x) => `${esc(x.source)} → ${esc(x.target)}: ${x.per_day_a} → ${x.per_day_b} conn./day <b>×${x.ratio}</b>`));
    html += section("New flows", "added", d.services_added.map((x) => `${esc(x.source)} → ${esc(x.target)} ${svc(x)}${x.decision !== "allowed" ? ` <span class="pill ${esc(x.decision)}">${esc(DECISION_LABEL[x.decision])}</span>` : ""}`));
    html += section("Flows gone", "removed", d.services_removed.map((x) => `${esc(x.source)} → ${esc(x.target)} ${svc(x)}`));
    html += section("Inferred role changes", "changed", d.role_changes.map((x) => `${esc(x.workload)}: ${esc(x.from)} → ${esc(x.to)}`));
    html += section("Tier changes", "changed", d.tier_changes.map((x) => `${esc(x.workload)}: tier ${x.from} → ${x.to}`));
    if (!d.total_changes) html += `<div class="muted">No structural change between the two periods.</div>`;
    html += `<h4>Report</h4><pre>${esc(out.markdown)}</pre>`;
    openDetails(html);
    applyDiffHighlight();
  }
  async function runDiff() {
    if (EMBEDDED) return toast("Period comparison requires the backend");
    const app = $("#diff-app").value, days = $("#diff-days").value || 30;
    try {
      const out = await api(`api/diff?days=${encodeURIComponent(days)}${app ? `&app=${encodeURIComponent(app)}` : ""}`);
      renderDiff(out);
    } catch (err) { toast(`Comparison failed: ${err.message}`, 6000); }
  }

  // ------------------------------------------------------------------ AI proposals
  function proposalCard(p, kind) {
    const conf = `<span class="conf">confidence ${(p.confidence * 100).toFixed(0)}%</span>`;
    const status = p.status === "pending" ? "" : ` · <b>${p.status === "accepted" ? "accepted" : "rejected"}</b>`;
    let body;
    if (kind === "clusters") {
      body = `<b>${esc(p.current_name || p.id)}</b> → <b>${esc(p.name)}</b>${status}${conf}<div class="why">${esc(p.rationale)}</div><div>Labels: <span class="pill">app: ${esc(p.app)}</span>${p.env ? `<span class="pill">env: ${esc(p.env)}</span>` : ""}</div>` +
        (p.workload_roles && p.workload_roles.length ? `<div class="muted">${p.workload_roles.map((r) => `${esc(r.workload)} → ${esc(r.role_label)} (${esc(r.role_class)})`).join(" · ")}</div>` : "");
    } else {
      body = `<b>${esc(p.hostname || p.id)}</b>${p.application ? ` <span class="muted">${esc(p.application)}</span>` : ""} : ${esc(p.current_role || "?")} → <b>${esc(p.role_label)}</b> <span class="pill">${esc(p.role_class)}</span>${status}${conf}<div class="why">${esc(p.rationale)}</div>`;
    }
    const actions = p.status === "pending" ? `<div class="row"><button class="btn small" data-review="accept" data-kind="${kind}" data-id="${esc(p.id)}">Accept</button><button class="btn small ghost" data-review="reject" data-kind="${kind}" data-id="${esc(p.id)}">Reject</button></div>` : "";
    return `<div class="proposal ${esc(p.status)}">${body}${actions}</div>`;
  }
  function wireReviewButtons(after) {
    $$("#details [data-review]").forEach((b) => (b.onclick = async () => {
      try {
        await api(`api/proposals/${b.dataset.kind}/${encodeURIComponent(b.dataset.id)}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: b.dataset.review }) });
        toast(b.dataset.review === "accept" ? "Proposal applied to the model" : "Proposal rejected");
        await reloadAll();
        if (after) after();
      } catch (err) { toast(err.message); }
    }));
  }
  async function showProposals() {
    if (EMBEDDED) return toast("AI proposals require the backend");
    let data;
    try { data = await api("api/proposals"); } catch (err) { return toast(err.message); }
    const total = data.clusters.length + data.workloads.length;
    let html = `<h2>AI proposals</h2><div class="kind">${data.pending} pending · ${total} total</div>`;
    if (!total) html += `<div class="muted">No proposal yet. Click "Enrich with AI".</div>`;
    if (data.clusters.length) html += `<h4>Clusters → applications</h4>` + data.clusters.map((p) => proposalCard(p, "clusters")).join("");
    if (data.workloads.length) html += `<h4>Workload roles</h4>` + data.workloads.map((p) => proposalCard(p, "workloads")).join("");
    openDetails(html);
    wireReviewButtons(showProposals);
  }
  async function refreshProposalCount() {
    if (EMBEDDED) return;
    try {
      const h = await api("api/health");
      const el = $("#proposals-count");
      el.textContent = h.pending_proposals;
      el.hidden = !h.pending_proposals;
    } catch (_) { /* ignore */ }
  }
  async function runEnrichment() {
    if (EMBEDDED) return toast("AI enrichment requires the backend");
    const btn = $("#btn-enrich");
    btn.disabled = true;
    toast("Enrichment running (a few tens of seconds)…", 60000);
    try {
      const out = await api("api/enrich", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ clusters: true, roles: true, auto_apply: false }) });
      toast(`${out.clusters} cluster proposals, ${out.workloads} role proposals — ${out.pending} to review`, 6000);
      await reloadAll();
      showProposals();
    } catch (err) { toast(`Enrichment failed: ${err.message}`, 8000); }
    btn.disabled = false;
  }

  function focusApp(key) {
    $("#f-app").value = key;
    setLevel("workload");
  }
  function setLevel(level) {
    state.level = level;
    $$(".seg button").forEach((b) => b.classList.toggle("active", b.dataset.level === level));
    render();
  }

  // ------------------------------------------------------------------ chat
  function renderMarkdown(text) {
    const lines = text.split("\n");
    let html = "", inTable = false, inCode = false, inList = false;
    const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
    for (const line of lines) {
      if (line.startsWith("```")) { inCode = !inCode; html += inCode ? "<pre>" : "</pre>"; continue; }
      if (inCode) { html += esc(line) + "\n"; continue; }
      if (/^\s*\|/.test(line)) {
        if (/^\s*\|?\s*:?-{2,}/.test(line)) continue;
        if (!inTable) { html += "<table>"; inTable = true; }
        html += "<tr>" + line.split("|").slice(1, -1).map((c) => `<td>${inline(c.trim())}</td>`).join("") + "</tr>";
        continue;
      } else if (inTable) { html += "</table>"; inTable = false; }
      if (/^\s*[-*] /.test(line)) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${inline(line.replace(/^\s*[-*] /, ""))}</li>`; continue; }
      else if (inList) { html += "</ul>"; inList = false; }
      if (/^#{1,4} /.test(line)) { html += `<b>${inline(line.replace(/^#+ /, ""))}</b><br>`; continue; }
      html += inline(line) + "<br>";
    }
    if (inTable) html += "</table>";
    if (inList) html += "</ul>";
    return html;
  }
  function addMsg(kind, html) {
    const el = document.createElement("div");
    el.className = `msg ${kind}`;
    el.innerHTML = html;
    $("#chat-log").appendChild(el);
    $("#chat-log").scrollTop = $("#chat-log").scrollHeight;
    return el;
  }
  async function sendChat(message) {
    addMsg("user", esc(message));
    const pending = addMsg("agent", "<i>The agent is analysing the flows…</i>");
    try {
      const out = await api("api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message, thread_id: state.threadId }) });
      state.threadId = out.thread_id;
      const tools = out.tool_calls.filter((t) => t.tool).map((t) => `<span title="${esc(JSON.stringify(t.args))}">⚙ ${esc(t.tool)}</span>`).join("");
      pending.innerHTML = (tools ? `<div class="tools">${tools}</div>` : "") + renderMarkdown(out.reply);
      if (/rename_application|review_proposal|run_ai_enrichment/.test(JSON.stringify(out.tool_calls))) reloadAll();
      const cmp = out.tool_calls.find((t) => t.tool === "compare_periods");
      if (cmp) { $("#diff-app").value = state.apps.find((a) => a.name === cmp.args.application || a.key === cmp.args.application)?.key || ""; $("#diff-days").value = cmp.args.days || 30; runDiff(); }
    } catch (err) {
      pending.innerHTML = `<b>Error:</b> ${esc(err.message)}`;
    }
  }

  // ------------------------------------------------------------------ wiring
  function wire() {
    $$(".seg button").forEach((b) => (b.onclick = () => setLevel(b.dataset.level)));
    ["#f-env", "#f-app", "#f-hide-infra", "#f-hide-shared", "#f-hide-external", "#f-hide-agents", "#f-tiers"].forEach((sel) => ($(sel).onchange = render));
    $$("[data-decision]").forEach((c) => (c.onchange = render));
    $("#f-min").oninput = () => { $("#f-min-out").textContent = fmt(Math.round(Math.pow(10, parseFloat($("#f-min").value)))); };
    $("#f-min").onchange = render;
    $("#f-ports").onchange = render;
    $("#f-labels").onchange = () => state.cy.edges().toggleClass("labels", $("#f-labels").checked);
    let searchTimer;
    $("#f-search").oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => applySearch(readFilters().search), 200); };
    $("#btn-layout").onclick = () => runLayout(readFilters());
    $("#btn-fit").onclick = () => state.cy.fit(undefined, 30);
    $("#btn-png").onclick = () => download("flowmapper.png", state.cy.png({ full: true, scale: 2, bg: cssVar("--surface-0") }));
    const exportParams = () => {
      const f = readFilters();
      const p = new URLSearchParams({ hide_infra: f.hideInfra, hide_shared: f.hideShared, hide_unmanaged: f.hideExternal, min_connections: f.minConnections, level: state.level });
      if (f.env) p.set("env", f.env);
      if (f.app) { const a = state.apps.find((x) => x.key === f.app); p.set("app", a ? a.key : f.app); }
      if (f.decisions.size < 4) p.set("decisions", Array.from(f.decisions).join(","));
      return p;
    };
    $("#btn-mermaid").onclick = () => EMBEDDED ? download("flowmapper.mmd", EMBEDDED.exports.mermaid) : window.open(`api/export?format=mermaid&${exportParams()}`);
    $("#btn-markdown").onclick = () => EMBEDDED ? download("flowmapper-report.md", EMBEDDED.exports.markdown, "text/markdown") : window.open(`api/export?format=markdown&${exportParams()}`);
    $("#btn-graphml").onclick = () => EMBEDDED ? toast("GraphML export is available with the backend") : window.open(`api/export?format=graphml&${exportParams()}`);
    $("#file-input").onchange = async (e) => {
      const files = Array.from(e.target.files || []);
      if (!files.length) return;
      if (EMBEDDED) return toast("Embedded demo: run the backend to import your own flows");
      const fd = new FormData();
      files.forEach((f) => fd.append("files", f));
      toast(`Importing ${files.length} file(s)…`, 8000);
      try {
        const out = await api("api/ingest?replace=true", { method: "POST", body: fd });
        toast(`${fmt(out.stats.flows)} flows imported, ${out.stats.groups} applications`);
        state.threadId = null;
        await reloadAll();
      } catch (err) { toast(`Import failed: ${err.message}`, 6000); }
      e.target.value = "";
    };
    $("#btn-diff").onclick = runDiff;
    $("#btn-diff-clear").onclick = () => { clearDiff(); clearDetails(); };
    $("#btn-enrich").onclick = runEnrichment;
    $("#btn-proposals").onclick = showProposals;
    $("#btn-chat").onclick = async () => {
      const chat = $("#chat");
      chat.hidden = !chat.hidden;
      if (!chat.hidden) {
        if (EMBEDDED) $("#chat-status").textContent = "offline demo: the agent requires the backend";
        else try { const h = await api("api/health"); $("#chat-status").textContent = h.agent.available ? h.agent.detail : `unavailable — ${h.agent.detail}`; } catch (_) { /* ignore */ }
        $("#chat-input").focus();
      }
    };
    $("#chat-close").onclick = () => ($("#chat").hidden = true);
    $("#chat-form").onsubmit = (e) => {
      e.preventDefault();
      const msg = $("#chat-input").value.trim();
      if (!msg) return;
      $("#chat-input").value = "";
      if (EMBEDDED) { addMsg("user", esc(msg)); addMsg("agent", "This demo is static: run <code>flowmapper serve</code> with an API key to query the agent."); return; }
      sendChat(msg);
    };
    $("#btn-theme").onclick = () => {
      const root = document.documentElement;
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try { localStorage.setItem("flowmapper-theme", next); } catch (_) { /* ignore */ }
      state.cy.style(buildStyle());
      render();
    };
  }

  function initTheme() {
    let theme = null;
    try { theme = localStorage.getItem("flowmapper-theme"); } catch (_) { /* ignore */ }
    if (!theme) theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    document.documentElement.dataset.theme = theme;
  }

  initTheme();
  initCy();
  wire();
  reloadAll();
})();
