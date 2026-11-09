// LGTM dashboard: one app, a light and a dark theme (web/theme.css). Plain JS, hash routes, no build step.
(function () {
  "use strict";

  // ---------------------------------------------------------------- basics
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const view = () => $("#view");
  const enc = encodeURIComponent;

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function rich(s) {
    return esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  }
  async function get(url) {
    const res = await fetch(url, { credentials: "same-origin" });
    if (res.status === 401) { const e = new Error("signin"); e.signin = true; throw e; }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
    return body;
  }
  async function post(url, data) {
    const res = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
    return body;
  }
  function secs(n) {
    if (n == null) return "–";
    n = Math.round(n);
    return n >= 60 ? `${Math.floor(n / 60)}m ${String(n % 60).padStart(2, "0")}s` : `${n}s`;
  }
  function ago(iso) {
    if (!iso) return "–";
    const t = new Date(iso.length === 19 ? iso : iso.replace("Z", "")).getTime();
    const d = (Date.now() - t) / 1000;
    if (d < 45) return "just now";
    if (d < 3600) return `${Math.round(d / 60)} min ago`;
    if (d < 86400) return `${Math.round(d / 3600)} h ago`;
    if (d < 86400 * 30) return `${Math.round(d / 86400)} d ago`;
    return new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short" });
  }
  function when(iso) {
    if (!iso) return "";
    return new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  }
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + "s"}`;
  const short = (sha) => (sha || "").slice(0, 7);
  const repoName = (full) => (full || "").split("/").pop();

  const CWE = {
    "CWE-89": "SQL injection", "CWE-639": "Insecure direct object reference", "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization", "CWE-285": "Improper authorization", "CWE-284": "Improper access control",
  };
  const cweName = (c) => CWE[c] || c || "Security issue";
  const SEV = ["critical", "high", "medium", "low"];
  const STAGES = [
    ["fetch", "Fetch the pull request"], ["index", "Index repository docs"], ["context", "Read the diff, build code graphs"],
    ["sast", "Semgrep on changed files"], ["triage", "Triage Semgrep hits"], ["investigator", "Investigator agent"],
    ["review", "Authorization and SQL-injection reviewers"], ["validate", "Check the cited evidence"],
    ["judge", "Evidence judge"], ["report", "Write the report"],
  ];
  const AGENTS = { investigator: "Investigator", authz_reviewer: "Authorization reviewer", sqli_reviewer: "SQL-injection reviewer", sast_triage: "Semgrep triage" };
  const TOOLS = { code: "read code", rag: "looked up policy", graph: "queried the code graph", other: "used a tool" };
  const TRIAGE = { open: "Open", confirmed: "Confirmed", accepted_risk: "Accepted risk", false_positive: "False positive", fixed: "Fixed", filtered: "Filtered by LGTM" };

  // ---------------------------------------------------------------- icons (inline, stroke)
  const I = {
    play: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M10.2 8.8v6.4l5-3.2z" fill="currentColor"/></svg>',
    logo: '<img class="mascot brand-owl" src="/assets/mascot/owl.webp" alt="" width="720" height="672">',
    overview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h6V4H4zm10 7h6V11h-6zM4 20h6v-4H4zm10-12h6V4h-6z" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>',
    pr: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="6" cy="6" r="2.2" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="6" cy="18" r="2.2" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="18" cy="18" r="2.2" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M6 8.2v7.6M18 15.8V9a3 3 0 0 0-3-3h-4m2-2.5L10.5 6 13 8.5" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>',
    inbox: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13.5 6.5 5h11L20 13.5V19H4zm0 0h4.5l1.5 2.5h4l1.5-2.5H20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg>',
    repo: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 4h12v16H8a2 2 0 0 1-2-2zm0 13a2 2 0 0 1 2-2h10M9 8h6" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>',
    target: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="12" cy="12" r="1" fill="currentColor"/></svg>',
    code: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8 7-5 5 5 5M16 7l5 5-5 5M13.5 4.5l-3 15" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    gear: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8" stroke="currentColor" stroke-width="1.7"/></svg>',
    gh: '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
  };
  const NAV = [
    ["overview", "Overview", I.overview], ["workspace", "Workspace", I.code], ["runs", "Pull requests", I.pr],
    ["repos", "Repositories", I.repo], ["settings", "Settings", I.gear],
  ];

  // ---------------------------------------------------------------- state
  const S = { me: null, health: null, live: null, timers: [], leave: [] };
  const THEMES = [["light", "Light"], ["dark", "Dark"]];
  const THEME_ICON = '<svg class="i-moon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.2A8.2 8.2 0 1 1 9.8 4a6.6 6.6 0 0 0 10.2 10.2z"/></svg><svg class="i-sun" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/></svg>';

  function setTheme(name) {
    if (name !== "dark") name = "light";
    document.documentElement.dataset.theme = name;
    try { localStorage.setItem("lgtm-theme", name); } catch (e) { /* private window */ }
    $$("[data-theme-pick]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themePick === name)));
    $$(".theme-toggle").forEach((b) => { b.setAttribute("aria-label", name === "dark" ? "Switch to light mode" : "Switch to dark mode"); b.title = b.getAttribute("aria-label"); });
    try { if (window.monaco) window.monaco.editor.setTheme(name === "dark" ? "lgtm-dark" : "lgtm-light"); } catch (e) { /* editor not loaded yet */ }
  }

  // ---------------------------------------------------------------- shell
  function shell() {
    const u = S.me && S.me.user;
    $("#app").classList.toggle("bare", !u);   // signed out: the landing page, no sidebar
    const navLinks = u ? NAV.map(([id, label, icon]) => `<a href="#/${id === "overview" ? "" : id}" data-nav="${id}">${icon}<span>${label}</span></a>`).join("") : "";
    $("#app").innerHTML = `
      <a class="skip" href="#view">Skip to content</a>
      <aside class="side" aria-label="Main">
        <a class="brand" href="#/">${I.logo}<span>LGTM</span></a>
        ${u ? `<div class="org" title="GitHub account">${S.me.installations[0] && S.me.installations[0].avatar ? `<img src="${esc(S.me.installations[0].avatar)}&s=40" alt="">` : ""}<span>${esc((S.me.installations[0] || {}).account || u.login)}</span></div>` : ""}
        <nav class="nav">${navLinks}</nav>
        <div class="side-foot" id="status-side"></div>
      </aside>
      <div class="frame">
        <header class="top">
          <a class="brand" href="#/">${I.logo}<span>LGTM</span></a>
          <nav class="tabs" aria-label="Main">${navLinks}</nav>
          <div class="top-right">
            <span class="status-top" id="status-top"></span>
            <button class="theme-toggle" type="button">${THEME_ICON}</button>
            ${u ? `<button class="user" type="button" id="signout" title="Sign out ${esc(u.login)}"><img src="${esc(u.avatar)}&s=48" alt=""><span>${esc(u.login)}</span></button>` : ""}
          </div>
        </header>
        <main id="view" tabindex="-1"></main>
      </div>`;
    $$(".theme-toggle").forEach((b) => b.addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark")));
    ["#status-top", "#status-side"].forEach((sel) => {
      const el = $(sel);
      if (el) el.addEventListener("click", (e) => { const b = e.target.closest("[data-backend]"); if (b && !b.disabled) setBackend(b.dataset.backend); });
    });
    const so = $("#signout");
    if (so) so.addEventListener("click", async () => { await fetch("/auth/logout", { method: "POST" }); location.hash = "#/signin"; boot(); });
    setTheme(document.documentElement.dataset.theme);
    renderStatus();
  }

  function setNav(id) {
    $$("[data-nav]").forEach((a) => a.toggleAttribute("aria-current", a.dataset.nav === id));
    $$("[data-nav]").forEach((a) => { if (a.dataset.nav === id) a.setAttribute("aria-current", "page"); });
  }

  function renderStatus() {
    const h = S.health;
    if (!h) return;
    const dot = (ok, label, title) => `<span class="dot ${ok ? "ok" : "off"}" title="${esc(title)}">${esc(label)}</span>`;
    const relay = h.relay || {};
    const gpu = h.gpu || { reviewer: { ok: h.reviewer, detail: "" }, judge: { ok: h.judge, detail: "" } };
    const backend = h.backend === "bedrock" && h.bedrock ? "bedrock" : "gpu";
    const usable = backend === "gpu" ? gpu.reviewer.ok : h.bedrock;
    const seg = (key, label, ok, title, disabled) => `<button type="button" data-backend="${key}" aria-pressed="${backend === key}" ${disabled ? "disabled" : ""}
      title="${esc(title)}"><span class="dot ${ok ? "ok" : "off"}" aria-hidden="true"></span>${label}</button>`;
    const engine = `<div class="engine${usable ? "" : " engine-bad"}" role="group" aria-label="Reviewer model">
      ${seg("gpu", "GPU", gpu.reviewer.ok, `Qwen 3.8 27B on our GPU job. ${gpu.reviewer.detail}`, false)}
      ${seg("bedrock", "API", h.bedrock, h.bedrock ? "Claude Sonnet on Amazon Bedrock (capped spend). The evidence judge is chosen in Settings." : (h.bedrock_error || "No Bedrock key found in .env"), !h.bedrock)}
    </div>${usable ? "" : `<span class="engine-warn" title="${esc(gpu.reviewer.detail)}">GPU offline: reviews will fail</span>`}`;
    const html = [
      engine,
      dot(gpu.judge.ok, h.judge_kind === "claude" ? "Judge: Claude" : "Judge: Kev", gpu.judge.ok ? gpu.judge.detail : `${gpu.judge.detail} Without a judge, LGTM cannot confirm any finding, so reviews pass.`),
      dot(relay.connected, "Webhooks", relay.connected ? "Relay connected" : "Relay offline: polling every 30 s"),
    ].join("");
    const busy = h.current ? `<a class="busy" href="#/runs/${enc(h.current)}">Reviewing now</a>` : "";
    const side = $("#status-side"), top = $("#status-top");
    const put = (el, markup) => { if (el && el.dataset.markup !== markup) { el.innerHTML = markup; el.dataset.markup = markup; } };
    put(side, `<div class="dots">${html}</div>${busy}`);
    put(top, busy + html);
  }

  async function setBackend(backend) {
    if (S.health) { S.health.backend = backend; renderStatus(); }
    await post("/api/settings", { backend });
    const sel = $('select[data-set="backend"]');
    if (sel) sel.value = backend;
    await pollHealth();
  }

  async function pollHealth() {
    try {
      S.health = await get("/api/health");
      renderStatus();
    } catch (e) { /* server restarting */ }
  }

  // ---------------------------------------------------------------- router
  function clearTimers() {
    S.timers.forEach(clearInterval); S.timers = [];
    if (S.live) { S.live.close(); S.live = null; }
    S.leave.forEach((f) => { try { f(); } catch (e) { /* already gone */ } }); S.leave = [];
  }

  async function route() {
    clearTimers();
    const parts = location.hash.replace(/^#\/?/, "").split("?")[0].split("/").map(decodeURIComponent);
    const query = new URLSearchParams(location.hash.split("?")[1] || "");
    const [name, ...args] = parts;
    const signedIn = S.me && S.me.user;
    if (name === "onboarding") { setNav(""); return onboarding(); }
    if (!signedIn || name === "signin") { setNav(""); return signin(query); }
    const views = { "": overview, overview, runs: args.length ? runPage : runsPage, findings: findingsPage, repos: args.length ? repoPage : reposPage, accuracy: accuracyPage, settings: settingsPage, workspace: (a, q) => window.LGTMWorkspace(a, q) };
    const fn = views[name] || overview;
    setNav({ "": "overview", accuracy: "overview", findings: "runs" }[name] ?? name);   // Accuracy lives in Overview, Findings in Pull requests
    try {
      await fn(args, query);
    } catch (e) {
      if (e.signin) { S.me.user = null; return boot(); }
      view().innerHTML = `<section class="page"><div class="empty"><h2>Could not load this page</h2><p>${esc(e.message)}</p><p><a href="#/">Back to overview</a></p></div></section>`;
    }
  }

  function page(html, cls = "") { view().innerHTML = `<section class="page ${cls}">${html}</section>`; }

  // ---------------------------------------------------------------- sign in and onboarding
  function signin(query) { return window.LGTMLanding(query); }

  async function onboarding() {
    const me = S.me;
    const app = me.app, user = me.user;
    let repos = [];
    if (user) { try { repos = (await get("/api/repos?source=connected")).filter((r) => r.source === "github"); } catch (e) { repos = []; } }
    const installed = me.installations && me.installations.length;
    const step = (n, done, active, title, body) => `
      <li class="step ${done ? "done" : ""} ${active ? "active" : ""}">
        <span class="step-n" aria-hidden="true">${done ? "✓" : n}</span>
        <div><h3>${title}${done ? '<span class="sr-only"> (done)</span>' : ""}</h3>${body}</div>
      </li>`;
    page(`
      <header class="page-head"><h1>Set up LGTM</h1><p>Four steps, about two minutes. You stay in control of every grant on GitHub's own pages.</p></header>
      <ol class="steps">
        ${step(1, !!app, !app, "Create the GitHub App", app ? `<p>Created <b>${esc(app.name)}</b> owned by <b>${esc(app.owner)}</b>.</p>` : `<p>LGTM sends GitHub an app manifest; you confirm it on GitHub.</p><a class="btn primary" href="/setup.html">Create the app</a>`)}
        ${step(2, !!user, app && !user, "Sign in with GitHub", user ? `<p>Signed in as <b>${esc(user.login)}</b>.</p>` : `<p>LGTM only shows repositories your GitHub account can access.</p>${app ? `<a class="btn primary" href="/auth/login">${I.gh}<span>Sign in with GitHub</span></a>` : ""}`)}
        ${step(3, !!installed, user && !installed, "Install LGTM on your repositories", installed ? `<p>Installed on <b>${esc(me.installations.map((i) => i.account).join(", "))}</b>. <a href="${esc(me.install_url)}" target="_blank" rel="noopener">Change which repositories</a></p>` : `<p>Pick the repositories LGTM may read. It needs read access to code and write access to checks and pull-request reviews.</p>${me.install_url ? `<a class="btn primary" href="${esc(me.install_url)}" target="_blank" rel="noopener">Install on GitHub</a> <button class="btn" type="button" id="recheck">I've installed it</button>` : ""}`)}
        ${step(4, installed && repos.some((r) => r.enabled), installed, "Choose what to review", repos.length ? `<p>New and updated pull requests in these repositories are reviewed automatically.</p><ul class="repo-toggles">${repos.map((r) => `<li><label><input type="checkbox" data-repo="${r.id}" ${r.enabled ? "checked" : ""}> <b>${esc(r.repo)}</b> ${r.private ? '<span class="tag">Private</span>' : '<span class="tag">Public</span>'}</label></li>`).join("")}</ul><a class="btn primary" href="#/">Go to the dashboard</a>` : `<p>Repositories appear here once the app is installed.</p>`)}
      </ol>`, "onboard");
    $$("[data-repo]").forEach((c) => c.addEventListener("change", () => post(`/api/repos/${c.dataset.repo}`, { enabled: c.checked })));
    const re = $("#recheck");
    if (re) re.addEventListener("click", async () => { re.disabled = true; re.textContent = "Checking…"; await post("/api/sync").catch(() => {}); await loadMe(); onboarding(); });
  }

  function prSwitch(current) {
    return `<nav class="pr-switch" aria-label="Pull requests">${[["runs", "Reviews"], ["findings", "Findings"]].map(([k, l]) => `<a href="#/${k}" ${k === current ? 'aria-current="page"' : ""}>${l}</a>`).join("")}</nav>`;
  }

  // ---------------------------------------------------------------- overview
  function sourceSwitch(current, base) {
    const opts = [["all", "Everything"], ["connected", "Connected repositories"], ["imported", "Benchmark history"]];
    return `<div class="seg" role="group" aria-label="Which runs">${opts.map(([k, l]) => `<a href="${base}?source=${k}" ${k === current ? 'aria-current="true"' : ""}>${l}</a>`).join("")}</div>`;
  }

  async function overview(args, query) {
    const source = query.get("source") || "all";
    const o = await get(`/api/overview?source=${source}`);
    const t = o.totals;
    const running = o.recent.filter((r) => r.status === "running" || r.status === "queued");
    page(`
      <header class="page-head row">
        <div><h1>Overview</h1><p>${plural(t.repos, "repository", "repositories")}, ${plural(t.runs, "review")} so far.</p></div>
        ${sourceSwitch(source, "#/")}
      </header>
      ${running.map((r) => `<a class="live-banner" href="#/runs/${enc(r.id)}"><span class="pulse" aria-hidden="true"></span><span><b>Reviewing ${esc(r.repo)} #${r.pr_number}</b> ${esc(r.pr_title)}</span><span class="muted">${r.status === "queued" ? "Queued" : stageLabel(r.stage)}</span></a>`).join("")}
      <div class="kpis">
        ${kpi("Pull requests reviewed", t.prs, source === "all" ? `${t.app_runs} by the app, ${t.imported_runs} from the benchmark` : plural(t.runs, "run"))}
        ${kpi("Findings reported", t.flagged, `${t.open} still open`, "risk")}
        ${kpi("Merges blocked", t.blocked, "by the severity policy")}
        ${kpi("Median review time", secs(t.median_latency), "per pull request")}
      </div>
      <div class="grid-2">
        <section class="panel funnel-panel">
          <h2>Noise LGTM removed</h2>
          ${funnel([["Raised by the agents", t.candidates], ["Reported to developers", t.flagged]])}
          <p class="note">Every candidate must cite code that exists and pass the evidence judge before it reaches a pull request. ${t.candidates ? Math.round(100 * t.filtered / t.candidates) : 0}% never did.</p>
        </section>
        <section class="panel">
          <h2>Reviews per day</h2>
          ${barChart(o.series)}
        </section>
      </div>
      <div class="grid-2">
        <section class="panel">
          <h2>What it finds</h2>
          ${o.by_cwe.length ? `<ul class="hbars">${o.by_cwe.map((c) => `<li><span class="hb-label">${esc(c.name)} <span class="muted">${esc(c.cwe)}</span></span><span class="hb-track"><span class="hb-fill" style="width:${(100 * c.n / o.by_cwe[0].n).toFixed(1)}%"></span></span><span class="hb-n">${c.n}</span></li>`).join("")}</ul>` : `<p class="muted">No findings yet.</p>`}
          <div class="sev-row">${SEV.map((s) => `<span class="sev-chip ${s}"><b>${o.severity[s] || 0}</b> ${s}</span>`).join("")}</div>
        </section>
        <section class="panel">
          <h2>Latest reviews</h2>
          ${runList(o.recent.slice(0, 7), true)}
          <p><a href="#/runs">All pull requests</a></p>
        </section>
      </div>
      <section class="panel">
        <h2>Repositories</h2>
        ${repoTable(o.repos)}
      </section>
      <section class="panel ov-accuracy" id="ov-accuracy"><h2>Accuracy on known bugs</h2>
        <p class="note">How LGTM scores on pull requests with a known answer: real advisories from open-source Python projects (the change that introduced each bug and the change that fixed it), plus a synthetic shop.</p>
        <div id="ov-acc-body"><p class="muted">Loading…</p></div></section>`, "overview");
    get("/api/accuracy").then((a) => { const el = $("#ov-acc-body"); if (el) el.innerHTML = accuracyBlocks(a); }).catch(() => { const el = $("#ov-acc-body"); if (el) el.innerHTML = `<p class="muted">The benchmark numbers did not load.</p>`; });
    S.timers.push(setInterval(() => { if (location.hash.replace(/\?.*/, "") === "#/" || location.hash === "" ) refreshIfChanged(); }, 8000));
  }

  let lastSig = "";
  async function refreshIfChanged() {
    try {
      const runs = await get("/api/runs?source=connected&limit=5");
      const sig = runs.map((r) => r.id + r.status + r.stage).join();
      if (lastSig && sig !== lastSig) route();
      lastSig = sig;
    } catch (e) { /* ignore */ }
  }

  function kpi(label, value, sub, tone = "") {
    return `<div class="kpi ${tone}"><span class="kpi-label">${esc(label)}</span><span class="kpi-value">${esc(value)}</span><span class="kpi-sub">${esc(sub)}</span></div>`;
  }

  function funnel(steps) {
    const max = Math.max(1, ...steps.map((s) => s[1]));
    return `<ol class="funnel">${steps.map(([label, n], i) => `
      <li style="--w:${Math.max(4, (100 * n) / max).toFixed(1)}%">
        <span class="f-bar"><span class="f-fill ${i === steps.length - 1 ? "last" : ""}"></span></span>
        <span class="f-n">${n}</span><span class="f-label">${esc(label)}</span>
      </li>`).join("")}</ol>`;
  }

  function barChart(series) {
    if (!series.length) return `<p class="muted">No reviews yet.</p>`;
    const keys = [["passed", "No findings"], ["findings", "Findings"], ["blocked", "Blocked"], ["error", "Error"]];
    const max = Math.max(1, ...series.map((d) => keys.reduce((a, [k]) => a + (d[k] || 0), 0)));
    const W = 560, H = 170, pad = 22, bw = Math.min(26, (W - pad) / series.length - 4);
    const bars = series.map((d, i) => {
      let y = H - pad;
      const x = pad + i * ((W - pad) / series.length) + 2;
      const total = keys.reduce((a, [k]) => a + (d[k] || 0), 0);
      const rects = keys.map(([k]) => {
        const h = ((d[k] || 0) / max) * (H - pad - 10);
        y -= h;
        return h ? `<rect class="c-${k}" x="${x}" y="${y.toFixed(1)}" width="${bw}" height="${h.toFixed(1)}" rx="2"><title>${d.day}: ${d[k]} ${k}</title></rect>` : "";
      }).join("");
      const label = i % Math.ceil(series.length / 7) === 0 ? `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${new Date(d.day).toLocaleDateString(undefined, { day: "numeric", month: "short" })}</text>` : "";
      return `<g aria-label="${d.day}: ${total} reviews">${rects}${label}</g>`;
    }).join("");
    return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Reviews per day, by result">${bars}<line x1="${pad}" x2="${W}" y1="${H - pad}" y2="${H - pad}" class="axis"/><text x="0" y="12" class="ymax">${max}</text></svg>
      <div class="legend">${keys.map(([k, l]) => `<span><i class="c-${k}"></i>${l}</span>`).join("")}</div>`;
  }

  function stageLabel(stage) {
    const s = STAGES.find(([k]) => k === stage);
    return s ? s[1] : stage === "done" ? "Done" : "Starting";
  }

  function conclusionBadge(r) {
    if (r.status === "queued") return `<span class="badge queued">Queued</span>`;
    if (r.status === "running") return `<span class="badge running">Reviewing</span>`;
    if (r.status === "failed") return `<span class="badge error">Failed</span>`;
    if (r.status === "cancelled") return `<span class="badge muted">Cancelled</span>`;
    const map = { blocked: ["blocked", "Blocked"], findings: ["warn", "Findings"], passed: ["ok", "No findings"], error: ["error", "Error"] };
    const [cls, label] = map[r.conclusion] || ["muted", r.conclusion || "–"];
    return `<span class="badge ${cls}">${label}</span>`;
  }

  function sourceTag(r) {
    if (r.source === "imported") return `<span class="tag imported" title="Produced by the benchmark harness on a cached clone of the public project, not through the GitHub App">Imported from benchmark</span>`;
    const t = (r.trigger || "").split(":")[0];
    return `<span class="tag" title="How this review started">${{ webhook: "Webhook", poll: "Polling", manual: "Re-run", github: "Re-run on GitHub" }[t] || esc(t)}</span>`;
  }

  function runList(runs, compact) {
    if (!runs.length) return `<div class="empty small"><p>No reviews yet. Open a pull request in a connected repository and LGTM starts within seconds.</p></div>`;
    return `<ul class="runs ${compact ? "compact" : ""}">${runs.map((r) => `
      <li><a href="#/runs/${enc(r.id)}">
        ${conclusionBadge(r)}
        <span class="run-main"><span class="run-title">${esc(r.pr_title || "Untitled")}</span>
          <span class="run-sub">${esc(r.repo)}${r.pr_number ? ` #${r.pr_number}` : ""}${r.head_ref ? ` <code>${esc(r.head_ref)}</code>` : ""} ${compact ? "" : sourceTag(r)}</span></span>
        <span class="run-num">${r.status === "completed" ? (r.n_flagged ? `<b class="risk">${plural(r.n_flagged, "finding")}</b>` : `<span class="muted">0 findings</span>`) : r.status === "running" ? esc(stageLabel(r.stage)) : ""}</span>
        <span class="run-when"><span>${ago(r.created_at)}</span><span class="muted">${r.latency ? secs(r.latency) : ""}</span></span>
      </a></li>`).join("")}</ul>`;
  }

  function repoTable(repos) {
    if (!repos.length) return `<p class="muted">No repositories yet.</p>`;
    return `<div class="table-wrap"><table class="table">
      <thead><tr><th scope="col">Repository</th><th scope="col" class="num">Reviews</th><th scope="col" class="num">Bugs found</th><th scope="col" class="num">Open</th><th scope="col" class="num">Median time</th><th scope="col">Last review</th></tr></thead>
      <tbody>${repos.map((r) => `<tr>
        <th scope="row"><a href="#/repos/${r.repo.split("/").map(enc).join("/")}">${esc(r.repo)}</a> ${r.source === "imported" ? '<span class="tag imported">Benchmark</span>' : r.private ? '<span class="tag">Private</span>' : '<span class="tag">Public</span>'}</th>
        <td class="num">${r.runs}</td><td class="num ${r.flagged ? "risk" : ""}">${r.flagged}</td><td class="num">${r.open}</td><td class="num">${secs(r.median_latency)}</td>
        <td>${r.last ? `<a href="#/runs/${enc(r.last.id)}">${conclusionBadge(r.last)}</a> <span class="muted">${ago(r.last.created_at)}</span>` : '<span class="muted">Waiting for a pull request</span>'}</td>
      </tr>`).join("")}</tbody></table></div>`;
  }

  // ---------------------------------------------------------------- runs feed
  async function runsPage(args, query) {
    const source = query.get("source") || "all";
    const status = query.get("conclusion") || "";
    const runs = await get(`/api/runs?source=${source}${status ? `&conclusion=${status}` : ""}`);
    const live = runs.filter((r) => r.status === "running" || r.status === "queued").length;
    page(`
      <header class="page-head row">
        <div><h1>Pull requests</h1>${prSwitch("runs")}<p>Every review LGTM has run, newest first.${live ? ` ${plural(live, "review")} in progress.` : ""}</p></div>
        ${sourceSwitch(source, "#/runs")}
      </header>
      <div class="filters">${[["", "All results"], ["blocked", "Blocked"], ["findings", "Findings"], ["passed", "No findings"]].map(([k, l]) => `<a href="#/runs?source=${source}${k ? `&conclusion=${k}` : ""}" ${k === status ? 'aria-current="true"' : ""}>${l}</a>`).join("")}</div>
      <section class="panel flush">${runList(runs)}</section>`);
    if (live) S.timers.push(setInterval(() => route(), 6000));
  }

  // ---------------------------------------------------------------- one run
  async function runPage(args, query) {
    const id = args[0];
    const tab = args[1] || "";
    const d = await get(`/api/runs/${enc(id)}`);
    const r = d.run;
    S.judgeName = r.judge === "claude" ? "Claude judge" : "Kev judge";
    const res = d.result;
    const active = r.status === "queued" || r.status === "running";
    const findings = res ? res.findings : [];
    const flagged = findings.filter((f) => f.flagged);
    const supported = findings.filter((f) => f.supported).length;
    const defaultTab = active ? "live" : flagged.length ? "findings" : "changes";
    const current = tab || defaultTab;
    const tabs = [["live", active ? "Live" : "Activity"], ["findings", `Findings <span class="count">${flagged.length}</span>`], ["changes", "Code changes"], ["trace", "Agent trace"], ["log", "Log"]];
    const ghLinks = r.source === "github" ? [r.pr_url && `<a href="${esc(r.pr_url)}" target="_blank" rel="noopener">${I.gh}<span>Pull request</span></a>`, r.check_url && `<a href="${esc(r.check_url)}" target="_blank" rel="noopener">Check run</a>`, r.review_url && `<a href="${esc(r.review_url)}" target="_blank" rel="noopener">Review comments</a>`].filter(Boolean).join("") : (r.pr_url ? `<a href="${esc(r.pr_url)}" target="_blank" rel="noopener">Upstream ${r.pr_url.includes("/pull/") ? "pull request" : "commit"}</a>` : "");
    page(`
      <nav class="crumbs" aria-label="Breadcrumb"><a href="#/runs">Pull requests</a><span aria-hidden="true">/</span><a href="#/repos/${r.repo.split("/").map(enc).join("/")}">${esc(r.repo)}</a></nav>
      <header class="run-head">
        <div class="run-head-main">
          <h1>${esc(r.pr_title || "Untitled")} ${r.pr_number ? `<span class="muted">#${r.pr_number}</span>` : ""}</h1>
          <p class="run-meta">${conclusionBadge(r)} ${sourceTag(r)} ${r.merged ? '<span class="tag merged">Merged</span>' : ""}
            ${r.author ? `<span>${r.author_avatar ? `<img class="av" src="${esc(r.author_avatar)}&s=32" alt="">` : ""}${esc(r.author)}</span>` : ""}
            ${r.head_ref ? `<span><code>${esc(r.head_ref)}</code> into <code>${esc(r.base_ref)}</code></span>` : ""}
            ${r.head_sha ? `<span>at <code>${short(r.head_sha)}</code></span>` : ""}
            <span>${when(r.created_at)}</span>${r.latency ? `<span>${secs(r.latency)}</span>` : ""}${r.model ? `<span>${esc(String(r.model).replace("bedrock:", ""))} + ${r.judge === "claude" ? "Claude judge" : "Kev"}</span>` : ""}</p>
          ${r.source === "imported" ? `<p class="notice">This run comes from the benchmark: the pipeline reviewed a cached clone of the public project, scored against the advisory${r.outcome ? ` (<b>${esc(outcomeText(r.outcome))}</b>)` : ""}. LGTM was never installed on that repository and posted nothing to it.</p>` : ""}
          ${r.error && r.verdict === "error" || r.status === "failed" ? `<p class="notice warn">${esc(r.error || "The review failed.")}</p>` : ""}
        </div>
        <div class="run-actions">${ghLinks}
          ${res ? `<button class="btn" type="button" id="pdf">Download report (PDF)</button>` : ""}
          ${r.source === "github" && active ? `<button class="btn" type="button" id="cancel">Cancel</button>` : ""}
          ${r.source === "github" && !active ? `<button class="btn" type="button" id="rerun">Run again</button>` : ""}</div>
      </header>
      ${res ? `<div class="run-summary">
        <div class="verdict ${res.verdict}"><span class="verdict-label">${res.verdict === "vulnerable" ? "Security bugs found" : res.verdict === "safe" ? "No security bugs found" : "Review failed"}</span>
          <span class="verdict-sub">${flagged.length ? flagged.map((f) => `${cweName(f.cwe)} in <code>${esc(f.file)}:${f.line}</code>`).slice(0, 3).join("<br>") : "Every changed Python file was reviewed for SQL injection and broken authorization."}</span></div>
        ${funnel([["Raised by the agents", findings.length], ["Evidence checks out", supported], ["Confirmed and reported", flagged.length]])}
        <div class="mini-stats"><span><b>${(res.meta.investigator_tool_calls || 0) + (res.meta.reviewer_tool_calls || 0) + (res.meta.sast_triage_tool_calls || 0)}</b> tool calls</span><span><b>${res.meta.python_files_changed ?? "–"}</b> Python files</span><span><b>${res.meta.added_lines ?? "–"}</b> lines added</span><span><b>${Array.isArray(res.meta.semgrep_findings_in_diff) ? res.meta.semgrep_findings_in_diff.length : res.meta.semgrep_findings_in_diff ?? 0}</b> Semgrep hits</span></div>
      </div>` : ""}
      <div class="tabbar" role="tablist">${tabs.map(([k, l]) => `<a role="tab" href="#/runs/${enc(id)}/${k}" aria-selected="${k === current}">${l}</a>`).join("")}</div>
      <div id="tab"></div>`, "run");
    const pdf = $("#pdf");
    if (pdf) pdf.addEventListener("click", async () => {
      pdf.disabled = true; pdf.textContent = "Preparing the PDF…";
      try {
        const resp = await fetch(`/api/runs/${enc(id)}/report.pdf`, { credentials: "same-origin" });
        if (!resp.ok) throw new Error((await resp.json().catch(() => ({}))).error || resp.statusText);
        const name = (resp.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
        const a = document.createElement("a");
        a.href = URL.createObjectURL(await resp.blob());
        a.download = name ? name[1] : "LGTM-review.pdf";
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        pdf.textContent = "Download report (PDF)";
      } catch (e) {
        window.open(`/api/runs/${enc(id)}/report.html`, "_blank");
        pdf.textContent = "Opened the printable report instead";
      }
      pdf.disabled = false;
    });
    const cancel = $("#cancel"), rerun = $("#rerun");
    if (cancel) cancel.addEventListener("click", async () => { cancel.disabled = true; await post(`/api/runs/${enc(id)}/cancel`); route(); });
    if (rerun) rerun.addEventListener("click", async () => { rerun.disabled = true; rerun.textContent = "Queuing…"; const x = await post(`/api/runs/${enc(id)}/rerun`).catch((e) => ({ error: e.message })); if (x.run) location.hash = `#/runs/${enc(x.run)}`; else { rerun.textContent = x.error || "Could not queue"; } });
    const box = $("#tab");
    if (current === "live") return liveTab(box, id, active);
    if (current === "findings") {
      findingsTab(box, d);
      if (d.result && d.result.findings.some((f) => f.flagged && needsBrief(f))) {   // written once, then cached
        get(`/api/runs/${enc(id)}/briefs`).then((b) => {
          d.result.findings.forEach((f) => { if (b[f.key]) f.brief = b[f.key]; });
          if (document.body.contains(box)) findingsTab(box, d);
        }).catch(() => {});
      }
      return;
    }
    if (current === "changes") return changesTab(box, d);
    if (current === "trace") return traceTab(box, d);
    if (current === "log") return logTab(box, id);
  }

  function outcomeText(o) {
    return { TP: "caught the advisory's bug", FN: "missed the advisory's bug", TN: "correctly quiet on the fix", FP: "false alarm on the fix", ERROR: "errored" }[o] || o;
  }

  // Live: stage tracker plus what each agent is doing.
  function liveTab(box, id, active) {
    const st = { stages: {}, current: null, agents: [], tools: 0, verdicts: [], logs: [], done: null, error: null, t: 0 };
    STAGES.forEach(([k]) => (st.stages[k] = { status: "pending", detail: "", info: [] }));
    const draw = () => {
      box.innerHTML = `<div class="live">
        <ol class="stages">${STAGES.map(([k, label]) => { const s = st.stages[k]; return `<li class="st ${s.status}"><span class="st-mark" aria-hidden="true"></span><span class="st-label">${label}</span><span class="st-detail">${esc([s.detail, ...s.info].filter(Boolean).join(" · "))}</span></li>`; }).join("")}</ol>
        <div class="feed">
          <h2>${st.done ? "Finished" : st.error ? "Stopped" : active ? "Working" : "Activity"} <span class="muted">${secs(st.t)}, ${plural(st.tools, "tool call")}</span></h2>
          ${st.error ? `<p class="notice warn">${esc(st.error)}</p>` : ""}
          ${st.posting && !st.done && !st.error ? `<p class="notice"><span class="pulse"></span> Analysis finished. Writing fixes and posting the review to GitHub…</p>` : ""}
          ${st.done ? `<p class="notice ${st.done.n_flagged ? "risk" : "ok"}">${st.done.n_flagged ? `${plural(st.done.n_flagged, "security bug")} reported on the pull request.` : "No security bugs: the check passed."} <a href="#/runs/${enc(id)}/${st.done.n_flagged ? "findings" : "changes"}">See the results</a></p>` : ""}
          ${st.verdicts.length ? `<ul class="verdicts">${st.verdicts.map((v) => `<li class="${v.kev_verdict === "real" && v.supported ? "real" : "dropped"}"><b>${v.kev_verdict === "real" && v.supported ? "Confirmed" : "Dropped"}</b> ${esc(cweName(v.cwe))} <code>${esc(v.file)}:${v.line}</code><span class="muted">${v.supported ? `judge: ${esc(v.kev_verdict || "–")}` : "evidence did not check out"}</span></li>`).join("")}</ul>` : ""}
          <ol class="agents">${st.agents.slice().reverse().slice(0, 12).map((a) => `<li><div class="ag-head"><b>${esc(AGENTS[a.agent] || a.agent)}</b> <span class="muted">${esc(a.section && a.section !== a.agent ? a.section : "")}</span></div>
            ${a.tools.length ? `<ul class="tools">${a.tools.slice(-6).map((t) => `<li><span class="tool-kind ${t.kind}">${esc(TOOLS[t.kind] || t.tool)}</span> <code>${esc(argSummary(t.tool, t.args))}</code></li>`).join("")}</ul>` : ""}</li>`).join("")}</ol>
        </div></div>`;
    };
    draw();
    const es = new EventSource(`/api/runs/${enc(id)}/events`);
    S.live = { close: () => es.close() };
    let pending = false;
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      if (typeof ev.t === "number") st.t = Math.max(st.t, ev.t);
      if (ev.type === "stage" && st.stages[ev.stage]) { const s = st.stages[ev.stage]; s.status = ev.status === "start" ? "running" : ev.status; if (ev.detail) s.detail = ev.detail; }
      else if (ev.type === "info" && st.stages[ev.stage]) st.stages[ev.stage].info.push(ev.detail);
      else if (ev.type === "agent") st.agents.push({ agent: ev.agent, section: ev.section, tools: [] });
      else if (ev.type === "tool") { (st.agents[st.agents.length - 1] || st.agents[st.agents.push({ agent: ev.agent, section: "", tools: [] }) - 1]).tools.push(ev); st.tools++; }
      else if (ev.type === "verdict") st.verdicts.push(ev);
      else if (ev.type === "done" && ev.conclusion) st.done = ev;   // LGTM's result; the pipeline's own "done" (no count yet) is not it
      else if (ev.type === "done") st.posting = true;
      else if (ev.type === "error") st.error = ev.msg;
      if (!pending) { pending = true; requestAnimationFrame(() => { pending = false; draw(); }); }
    };
    es.addEventListener("end", () => { es.close(); if (active) setTimeout(() => route(), 1200); });
  }

  function argSummary(tool, a) {
    if (!a) return "";
    if (tool === "read_file") return `${a.path || ""}${a.start_line ? `:${a.start_line}${a.end_line ? "–" + a.end_line : ""}` : ""}`;
    if (tool === "grep_repo") return `/${a.pattern || ""}/${a.file_glob ? " in " + a.file_glob : ""}`;
    return a.query || Object.values(a).join(" ");
  }

  function briefHtml(b) {
    if (!b) return "";
    const rows = [["Where", b.where], ["Impact", b.impact], ["Breaks", b.breaks], ["Fix", b.fix]].filter(([, v]) => v);
    return `<div class="brief"><p class="brief-h">${rich(b.headline)}</p><dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${rich(v)}</dd>`).join("")}</dl></div>`;
  }
  // The suggested fix as one sentence and the corrected code; the agent's full prose stays one click away.
  function fixHtml(f) {
    const b = f.brief;
    if (!b || !b.fix) return `<p>${rich(f.suggested_fix)}</p>`;
    return `<div class="fixbox">${b.fix_code ? `<pre class="fixcode"><code>${esc(b.fix_code)}</code></pre>` : `<p>${rich(b.fix)}</p>`}
      <details class="full-why"><summary>The fix in full</summary>${richBlocks(f.suggested_fix)}</details></div>`;
  }
  // Prose with ``` fenced code: paragraphs through rich(), fences as code blocks.
  function richBlocks(s) {
    return String(s || "").split(/```[\w-]*\n?/).map((part, i) => i % 2
      ? `<pre class="fixcode"><code>${esc(part.replace(/\n$/, ""))}</code></pre>`
      : part.trim() ? `<p>${rich(part.trim())}</p>` : "").join("");
  }
  const needsBrief = (f) => !f.brief || (!!f.suggested_fix && !("fix_code" in f.brief));
  function explained(f) {
    return f.brief ? `${briefHtml(f.brief)}<details class="full-why"><summary>Full reasoning</summary><p>${rich(f.explanation)}</p></details>`
      : `<p>${rich(f.explanation)}</p>`;
  }

  function findingCard(f, runId, opts = {}) {
    const ev = (f.evidence || []).filter((e) => e.content).slice(0, 3);
    return `<article class="finding ${f.flagged ? "" : "filtered"}" id="f-${esc(f.id)}">
      <header><span class="sev ${f.severity}">${esc(f.severity)}</span><h3>${esc(cweName(f.cwe))} <span class="muted">${esc(f.cwe || "")}</span></h3>
        <code class="loc">${esc(f.file)}:${f.line}</code></header>
      ${f.flagged ? explained(f) : `<p>${rich(f.explanation)}</p>`}
      ${ev.length ? `<details ${opts.open ? "open" : ""}><summary>Evidence the agents cited (${ev.length})</summary>${ev.map((e) => `<div class="evidence"><div class="ev-head"><code>${esc(e.file || "")}${e.lines ? ":" + esc(e.lines) : ""}</code><span class="muted">${esc(e.type || "")}${e.grounded_in_pr ? ", in this change" : ""}</span></div><pre><code>${esc(e.content.trim())}</code></pre></div>`).join("")}</details>` : ""}
      ${f.suggested_fix ? `<details><summary>Suggested fix</summary>${fixHtml(f)}</details>` : ""}
      <footer><span class="judge ${f.kev_verdict === "real" ? "real" : ""}">${f.flagged ? `Confirmed by the ${S.judgeName || "Kev judge"}` : f.supported === false ? "Dropped: the cited evidence did not check out" : f.kev_verdict === "not_real" ? "Dropped by the Kev judge" : "Not reported"}</span>
        <span class="muted">${esc(AGENTS[f.agent] || f.agent || "")}, ${plural(f.tool_calls || 0, "tool call")}</span>
        ${f.key && f.flagged ? triageButtons(f.key, f.triage) : ""}</footer>
    </article>`;
  }

  // Your verdict on a finding. "Fixed" is not a verdict: LGTM sets it when a later commit removes the bug, so it shows
  // as a status (with Reopen) instead of a fourth button.
  function triageButtons(key, status) {
    if (status === "fixed") {
      return `<span class="triage-wrap"><span class="state fixed">Fixed</span><span class="triage" data-key="${esc(key)}"><button type="button" data-status="open" aria-pressed="false" title="The bug is back or was not really fixed">Reopen</button></span></span>`;
    }
    const HELP = { confirmed: "A real bug the team will fix. It becomes Fixed when a later review no longer reports it",
      accepted_risk: "A real bug the team chooses not to fix", false_positive: "LGTM was wrong: this is not a bug" };
    return `<span class="triage-wrap"><span class="triage-l">Mark as</span><span class="triage" data-key="${esc(key)}" role="group" aria-label="Mark this finding as">${["confirmed", "accepted_risk", "false_positive"].map((s) => `<button type="button" data-status="${s}" aria-pressed="${status === s}" title="${esc(HELP[s])}">${TRIAGE[s]}</button>`).join("")}</span></span>`;
  }

  function wireTriage(root, after) {
    $$(".triage button", root).forEach((b) => b.addEventListener("click", async () => {
      const group = b.closest(".triage"), key = group.dataset.key;
      const next = b.getAttribute("aria-pressed") === "true" ? "open" : b.dataset.status;
      await post(`/api/findings/${enc(key)}`, { status: next });
      const holder = document.createElement("span");
      holder.innerHTML = triageButtons(key, next);
      const fresh = holder.firstElementChild;
      group.closest(".triage-wrap").replaceWith(fresh);
      wireTriage(fresh, after);
      after && after(key, next);
    }));
  }

  function findingsTab(box, d) {
    const fs = d.result ? d.result.findings : [];
    const flagged = fs.filter((f) => f.flagged), dropped = fs.filter((f) => !f.flagged);
    box.innerHTML = `${flagged.length ? flagged.map((f) => findingCard(f, d.run.id)).join("") : `<div class="empty small"><p>${d.result ? "Nothing reported on this pull request." : "Results appear here when the review finishes."}</p></div>`}
      ${dropped.length ? `<details class="dropped"><summary>${plural(dropped.length, "candidate")} LGTM checked and did not report</summary>${dropped.map((f) => findingCard(f, d.run.id)).join("")}</details>` : ""}`;
    wireTriage(box);
  }

  function changesTab(box, d) {
    const diff = (d.result && d.result.diff) || d.diff;
    const fs = d.result ? d.result.findings.filter((f) => f.flagged) : [];
    if (!diff || !diff.available) { box.innerHTML = `<div class="empty small"><p>The diff is not available for this run${diff && diff.reason ? ` (${esc(diff.reason)})` : ""}.</p></div>`; return; }
    const byLine = {};
    fs.forEach((f) => (byLine[`${f.file}:${f.line}`] = byLine[`${f.file}:${f.line}`] || []).push(f));
    const files = diff.files.slice().sort((a, b) => fs.some((f) => f.file === b.path) - fs.some((f) => f.file === a.path));
    box.innerHTML = `<div class="diff-wrap">${files.map((fd) => `
      <section class="dfile"><header><code>${esc(fd.path)}</code><span class="muted">${fd.status === "added" ? "new file" : fd.status}</span><span class="add">+${fd.additions}</span><span class="del">−${fd.deletions}</span>${fs.some((f) => f.file === fd.path) ? `<span class="sev high">${plural(fs.filter((f) => f.file === fd.path).length, "finding")}</span>` : ""}</header>
      ${fd.collapsed ? `<p class="muted pad">Large file with no findings, not shown.</p>` : `<table class="diff"><tbody>${fd.hunks.map((h) => `<tr class="hunk"><td colspan="3">${esc(h.header)}</td></tr>${h.lines.map((l) => {
        const k = `${fd.path}:${l.new}`;
        const cards = l.new != null && byLine[k] ? `<tr class="inline"><td colspan="3">${byLine[k].map((f) => findingCard(f, d.run.id)).join("")}</td></tr>` : "";
        return `<tr class="l ${l.t === "+" ? "add" : l.t === "-" ? "del" : ""} ${byLine[k] && l.new != null ? "flag" : ""}"><td class="ln">${l.old ?? ""}</td><td class="ln">${l.new ?? ""}</td><td class="code"><span class="sign">${l.t === " " ? "" : l.t}</span>${esc(l.text)}</td></tr>${cards}`;
      }).join("")}`).join("")}</tbody></table>`}</section>`).join("")}</div>`;
    wireTriage(box);
    const first = $(".flag", box);
    if (first) setTimeout(() => first.scrollIntoView({ block: "center" }), 60);
  }

  function traceTab(box, d) {
    const tr = d.result && d.result.trace;
    if (!tr || !tr.runs.length) { box.innerHTML = `<div class="empty small"><p>${d.result ? "No agent trace was recorded for this run." : "The trace appears when the review finishes. The Live tab shows it as it happens."}</p></div>`; return; }
    box.innerHTML = `<ol class="trace">${tr.runs.map((run) => `<li><details ${run.calls.length < 8 ? "open" : ""}><summary><b>${esc(AGENTS[run.agent] || run.agent)}</b> <span class="muted">${esc(run.label)}</span><span class="muted right">${plural(run.turns, "turn")}, ${plural(run.calls.length, "tool call")}</span></summary>
      <ol class="calls">${run.calls.map((c) => `<li><details><summary><span class="tool-kind ${c.kind}">${esc(TOOLS[c.kind] || c.tool)}</span> <code>${esc(argSummary(c.tool, c.args))}</code><span class="muted right">${c.result_chars.toLocaleString()} chars</span></summary><pre><code>${esc(c.result)}${c.result_chars > c.result.length ? "\n…" : ""}</code></pre></details></li>`).join("")}</ol></details></li>`).join("")}</ol>`;
  }

  // The full transcript of a review, terminal style: every line, scrollable, refreshed while the review runs.
  async function logTab(box, id) {
    box.innerHTML = `<p class="muted">Loading the log…</p>`;
    let wrap = (() => { try { return localStorage.getItem("lgtm-log-wrap") === "1"; } catch (e) { return false; } })();
    let last = "";
    const kindOf = (l) => { const k = (l.slice(10, 18).trim() || "").toLowerCase(); return ["warn", "error", "verdict", "result", "stage", "agent", "tool"].includes(k) ? k : ""; };
    const draw = (text, follow) => {
      const lines = (text || "").replace(/\n$/, "").split("\n").filter((l, i, a) => l || a.length > 1);
      const term = $(".term", box);
      const atEnd = term ? term.scrollTop + term.clientHeight >= term.scrollHeight - 8 : false;
      box.innerHTML = `<div class="termlog">
          <div class="term-bar"><span>${plural(lines.length, "line")}</span>
            <button type="button" class="btn" data-a="top">Start</button><button type="button" class="btn" data-a="end">End</button>
            <button type="button" class="btn" data-a="wrap" aria-pressed="${wrap}">Wrap lines</button><button type="button" class="btn" data-a="copy">Copy</button></div>
          <div class="term ${wrap ? "wrap" : ""}" tabindex="0" aria-label="Review log">${lines.length ? lines.map((l, i) => `<div class="tl ${kindOf(l)}"><span class="tn">${i + 1}</span><span class="tx">${esc(l)}</span></div>`).join("") : '<div class="tl"><span class="tx">No log lines yet.</span></div>'}</div></div>`;
      const t = $(".term", box);
      if (follow || atEnd) t.scrollTop = t.scrollHeight;
      box.querySelectorAll("[data-a]").forEach((b) => b.addEventListener("click", async () => {
        const a = b.dataset.a;
        if (a === "top") t.scrollTop = 0;
        if (a === "end") t.scrollTop = t.scrollHeight;
        if (a === "wrap") { wrap = !wrap; try { localStorage.setItem("lgtm-log-wrap", wrap ? "1" : "0"); } catch (e) { /* private window */ } draw(last, false); }
        if (a === "copy") { try { await navigator.clipboard.writeText(last); b.textContent = "Copied"; } catch (e) { b.textContent = "Copy failed"; } }
      }));
    };
    const load = async (follow) => {
      const text = await fetch(`/api/runs/${enc(id)}/log`).then((r) => r.text());
      if (text !== last) { last = text; draw(text, follow); }
    };
    await load(false);
    const run = await get(`/api/runs/${enc(id)}`).then((d) => d.run).catch(() => null);
    if (run && (run.status === "queued" || run.status === "running")) S.timers.push(setInterval(() => load(true), 3000));
  }

  // ---------------------------------------------------------------- findings inbox
  async function findingsPage(args, query) {
    const status = query.get("status") || "open,confirmed";
    const source = query.get("source") || "connected";  // triage is for your own repositories
    const rows = await get(`/api/findings?status=${enc(status)}&source=${source}`);
    const tabs = [["open,confirmed", "Needs attention"], ["accepted_risk", "Accepted risk"], ["false_positive", "False positive"], ["fixed", "Fixed"], ["open,confirmed,accepted_risk,false_positive,fixed", "All"]];
    page(`
      <header class="page-head row"><div><h1>Pull requests</h1>${prSwitch("findings")}<p>Security bugs LGTM reported on pull requests. Mark each one so the team knows where it stands.</p></div>${sourceSwitch(source, `#/findings`)}</header>
      <div class="filters">${tabs.map(([k, l]) => `<a href="#/findings?status=${k}&source=${source}" ${k === status ? 'aria-current="true"' : ""}>${l}</a>`).join("")}</div>
      <div class="inbox">
        <section class="panel flush inbox-list">${rows.length ? `<ul class="frows">${rows.map((f, i) => `<li><button type="button" data-i="${i}" aria-pressed="${i === 0}">
          <span class="sev ${f.severity}">${esc(f.severity)}</span>
          <span class="fr-main"><span class="fr-title">${esc(cweName(f.cwe))}</span><span class="fr-sub"><code>${esc(f.file)}:${f.line}</code></span><span class="fr-sub">${esc(f.repo)}${f.pr_number ? ` #${f.pr_number}` : ""} ${f.source === "imported" ? '<span class="tag imported">Benchmark</span>' : ""}</span></span>
          <span class="fr-side"><span class="state ${f.status}">${TRIAGE[f.status] || f.status}</span><span class="muted">${ago(f.created_at)}</span></span></button></li>`).join("")}</ul>` : `<div class="empty small"><p>Nothing here. ${status.startsWith("open") ? "No open findings: every reported bug has been triaged." : ""}</p></div>`}</section>
        <section class="panel inbox-detail" id="fdetail" aria-live="polite"></section>
      </div>`, "findings");
    const show = (i) => {
      const f = rows[i];
      if (!f) { $("#fdetail").innerHTML = ""; return; }
      $$(".frows button").forEach((b) => b.setAttribute("aria-pressed", String(+b.dataset.i === i)));
      $("#fdetail").innerHTML = `<header><span class="sev ${f.severity}">${esc(f.severity)}</span><h2>${esc(cweName(f.cwe))} <span class="muted">${esc(f.cwe || "")}</span></h2></header>
        <p class="fd-meta"><code>${esc(f.file)}:${f.line}</code><br>${esc(f.repo)}${f.pr_number ? ` #${f.pr_number}` : ""}: ${esc(f.pr_title || "")}</p>
        ${explained(f)}
        ${f.note ? `<p class="muted">${esc(f.note)}</p>` : ""}
        <div class="fd-actions">${f.source === "imported" ? "" : triageButtons(f.id, f.status)}<a class="btn" href="#/runs/${enc(f.run_id)}/findings">Open the review</a></div>`;
      wireTriage($("#fdetail"), (key, next) => { f.status = next; const b = $(`.frows button[data-i="${i}"] .state`); if (b) { b.className = `state ${next}`; b.textContent = TRIAGE[next]; } });
      if (needsBrief(f) && f.run_id) {
        get(`/api/runs/${enc(f.run_id)}/briefs`).then((b) => {
          if (!b[f.id]) return;
          f.brief = b[f.id];
          const btn = $(`.frows button[data-i="${i}"]`);
          if (btn && btn.getAttribute("aria-pressed") === "true") show(i);
        }).catch(() => {});
      }
    };
    $$(".frows button").forEach((b) => b.addEventListener("click", () => {
      show(+b.dataset.i);
      if (matchMedia("(max-width: 900px)").matches) $("#fdetail").scrollIntoView({ behavior: "smooth", block: "start" });
    }));
    show(0);
  }

  // ---------------------------------------------------------------- repositories
  async function reposPage(args, query) {
    const source = query.get("source") || "all";
    const repos = await get(`/api/repos?source=${source}`);
    page(`<header class="page-head row"><div><h1>Repositories</h1><p>Connected repositories are reviewed on every pull request. Benchmark repositories hold the runs LGTM was evaluated on.</p></div>
      <div class="row-actions">${sourceSwitch(source, "#/repos")}${S.me.install_url ? `<a class="btn" href="${esc(S.me.install_url)}" target="_blank" rel="noopener">Add repositories on GitHub</a>` : ""}</div></header>
      <section class="panel flush">${repoTable(repos)}</section>`);
  }

  async function repoPage(args) {
    const full = args.join("/");
    const [repos, runs, findings] = await Promise.all([get("/api/repos"), get(`/api/runs?repo=${enc(full)}`), get(`/api/findings?repo=${enc(full)}&status=open,confirmed,accepted_risk,false_positive,fixed`)]);
    const r = repos.find((x) => x.repo === full) || { repo: full, source: runs[0] ? runs[0].source : "github", runs: 0, flagged: 0, open: 0, blocked: 0 };
    page(`<nav class="crumbs" aria-label="Breadcrumb"><a href="#/repos">Repositories</a></nav>
      <header class="page-head row"><div><h1>${esc(full)}</h1><p>${r.source === "imported" ? "Benchmark history: these runs were scored against published advisories. LGTM is not installed here." : esc(r.description || "Connected through the LGTM GitHub App.")}</p></div>
        <div class="row-actions">${r.source === "github" && r.id ? `<label class="switch"><input type="checkbox" id="enabled" ${r.enabled ? "checked" : ""}> Review new pull requests</label> <a class="btn" href="https://github.com/${esc(full)}" target="_blank" rel="noopener">${I.gh}<span>Open on GitHub</span></a>` : ""}</div></header>
      <div class="kpis">${kpi("Reviews", r.runs, r.last ? `last ${ago(r.last.created_at)}` : "none yet")}${kpi("Security bugs found", r.flagged, `${r.open} open`, "risk")}${kpi("Merges blocked", r.blocked, "by policy")}${kpi("Median review time", secs(r.median_latency), "per pull request")}</div>
      <div class="grid-2"><section class="panel"><h2>Pull requests</h2>${runList(runs)}</section>
      <section class="panel"><h2>Findings</h2>${findings.length ? `<ul class="flist">${findings.map((f) => `<li><a href="#/runs/${enc(f.run_id)}/findings"><span class="sev ${f.severity}">${esc(f.severity)}</span> ${esc(cweName(f.cwe))} <code>${esc(f.file)}:${f.line}</code> <span class="state ${f.status}">${TRIAGE[f.status]}</span></a></li>`).join("")}</ul>` : `<p class="muted">No findings.</p>`}</section></div>`);
    const en = $("#enabled");
    if (en) en.addEventListener("change", () => post(`/api/repos/${r.id}`, { enabled: en.checked }));
  }

  // ---------------------------------------------------------------- accuracy
  async function accuracyPage() {
    const a = await get("/api/accuracy");
    page(`<header class="page-head"><h1>Accuracy</h1><p>How LGTM scores on pull requests with a known answer: real security advisories from open-source Python projects (the change that introduced the bug, and the change that fixed it), plus a synthetic shop. The held-out set was chosen after the reviewers were built and run once, untuned.</p></header>${accuracyBlocks(a)}`);
  }

  function accuracyBlocks(a) {
    const rate = (x, y) => (y ? `${Math.round((100 * x) / y)}%` : "–");
    const lgtmRows = a.sets.map((s) => ({ set: s, m: s.modes.find((m) => m.mode === "lgtm") })).filter((x) => x.m);
    const dev = a.sets.find((s) => s.id === "real_prs");
    return `<section class="panel flush"><div class="table-wrap"><table class="table">
        <thead><tr><th scope="col">Evaluation set</th><th scope="col" class="num">Bugs caught</th><th scope="col" class="num">Recall</th><th scope="col" class="num">False alarms on fixes</th><th scope="col" class="num">Precision</th><th scope="col" class="num">Median time</th></tr></thead>
        <tbody>${lgtmRows.map(({ set, m }) => `<tr><th scope="row">${esc(set.label)}<span class="row-note">${esc(set.note)}</span></th>
          <td class="num">${m.TP} of ${m.TP + m.FN}</td><td class="num"><b>${rate(m.TP, m.TP + m.FN)}</b></td><td class="num">${m.FP} of ${m.FP + m.TN}</td><td class="num"><b>${rate(m.TP, m.TP + m.FP)}</b></td><td class="num">${secs(m.median_latency)}</td></tr>`).join("")}</tbody></table></div></section>
      ${dev ? `<section class="panel"><h2>Why the agents and the judge matter</h2><p class="note">Same 26 pull requests (development set), three ways of reviewing them.</p>
        <div class="compare">${dev.modes.map((m) => `<div class="cmp"><h3>${esc({ lgtm: "LGTM", "llm-only": "The same model, prompted directly", "sast-only": "Semgrep alone" }[m.mode] || m.label)}</h3>
          ${meter("Bugs caught", m.TP, m.TP + m.FN)}${meter("Quiet on fixed code", m.TN, m.TN + m.FP)}</div>`).join("")}</div></section>` : ""}
      <p class="note">These numbers come from the project's benchmark runs, the same runs listed as "Imported from benchmark" in the history.</p>`;
  }

  function meter(label, n, of) {
    const pct = of ? (100 * n) / of : 0;
    return `<div class="meter"><span class="m-label">${esc(label)}</span><span class="m-track"><span class="m-fill" style="width:${pct.toFixed(1)}%"></span></span><span class="m-n">${n}/${of}</span></div>`;
  }

  // ---------------------------------------------------------------- settings
  async function settingsPage() {
    const [st, h, deliveries] = await Promise.all([get("/api/settings"), get("/api/health"), get("/api/deliveries")]);
    const app = h.app;
    page(`<header class="page-head"><h1>Settings</h1></header>
      <div class="settings">
        <section class="panel"><h2>Merge policy</h2>
          <label class="field"><span>Fail the LGTM check at or above</span>
            <select data-set="block_on">${["critical", "high", "medium", "low"].map((s) => `<option value="${s}" ${st.block_on === s ? "selected" : ""}>${s[0].toUpperCase() + s.slice(1)} severity</option>`).join("")}</select></label>
          <p class="note">Require the "LGTM security review" check in the branch's protection rules and a failing check blocks the merge.</p>
          <label class="switch"><input type="checkbox" data-set="request_changes" ${st.request_changes ? "checked" : ""}> Request changes when the check fails</label>
          <label class="switch"><input type="checkbox" data-set="inline_comments" ${st.inline_comments ? "checked" : ""}> Comment on the flagged lines</label>
          <label class="switch"><input type="checkbox" data-set="auto_review" ${st.auto_review ? "checked" : ""}> Review every new and updated pull request</label>
        </section>
        <section class="panel"><h2>Models</h2>
          <dl class="kv"><dt>GPU reviewer</dt><dd><span class="dot ${h.reviewer ? "ok" : "off"}">${esc(h.gpu ? h.gpu.reviewer.detail : h.reviewer ? "Reachable" : "Not reachable")}</span></dd>
            <dt>API reviewer</dt><dd><span class="dot ${h.bedrock ? "ok" : "off"}">${h.bedrock ? "Bedrock key found (capped spend)" : esc(h.bedrock_error || "No Bedrock key in .env")}</span></dd>
            <dt>Judge</dt><dd><span class="dot ${h.judge ? "ok" : "off"}">${esc(h.gpu ? h.gpu.judge.detail : h.judge ? "Reachable" : "Not reachable")}</span></dd></dl>
          <label class="field"><span>Run the reviewer on</span><select data-set="backend"><option value="gpu" ${st.backend === "gpu" ? "selected" : ""}>GPU: Qwen 3.8 27B on our GPU job</option><option value="bedrock" ${st.backend === "bedrock" ? "selected" : ""} ${h.bedrock ? "" : "disabled"}>API: Claude on Amazon Bedrock (capped spend)</option></select></label>
          <p class="note">Also switchable from the GPU / API toggle in the header.</p>
          <label class="field"><span>Evidence judge</span><select data-set="judge"><option value="kev" ${st.judge !== "claude" ? "selected" : ""}>Kev-4B: on this Mac or the GPU job (port 8008)</option><option value="claude" ${st.judge === "claude" ? "selected" : ""} ${h.bedrock ? "" : "disabled"}>Claude via the API: a stand-in, not the evaluated judge</option></select></label>
          <p class="note">Kev is the judge LGTM was evaluated with. The Claude judge answers the same questions when Kev is not running; reviews it decides are labelled “Claude judge”.</p>
        </section>
        <section class="panel"><h2>GitHub App</h2>
          ${app ? `<dl class="kv"><dt>App</dt><dd><a href="${esc(app.html_url)}" target="_blank" rel="noopener">${esc(app.name)}</a></dd><dt>Owner</dt><dd>${esc(app.owner)}</dd>
            <dt>Installed on</dt><dd>${h.installations.map((i) => esc(i.account)).join(", ") || "nowhere yet"}</dd>
            <dt>Permissions</dt><dd>Code: read. Pull requests and checks: write.</dd></dl>
            ${S.me.install_url ? `<a class="btn" href="${esc(S.me.install_url)}" target="_blank" rel="noopener">Manage repositories on GitHub</a>` : ""}` : `<p>Not created yet. <a href="/setup.html">Create the app</a></p>`}
        </section>
        <section class="panel"><h2>Webhook delivery</h2>
          <dl class="kv"><dt>Relay</dt><dd><span class="dot ${h.relay.connected ? "ok" : "off"}">${h.relay.connected ? `Connected since ${when(h.relay.since)}` : "Offline"}</span></dd>
            <dt>Polling fallback</dt><dd>${h.poll.last ? `Checked ${ago(h.poll.last)}, ${plural(h.poll.seen_prs, "open pull request")}` : "Not run yet"}${h.poll.error ? ` <span class="risk">${esc(h.poll.error)}</span>` : ""}</dd></dl>
          <button class="btn" type="button" id="sync">Check GitHub now</button>
          <h3>Recent deliveries</h3>
          ${deliveries.length ? `<div class="table-wrap"><table class="table small"><thead><tr><th scope="col">Received</th><th scope="col">Event</th><th scope="col">Via</th><th scope="col">Signature</th><th scope="col">Result</th></tr></thead><tbody>${deliveries.slice(0, 12).map((d) => `<tr><td>${when(d.received_at)}</td><td>${esc(d.event)}${d.action ? `.${esc(d.action)}` : ""}<br><span class="muted">${esc(d.repo)}</span></td><td>${esc(d.via)}</td><td>${d.verified ? "Valid" : '<b class="risk">Rejected</b>'}</td><td>${esc(d.outcome)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">None yet.</p>`}
        </section>
        <section class="panel"><h2>Appearance</h2><div class="theme-cards">${THEMES.map(([k, l]) => `<button type="button" class="theme-card" data-theme-pick="${k}" aria-pressed="${document.documentElement.dataset.theme === k}"><span class="sw sw-${k}" aria-hidden="true"></span>${l}</button>`).join("")}</div></section>
      </div>`, "settings-page");
    $$("[data-set]").forEach((el) => el.addEventListener("change", async () => {
      const v = el.type === "checkbox" ? el.checked : el.value;
      await post("/api/settings", { [el.dataset.set]: v });
      if (el.dataset.set === "backend") pollHealth();
    }));
    $$(".theme-card").forEach((b) => b.addEventListener("click", () => setTheme(b.dataset.themePick)));
    $("#sync").addEventListener("click", async (e) => { e.target.disabled = true; e.target.textContent = "Checking…"; await post("/api/sync").catch(() => {}); route(); });
  }

  // Helpers the workspace tab (workspace.js) builds on.
  window.LGTM = { $, $$, esc, get, post, secs, ago, when, plural, short, enc, page, view, S, I, stageLabel, conclusionBadge };

  // ---------------------------------------------------------------- boot
  async function loadMe() { S.me = await get("/api/me"); }

  async function boot() {
    // index.html already set data-theme before first paint; setTheme (in shell) syncs the toggle and the editor.
    await loadMe();
    shell();
    await pollHealth();
    route();
  }

  window.addEventListener("hashchange", () => { route(); const v = view(); if (v) v.focus({ preventScroll: true }); window.scrollTo(0, 0); });
  setInterval(pollHealth, 5000);

  // If the dashboard's own files change on disk (a new version), say so instead of running stale code.
  const FILES = ["/app.js", "/workspace.js", "/shop.js", "/landing.js", "/base.css"];
  let stamps = null;
  async function checkVersion() {
    try {
      const now = await Promise.all(FILES.map((f) => fetch(f, { method: "HEAD", cache: "no-store" }).then((r) => r.headers.get("Last-Modified") || "")));
      if (!stamps) { stamps = now; return; }
      if (now.join() !== stamps.join() && !document.getElementById("update-bar")) {
        const bar = document.createElement("div");
        bar.id = "update-bar";
        bar.innerHTML = `<span>LGTM was updated. Reload to use the latest version.</span><button type="button" class="btn primary">Reload</button>`;
        bar.querySelector("button").addEventListener("click", () => location.reload());
        document.body.appendChild(bar);
      }
    } catch (e) { /* server restarting */ }
  }
  checkVersion();
  setInterval(checkVersion, 10000);
  boot();
})();
