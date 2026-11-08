// LGTM workspace: a simple code editor over a connected repository. Browse, search and edit files; let the
// assistant write code (a scripted replay of a real commit, or Claude on Bedrock); then commit, push and open a
// real pull request, and follow LGTM's review of it. Uses helpers from app.js (window.LGTM).
(function () {
  "use strict";

  const MONACO = "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min";
  const W = { repo: null, models: new Map(), tabs: [], active: null, side: "files", openDirs: new Set(), animating: false,
    skip: false, commit: null, st: null, files: [], diffOf: null, monacoP: null, editor: null, diffEditor: null, decos: new Map(),
    presets: [], task: null, pr: null, run: null, prCommit: null, prTimer: null, q: "", hits: null,
    mode: "code", hasApp: false, app: { routes: [], persona: "alice", tokens: {}, log: [], attack: {} } };

  const L = () => window.LGTM;
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));
  const esc = (s) => L().esc(s);
  const enc = encodeURIComponent;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const frame = () => new Promise((r) => requestAnimationFrame(() => r()));
  const stamp = () => { const d = new Date(); const p = (n) => String(n).padStart(2, "0"); return `${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`; };
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const dark = () => document.documentElement.dataset.theme === "dark";
  const base = (p) => p.split("/").pop();
  const dirOf = (p) => p.split("/").slice(0, -1).join("/");

  const sv = (d) => `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  const IC = {
    search: sv('<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>'),
    branch: sv('<circle cx="6" cy="5.5" r="2"/><circle cx="6" cy="18.5" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 7.5v9M18 10c0 4-6 3.5-11 7"/>'),
    spark: sv('<path d="M12 4.5 13.8 10.2 19.5 12l-5.7 1.8L12 19.5l-1.8-5.7L4.5 12l5.7-1.8z"/>'),
    play: sv('<path d="M8 5.5v13l10-6.5z"/>'),
    chev: sv('<path d="m9 6 6 6-6 6"/>'),
    ext: sv('<path d="M14 5h5v5M19 5l-8 8M17 14v5H5V7h5"/>'),
    x: sv('<path d="M7 7l10 10M17 7 7 17"/>'),
    file: sv('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'),
  };

  // ---------------------------------------------------------------- Monaco (from the CDN, loaded on first use)
  function loadMonaco() {
    if (window.monaco) return Promise.resolve(window.monaco);
    if (W.monacoP) return W.monacoP;
    W.monacoP = new Promise((resolve, reject) => {
      window.MonacoEnvironment = { getWorkerUrl: () => `data:text/javascript;charset=utf-8,${encodeURIComponent(`self.MonacoEnvironment={baseUrl:'${MONACO}/'};importScripts('${MONACO}/vs/base/worker/workerMain.js');`)}` };
      const s = document.createElement("script");
      s.src = `${MONACO}/vs/loader.js`;
      s.onload = () => {
        window.require.config({ paths: { vs: `${MONACO}/vs` } });
        window.require(["vs/editor/editor.main"], () => {
          const m = window.monaco;
          m.editor.defineTheme("lgtm-light", { base: "vs", inherit: true, rules: [], colors: {
            "editor.background": "#ffffff", "editor.lineHighlightBackground": "#f6f6f6", "editor.lineHighlightBorder": "#00000000",
            "editorLineNumber.foreground": "#b4b4b4", "editorLineNumber.activeForeground": "#555555", "editorIndentGuide.background1": "#efefef",
            "editorGutter.background": "#ffffff", "scrollbarSlider.background": "#0000001a", "diffEditor.insertedLineBackground": "#1a7f3714",
            "diffEditor.removedLineBackground": "#d9303614" } });
          m.editor.defineTheme("lgtm-dark", { base: "vs-dark", inherit: true, rules: [], colors: { "editor.background": "#17181d", "editorGutter.background": "#17181d", "editor.lineHighlightBackground": "#1f2027" } });
          resolve(m);
        }, reject);
      };
      s.onerror = () => { W.monacoP = null; reject(new Error("The code editor could not load. Check the internet connection and reload.")); };
      document.head.appendChild(s);
    });
    return W.monacoP;
  }
  const theme = () => (dark() ? "lgtm-dark" : "lgtm-light");

  // ---------------------------------------------------------------- page
  window.LGTMWorkspace = async function workspacePage(args, query) {
    const { get, post, page, S } = L();
    const repos = (await get("/api/repos?source=connected")).filter((r) => r.source === "github" && !r.removed);
    if (!repos.length) {
      page(`<header class="page-head"><h1>Workspace</h1><p>Connect a repository first: the workspace edits and pushes to repositories LGTM is installed on.</p></header><p><a class="btn primary" href="#/onboarding">Connect a repository</a></p>`);
      return;
    }
    const want = query.get("repo") || W.repo;
    const repo = (repos.find((r) => r.repo === want) || repos.find((r) => r.repo.endsWith("/shoply-demo")) || repos[0]).repo;
    if (repo !== W.repo) { resetEditorState(); W.pr = null; W.run = null; W.prCommit = null; W.q = ""; W.hits = null; W.task = null; }
    W.repo = repo;
    W.presets = (await get("/api/ws/presets")).filter((p) => p.repo === repo);
    W.hasApp = (await get("/api/ws/apps").catch(() => [])).includes(repo);
    if (!W.hasApp) W.mode = "code";
    if (!W.presets.some((p) => p.id === W.task)) W.task = (W.presets.find((p) => !p.follows) || W.presets[0] || {}).id || null;
    page(`
      <div class="ide" id="ide">
        <div class="ide-bar">
          <label class="ide-repo"><span class="sr-only">Repository</span><select id="ws-repo">${repos.map((r) => `<option value="${esc(r.repo)}" ${r.repo === repo ? "selected" : ""}>${esc(r.repo)}</option>`).join("")}</select></label>
          <span class="ide-branch" id="ws-branch"></span>
          ${W.hasApp ? `<div class="ide-mode" role="tablist" aria-label="View"><button type="button" role="tab" data-mode="code" aria-selected="${W.mode === "code"}">Code</button><button type="button" role="tab" data-mode="app" aria-selected="${W.mode === "app"}">App</button></div>` : ""}
          <span class="ide-fill"></span>
          <span class="ide-dim" id="ws-who"></span>
          <button type="button" class="btn" id="ws-reset">Start over</button>
        </div>
        <div class="ide-ai">
          <span class="ide-ai-tag">${IC.spark}AI</span>
          ${W.presets.length ? `<label class="sr-only" for="ws-task">Recorded change to replay</label>
            <select id="ws-task">${W.presets.map((p) => `<option value="${esc(p.id)}" ${p.id === W.task ? "selected" : ""}>${esc(p.title)}${p.realworld ? " (real-world)" : ""}</option>`).join("")}</select>
            <button type="button" class="btn primary" id="ws-play">${IC.play}<span>Write it live</span></button>
            <span class="ide-or">or</span>` : ""}
          <label class="sr-only" for="ws-prompt">Ask Claude to change the open file</label>
          <input id="ws-prompt" type="text" placeholder="Ask Claude to change this file…" autocomplete="off">
          <button type="button" class="btn" id="ws-gen">Ask Claude</button>
        </div>
        <div class="ide-note" id="ws-note" aria-live="polite"></div>
        <div class="ide-main">
          <aside class="ide-side" aria-label="Files and changes">
            <div class="ide-switch" role="tablist">
              <button type="button" role="tab" data-side="files">Files</button>
              <button type="button" role="tab" data-side="changes">Changes <span class="ide-count" id="ws-count" hidden></span></button>
            </div>
            <div class="ide-side-b" id="ws-side"></div>
          </aside>
          <section class="ide-editor" aria-label="Editor">
            <div class="ide-tabs" id="ws-tabs" role="tablist"></div>
            <div class="ide-stage">
              <div class="ide-monaco" id="ws-monaco"></div>
              <div class="ide-monaco" id="ws-diff" hidden></div>
              <div class="ide-empty" id="ws-empty"><p>Open a file, or pick a change above and press <b>Write it live</b>.</p></div>
            </div>
          </section>
        </div>
        <section class="ide-app" id="ws-app" hidden aria-label="The app, running from the workspace"></section>
        <section class="ide-term" id="ws-term" hidden aria-label="Terminal" aria-live="polite"></section>
        <div class="ide-review" id="ws-review" hidden aria-live="polite"></div>
      </div>`, "ws-page");
    S.leave.push(disposeEditors);
    const fit = () => { const ide = $("#ide"); if (ide && window.innerWidth > 760) ide.style.height = `${Math.max(560, window.innerHeight - (ide.getBoundingClientRect().top + window.scrollY))}px`; };
    fit();
    window.addEventListener("resize", fit);
    S.leave.push(() => window.removeEventListener("resize", fit));
    wire();
    renderNote();
    renderSide();

    const ready = loadMonaco().catch((e) => { note(`<span class="bad">${esc(e.message)}</span>`); throw e; });
    let st = await get(`/api/ws/state?repo=${enc(repo)}`);
    if (!st.opened) {
      note(`<span class="pulse"></span>Cloning ${esc(repo)}…`);
      st = (await post("/api/ws/open", { repo })).state;
    }
    await ready;
    createEditor();
    await refreshTree();
    const first = (W.tabs.length && W.tabs.slice()) || (st.changed.length ? [st.changed[0].path] : [W.files.find((f) => /^readme/i.test(f)) || W.files.find((f) => f.endsWith(".py")) || W.files[0]]);
    const keep = W.active;
    for (const p of first.filter(Boolean)) await openFile(p, { focus: false });
    if (keep && W.models.has(keep)) showFile(keep); else if (first[0]) showFile(first[0]);
    renderNote();
    if (W.pr || st.pr) followPR(W.pr || st.pr, W.prCommit);
    if (W.mode === "app") setMode("app");
  };

  function wire() {
    $("#ws-repo").addEventListener("change", (e) => { location.hash = `#/workspace?repo=${enc(e.target.value)}`; });
    $("#ws-reset").addEventListener("click", startOver);
    $$("[data-side]").forEach((b) => b.addEventListener("click", () => { W.side = b.dataset.side; renderSide(); }));
    $$("[data-mode]").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
    const task = $("#ws-task");
    if (task) task.addEventListener("change", () => { W.task = task.value; renderNote(); });
    const play = $("#ws-play");
    if (play) play.addEventListener("click", () => runTask(W.task));
    $("#ws-gen").addEventListener("click", generate);
    $("#ws-prompt").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); generate(); } });
    const onKey = (e) => {
      if (!$("#ide")) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "p") { e.preventDefault(); W.side = "files"; renderSide(); const q = $("#ws-q"); if (q) q.focus(); }
    };
    document.addEventListener("keydown", onKey);
    L().S.leave.push(() => document.removeEventListener("keydown", onKey));
  }

  // The line under the toolbar: what the chosen change is, or what is happening now.
  function renderNote() {
    if (W.animating) return;
    const p = W.presets.find((x) => x.id === W.task);
    note(p ? `<span class="ide-ask"><span class="ide-tagl">Task</span>${esc(p.ask)}</span><span class="ide-expect"><span class="ide-tagl">LGTM should find</span>${esc(p.expect)}</span>` : "");
  }
  function note(html) { const el = $("#ws-note"); if (el) el.innerHTML = html; }

  function ask(title, body, ok) {
    return new Promise((resolve) => {
      const host = $("#ide") || document.body;
      const box = document.createElement("div");
      box.className = "ide-ask-modal";
      box.innerHTML = `<div class="ide-ask-card" role="alertdialog" aria-modal="true" aria-labelledby="ask-t" aria-describedby="ask-b">
          <h3 id="ask-t">${esc(title)}</h3><p id="ask-b">${esc(body)}</p>
          <div class="ide-ask-btns"><button type="button" class="btn" data-a="no">Cancel</button><button type="button" class="btn primary" data-a="yes">${esc(ok)}</button></div></div>`;
      host.appendChild(box);
      const done = (v) => { box.remove(); document.removeEventListener("keydown", key); resolve(v); };
      const key = (e) => { if (e.key === "Escape") done(false); };
      document.addEventListener("keydown", key);
      box.addEventListener("click", (e) => { if (e.target === box) done(false); const a = e.target.closest("[data-a]"); if (a) done(a.dataset.a === "yes"); });
      box.querySelector('[data-a="yes"]').focus();
    });
  }

  function resetEditorState() {
    W.models.forEach((m) => m.model.dispose());
    W.models.clear(); W.tabs = []; W.active = null; W.openDirs.clear(); W.commit = null; W.diffOf = null; W.decos.clear();
  }
  function disposeEditors() {
    W.skip = true;
    if (W.prTimer) { clearInterval(W.prTimer); W.prTimer = null; }
    if (W.editor) { W.editor.dispose(); W.editor = null; }
    if (W.diffEditor) { W.diffEditor.dispose(); W.diffEditor = null; }
  }

  function createEditor() {
    W.editor = window.monaco.editor.create($("#ws-monaco"), { model: null, theme: theme(), automaticLayout: true, minimap: { enabled: false },
      fontSize: 13, lineHeight: 20, scrollBeyondLastLine: false, renderLineHighlight: "line", padding: { top: 10 }, overviewRulerBorder: false,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", guides: { indentation: true }, folding: false, glyphMargin: false, lineDecorationsWidth: 8 });
    W.saveSoon = debounce(saveActive, 500);
  }

  // ---------------------------------------------------------------- side panel: files (tree and search) or changes
  function renderSide() {
    $$("[data-side]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.side === W.side)));
    const el = $("#ws-side");
    if (!el) return;
    if (W.side === "files") {
      el.innerHTML = `<div class="ide-search">${IC.search}<input id="ws-q" type="search" placeholder="Search files and code (⌘P)" value="${esc(W.q)}" autocomplete="off" spellcheck="false" aria-label="Search files and code"></div><div class="ide-list-wrap" id="ws-files"></div>`;
      const q = $("#ws-q");
      q.addEventListener("input", () => { W.q = q.value; renderFiles(); searchCode(); });
      renderFiles();
    } else {
      el.innerHTML = `<div id="ws-changes"></div>`;
      renderChanges();
    }
  }

  async function refreshState() {
    W.st = await L().get(`/api/ws/state?repo=${enc(W.repo)}`);
    const st = W.st;
    const br = $("#ws-branch");
    if (br) br.innerHTML = `${IC.branch}<span>${st.branch ? esc(st.branch) : `${esc(st.default_branch || "main")} at ${esc(st.head)}`}</span>`;
    const who = $("#ws-who");
    if (who && st.login) who.textContent = `Pushes as ${st.login}`;
    const count = $("#ws-count");
    if (count) { count.hidden = !st.changed.length; count.textContent = st.changed.length; }
    if (W.side === "changes") renderChanges(); else renderFiles();
    renderTabs();
    return st;
  }

  async function refreshTree() {
    W.files = (await L().get(`/api/ws/tree?repo=${enc(W.repo)}`)).files;
    await refreshState();
  }

  function changedMap() { const m = {}; ((W.st && W.st.changed) || []).forEach((c) => (m[c.path] = c.status)); return m; }
  const mark = (s) => (s ? `<span class="ide-mark ${s}" title="${s === "A" ? "New file" : s === "D" ? "Deleted" : "Changed"}">${s === "A" ? "U" : s}</span>` : "");

  function renderFiles() {
    const el = $("#ws-files");
    if (!el) return;
    const ch = changedMap();
    const q = W.q.trim().toLowerCase();
    if (q) {
      const names = W.files.filter((f) => f.toLowerCase().includes(q)).sort((a, b) => (base(a).toLowerCase().startsWith(q) ? 0 : 1) - (base(b).toLowerCase().startsWith(q) ? 0 : 1) || a.length - b.length).slice(0, 40);
      const hits = W.hits && W.hits.q === W.q.trim() ? W.hits : null;
      const re = new RegExp(W.q.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "ig");
      const by = {};
      (hits ? hits.hits : []).forEach((h) => (by[h.path] = by[h.path] || []).push(h));
      el.innerHTML = `<p class="ide-group">Files</p>${names.length ? `<ul class="ide-list">${names.map((f) => `<li><button type="button" class="ide-row ${f === W.active ? "on" : ""}" data-path="${esc(f)}"><span class="ide-fn">${esc(base(f))}</span><span class="ide-dir">${esc(dirOf(f))}</span>${mark(ch[f])}</button></li>`).join("")}</ul>` : `<p class="ide-dim pad">No file names match.</p>`}
        <p class="ide-group">In code</p>${q.length < 2 ? `<p class="ide-dim pad">Type two characters or more.</p>` : !hits ? `<p class="ide-dim pad">Searching…</p>` : !hits.hits.length ? `<p class="ide-dim pad">No matches.</p>`
          : `<ul class="ide-list">${Object.keys(by).map((p) => `<li class="ide-hits"><p class="ide-hitfile">${esc(base(p))} <span class="ide-dir">${esc(dirOf(p))}</span></p>${by[p].slice(0, 12).map((h) => `<button type="button" class="ide-row hit" data-path="${esc(p)}" data-line="${h.line}"><span class="ide-ln">${h.line}</span><code>${esc(h.text.trim()).replace(re, (m) => `<mark>${m}</mark>`)}</code></button>`).join("")}</li>`).join("")}</ul>`}`;
    } else {
      const root = {};
      W.files.forEach((f) => { let n = root; const parts = f.split("/"); parts.forEach((p, i) => { if (i === parts.length - 1) (n.__f = n.__f || []).push(f); else n = n[p] = n[p] || {}; }); });
      if (W.active) { const parts = W.active.split("/"); for (let i = 1; i < parts.length; i++) W.openDirs.add(parts.slice(0, i).join("/")); }
      const hot = new Set(Object.keys(ch).flatMap((p) => p.split("/").slice(0, -1).map((_, i, a) => a.slice(0, i + 1).join("/"))));
      const walk = (node, prefix, d) => Object.keys(node).filter((k) => k !== "__f").sort().map((name) => {
        const path = prefix ? `${prefix}/${name}` : name;
        return `<li><details data-dir="${esc(path)}" ${W.openDirs.has(path) ? "open" : ""}><summary class="ide-row dir" style="--d:${d}">${IC.chev}<span class="ide-fn">${esc(name)}</span>${hot.has(path) ? '<span class="ide-dot"></span>' : ""}</summary><ul>${walk(node[name], path, d + 1)}</ul></details></li>`;
      }).concat((node.__f || []).sort().map((f) => `<li><button type="button" class="ide-row ${f === W.active ? "on" : ""} ${ch[f] ? "changed" : ""}" data-path="${esc(f)}" style="--d:${d}"><span class="ide-fn">${esc(base(f))}</span>${mark(ch[f])}</button></li>`)).join("");
      el.innerHTML = `<ul class="ide-list tree">${walk(root, "", 0)}</ul>`;
      el.querySelectorAll("details[data-dir]").forEach((x) => x.addEventListener("toggle", () => { if (x.open) W.openDirs.add(x.dataset.dir); else W.openDirs.delete(x.dataset.dir); }));
    }
    el.querySelectorAll("[data-path]").forEach((b) => b.addEventListener("click", async () => { await openFile(b.dataset.path); if (b.dataset.line) revealLine(+b.dataset.line); }));
  }

  const searchCode = debounce(async () => {
    const q = W.q.trim();
    if (q.length < 2) return;
    const r = await L().get(`/api/ws/search?repo=${enc(W.repo)}&q=${enc(q)}`).catch(() => ({ hits: [] }));
    if (W.q.trim() !== q) return;
    W.hits = { q, hits: r.hits };
    renderFiles();
  }, 300);

  // ---------------------------------------------------------------- files and tabs
  async function openFile(path, { focus = true, content } = {}) {
    const monaco = window.monaco;
    if (!monaco) return;
    if (!W.models.has(path) || content !== undefined) {
      let text = content, reason = null;
      if (text === undefined) {
        const f = await L().get(`/api/ws/file?repo=${enc(W.repo)}&path=${enc(path)}`).catch(() => ({ content: "" }));
        text = f.content ?? "";
        reason = f.content == null ? f.reason : null;
      }
      if (W.models.has(path)) W.models.get(path).model.setValue(text);
      else {
        const model = monaco.editor.createModel(text, undefined, monaco.Uri.parse(`file:///${enc(W.repo)}/${path.split("/").map(enc).join("/")}`));
        model.onDidChangeContent(() => { if (!W.animating && W.active === path && !W.models.get(path).readonly) W.saveSoon(); });
        W.models.set(path, { model, readonly: !!reason, reason });
      }
    }
    if (!W.tabs.includes(path)) W.tabs.push(path);
    showFile(path, focus);
  }

  function showFile(path, focus = false) {
    if (!W.editor || !W.models.has(path)) return;
    W.active = path;
    W.diffOf = null;
    const entry = W.models.get(path);
    $("#ws-diff").hidden = true;
    $("#ws-monaco").hidden = false;
    $("#ws-empty").hidden = true;
    W.editor.setModel(entry.model);
    W.editor.updateOptions({ readOnly: W.animating || entry.readonly });
    if (focus && !W.animating) W.editor.focus();
    renderTabs();
    if (W.side === "files") renderFiles(); else renderChanges();
  }

  function renderTabs() {
    const el = $("#ws-tabs");
    if (!el) return;
    const ch = changedMap();
    el.innerHTML = W.tabs.map((p) => `<div class="ide-tab ${p === W.active && !W.diffOf ? "on" : ""}" role="tab" aria-selected="${p === W.active && !W.diffOf}">
        <button type="button" data-open="${esc(p)}" title="${esc(p)}">${esc(base(p))}${mark(ch[p])}</button>
        <button type="button" class="ide-x" data-close="${esc(p)}" aria-label="Close ${esc(p)}">${IC.x}</button></div>`).join("")
      + (W.diffOf ? `<div class="ide-tab on" role="tab" aria-selected="true"><button type="button">${esc(base(W.diffOf))}: changes</button><button type="button" class="ide-x" data-close-diff aria-label="Close the diff">${IC.x}</button></div>` : "");
    el.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => showFile(b.dataset.open, true)));
    el.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => closeTab(b.dataset.close)));
    el.querySelectorAll("[data-close-diff]").forEach((b) => b.addEventListener("click", () => (W.active ? showFile(W.active, true) : closeDiff())));
    const on = el.querySelector(".on");
    if (on) on.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  function closeTab(path) {
    if (W.animating) return;
    W.tabs = W.tabs.filter((p) => p !== path);
    const entry = W.models.get(path);
    if (entry) { entry.model.dispose(); W.models.delete(path); }
    if (W.active === path) {
      const next = W.tabs[W.tabs.length - 1];
      if (next) showFile(next);
      else { W.active = null; if (!W.diffOf) { W.editor.setModel(null); $("#ws-empty").hidden = false; } renderTabs(); renderFiles(); }
    } else renderTabs();
  }
  function closeDiff() { W.diffOf = null; $("#ws-diff").hidden = true; $("#ws-empty").hidden = false; renderTabs(); }

  function revealLine(line) {
    if (!W.editor) return;
    W.editor.revealLineInCenter(line);
    W.editor.setPosition({ lineNumber: line, column: 1 });
    const c = W.editor.createDecorationsCollection([{ range: new window.monaco.Range(line, 1, line, 1), options: { isWholeLine: true, className: "ws-flash" } }]);
    setTimeout(() => c.clear(), 1600);
  }

  async function saveActive() {
    const path = W.active;
    if (!path || W.animating) return;
    const entry = W.models.get(path);
    if (!entry || entry.readonly) return;
    await L().post("/api/ws/file", { repo: W.repo, path, content: entry.model.getValue() });
    if (!W.commit) W.commit = { branch: `lgtm-demo/change-${stamp()}`, message: "", title: "", how: "manual" };
    await refreshState();
  }

  // ---------------------------------------------------------------- the assistant: scripted replay
  async function runTask(id) {
    if (W.animating || !id) return;
    const preset = W.presets.find((p) => p.id === id);
    const follow = !!(preset && preset.follows);
    const st = W.st || {};
    if (!follow && st.changed && st.changed.length && !(await ask("Start from a clean copy?", "Your current edits in the workspace will be discarded.", "Discard and write it"))) return;
    setBusy(true);
    note(`<span class="pulse"></span>Getting ready…`);
    let r;
    try {
      r = await L().post("/api/ws/open", { repo: W.repo, preset: id });
    } catch (e) { setBusy(false); note(`<span class="bad">${esc(e.message)}</span>`); return; }
    if (!follow) { resetEditorState(); W.editor.setModel(null); clearPR(); }
    const script = r.script;
    await refreshTree();
    await play(script.steps);
    W.commit = { branch: script.branch, message: script.message, title: script.title, how: "replay" };
    setBusy(false);
    W.side = "changes";
    renderSide();
    await refreshState();
    note(`<span class="good">Wrote ${L().plural(script.steps.length, "file")}. Check the changes on the left, then commit and push.</span>`);
  }

  async function play(steps) {
    const monaco = window.monaco;
    W.skip = false;
    const total = steps.reduce((a, s) => a + lineDiff(s.before.split("\n"), s.after.split("\n")).reduce((b, h) => b + h.lines.join("\n").length, 0), 0);
    const perFrame = Math.max(1, Math.ceil(total / (60 * 20)));   // at most about 20 seconds of typing at 60 fps
    let n = 0;
    for (const step of steps) {
      if (!W.editor) return;
      n++;
      await openFile(step.path, { focus: false, content: step.before });
      const model = W.models.get(step.path).model;
      note(`<span class="pulse"></span><span>Writing <b>${esc(base(step.path))}</b>${steps.length > 1 ? ` (${n} of ${steps.length})` : ""}</span><button type="button" class="ide-link" id="ws-skip">Skip typing</button>`);
      const sk = $("#ws-skip"); if (sk) sk.addEventListener("click", () => (W.skip = true));
      const added = [];
      if (!W.skip && !step.deleted) {
        let offset = 0;
        for (const h of lineDiff(step.before.split("\n"), step.after.split("\n"))) {
          if (W.skip || !W.editor) break;
          const k = h.aStart + offset;
          const del = h.aEnd - h.aStart;
          if (del) {
            const flash = W.editor.createDecorationsCollection([{ range: new monaco.Range(k + 1, 1, k + del, 1), options: { isWholeLine: true, className: "ws-del" } }]);
            W.editor.revealLineInCenterIfOutsideViewport(k + 1);
            await sleep(350);
            flash.clear();
            deleteLines(model, k, del);
          }
          if (h.lines.length) { await typeLines(model, k, h.lines, perFrame); added.push([k + 1, k + h.lines.length]); }
          offset += h.lines.length - del;
        }
      }
      if (model.getValue() !== step.after) model.setValue(step.after);
      decorate(step.path, added.length && !W.skip ? added : changedRanges(step.before, step.after));
      await L().post("/api/ws/file", { repo: W.repo, path: step.path, content: step.after, deleted: !!step.deleted });
      await refreshState();
      await sleep(W.skip ? 0 : 400);
    }
  }

  function deleteLines(model, k, count) {
    const monaco = window.monaco;
    const n = model.getLineCount();
    let range;
    if (k + count < n) range = new monaco.Range(k + 1, 1, k + count + 1, 1);
    else if (k > 0) range = new monaco.Range(k, model.getLineMaxColumn(k), n, model.getLineMaxColumn(n));
    else range = model.getFullModelRange();
    model.applyEdits([{ range, text: "" }]);
  }

  async function typeLines(model, k, lines, perFrame) {
    const monaco = window.monaco;
    const n = model.getLineCount();
    let pos, text;
    if (k < n) { pos = { lineNumber: k + 1, column: 1 }; text = lines.join("\n") + "\n"; }
    else { pos = { lineNumber: n, column: model.getLineMaxColumn(n) }; text = "\n" + lines.join("\n"); }
    let i = 0;
    while (i < text.length) {
      if (!W.editor) return;
      let j = W.skip ? text.length : Math.min(text.length, i + perFrame);
      while (j < text.length && (text[j] === " " || text[j] === "\t") && /\n[ \t]*$/.test(text.slice(i, j))) j++;   // indentation in one go
      const chunk = text.slice(i, j);
      model.applyEdits([{ range: new monaco.Range(pos.lineNumber, pos.column, pos.lineNumber, pos.column), text: chunk, forceMoveMarkers: true }]);
      const parts = chunk.split("\n");
      pos = parts.length > 1 ? { lineNumber: pos.lineNumber + parts.length - 1, column: parts[parts.length - 1].length + 1 } : { lineNumber: pos.lineNumber, column: pos.column + chunk.length };
      if (W.editor && W.editor.getModel() === model) { W.editor.setPosition(pos); W.editor.revealPositionInCenterIfOutsideViewport(pos); }
      i = j;
      await frame();
    }
  }

  function decorate(path, ranges) {
    const monaco = window.monaco;
    if (!W.editor || W.active !== path) return;
    const old = W.decos.get(path);
    if (old) old.clear();
    W.decos.set(path, W.editor.createDecorationsCollection(ranges.map(([a, b]) => ({ range: new monaco.Range(a, 1, b, 1), options: { isWholeLine: true, className: "ws-add", linesDecorationsClassName: "ws-add-gutter" } }))));
  }

  function changedRanges(before, after) {
    let off = 0;
    return lineDiff(before.split("\n"), after.split("\n")).filter((h) => h.lines.length).map((h) => {
      const start = h.aStart + off + 1;
      off += h.lines.length - (h.aEnd - h.aStart);
      return [start, start + h.lines.length - 1];
    });
  }

  // Line diff: trim the common head and tail, then an LCS over what is left.
  function lineDiff(a, b) {
    let p = 0;
    while (p < a.length && p < b.length && a[p] === b[p]) p++;
    let s = 0;
    while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s++;
    const A = a.slice(p, a.length - s), B = b.slice(p, b.length - s);
    const hunks = [];
    if (!A.length && !B.length) return hunks;
    if (A.length * B.length > 4e6) return [{ aStart: p, aEnd: p + A.length, lines: B }];
    const n = A.length, m = B.length;
    const T = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) T[i][j] = A[i] === B[j] ? T[i + 1][j + 1] + 1 : Math.max(T[i + 1][j], T[i][j + 1]);
    let i = 0, j = 0, cur = null;
    while (i < n || j < m) {
      if (i < n && j < m && A[i] === B[j]) { if (cur) { hunks.push(cur); cur = null; } i++; j++; }
      else if (j < m && (i >= n || T[i][j + 1] >= T[i + 1][j])) { cur = cur || { aStart: p + i, aEnd: p + i, lines: [] }; cur.lines.push(B[j]); j++; }
      else { cur = cur || { aStart: p + i, aEnd: p + i, lines: [] }; cur.aEnd = p + i + 1; i++; }
    }
    if (cur) hunks.push(cur);
    return hunks;
  }

  // ---------------------------------------------------------------- the assistant: Claude on Bedrock
  async function generate() {
    if (W.animating) return;
    const input = $("#ws-prompt");
    const prompt = input.value.trim();
    const path = W.active;
    if (!path) { note(`<span class="bad">Open the file you want Claude to change first.</span>`); return; }
    if (!prompt) { input.focus(); note(`<span class="bad">Tell Claude what to write.</span>`); return; }
    const entry = W.models.get(path);
    if (entry.readonly) { note(`<span class="bad">This file cannot be edited here.</span>`); return; }
    if (W.editor.getModel() !== entry.model) showFile(path);
    const before = entry.model.getValue();
    setBusy(true);
    note(`<span class="pulse"></span>Claude is reading <b>${esc(base(path))}</b>…`);
    let text = "", usd = null, error = null, pending = false;
    try {
      const res = await fetch("/api/ws/generate", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repo: W.repo, path, prompt }) });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `${res.status} ${res.statusText}`);
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      const draw = () => {
        pending = false;
        if (!W.editor) return;
        entry.model.setValue(text);
        const last = entry.model.getLineCount();
        W.editor.revealLine(last);
        W.editor.setPosition({ lineNumber: last, column: entry.model.getLineMaxColumn(last) });
      };
      note(`<span class="pulse"></span>Claude is writing <b>${esc(base(path))}</b>`);
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
          if (!line.trim()) continue;
          const ev = JSON.parse(line);
          if (ev.type === "text") { text += ev.delta; if (!pending) { pending = true; requestAnimationFrame(draw); } }
          else if (ev.type === "done") usd = ev.usd;
          else if (ev.type === "error") error = ev.msg;
        }
      }
      if (error) throw new Error(error);
    } catch (e) {
      if (W.editor) entry.model.setValue(before);
      setBusy(false);
      note(`<span class="bad">${esc(e.message)}</span>`);
      return;
    }
    let final = text.replace(/^\s*```[\w-]*\n/, "").replace(/\n```\s*$/, "\n");
    if (before.endsWith("\n")) final = final.replace(/\s+$/, "") + "\n";   // keep the file's final newline
    entry.model.setValue(final);
    const changes = changedRanges(before, final);
    decorate(path, changes);
    await L().post("/api/ws/file", { repo: W.repo, path, content: final });
    const first = prompt.split("\n")[0].replace(/[.\s]+$/, "");
    W.commit = { branch: `lgtm-demo/ai-${stamp()}`, message: first.length > 72 ? first.slice(0, 69) + "…" : first, title: "", how: "model" };
    setBusy(false);
    await refreshState();
    note(changes.length ? `<span class="good">Claude changed ${L().plural(changes.reduce((a, [x, y]) => a + y - x + 1, 0), "line")}${usd != null ? ` for $${usd.toFixed(2)}` : ""}. Check the changes, then commit and push.</span>` : `<span class="ide-dim">Claude left the file unchanged.</span>`);
  }

  function setBusy(on) {
    W.animating = on;
    if (W.editor) W.editor.updateOptions({ readOnly: on || !!(W.active && W.models.get(W.active) && W.models.get(W.active).readonly) });
    $$("#ws-play, #ws-gen, #ws-reset, #ws-push, #ws-task, #ws-prompt, #ws-repo").forEach((b) => (b.disabled = on));
  }

  // ---------------------------------------------------------------- changes: diff, commit and push
  function renderChanges() {
    const el = $("#ws-changes");
    if (!el || !W.st) return;
    const st = W.st;
    const again = st.pushed && st.branch === st.pushed;
    const c = W.commit || { branch: `lgtm-demo/change-${stamp()}`, message: "", title: "", how: "manual" };
    if (st.changed.length) W.commit = c;
    el.innerHTML = `${st.changed.length ? `
      <ul class="ide-list">${st.changed.map((f) => `<li><button type="button" class="ide-row ${W.diffOf === f.path ? "on" : ""}" data-diff="${esc(f.path)}"><span class="ide-fn">${esc(base(f.path))}</span><span class="ide-dir">${esc(dirOf(f.path))}</span>${mark(f.status)}</button></li>`).join("")}</ul>
      <form class="ide-commit" id="ws-commit">
        ${again ? `<p class="ide-dim">Pushes to <b>${esc(st.branch)}</b> and updates pull request #${st.pr ? st.pr.number : ""}.</p>` : `<label><span>Branch</span><input name="branch" value="${esc(c.branch)}" required spellcheck="false"></label>`}
        <label><span>Commit message</span><textarea name="message" id="ws-msg" rows="2" required placeholder="Describe the change">${esc(c.message)}</textarea></label>
        <button class="btn primary" type="submit" id="ws-push" ${W.animating ? "disabled" : ""}>${again ? "Commit and push" : "Commit, push and open pull request"}</button>
        <p class="ide-dim">This is real: it pushes to GitHub${st.login ? ` as ${esc(st.login)}` : ""}, and LGTM reviews the pull request.</p>
      </form>` : `<p class="ide-dim pad">${again ? `Everything is pushed to ${esc(st.branch)}. Edit a file, or write a follow-up change, to push again.` : "No changes yet. Edit a file, or let the AI write one."}</p>`}
      ${W.pr ? `<div class="ide-prcard" id="ws-prcard"></div>` : ""}`;
    el.querySelectorAll("[data-diff]").forEach((b) => b.addEventListener("click", () => showDiff(b.dataset.diff)));
    const form = $("#ws-commit");
    if (form) {
      form.addEventListener("input", () => { const fd = new FormData(form); if (fd.get("branch")) c.branch = fd.get("branch"); c.message = fd.get("message"); });
      form.addEventListener("submit", (e) => { e.preventDefault(); push(new FormData(form)); });
      $("#ws-msg").addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); form.requestSubmit(); } });
    }
    drawPR();
  }

  async function showDiff(path) {
    const monaco = window.monaco;
    if (W.animating || !monaco) return;
    const d = await L().get(`/api/ws/diff?repo=${enc(W.repo)}`);
    const f = d.files.find((x) => x.path === path);
    if (!f) return;
    if (!W.diffEditor) W.diffEditor = monaco.editor.createDiffEditor($("#ws-diff"), { theme: theme(), automaticLayout: true, readOnly: true, renderSideBySide: true, minimap: { enabled: false }, fontSize: 13, lineHeight: 20, scrollBeyondLastLine: false, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", renderOverviewRuler: false });
    const old = W.diffEditor.getModel();
    const lang = (W.models.get(path) && W.models.get(path).model.getLanguageId()) || undefined;
    W.diffEditor.setModel({ original: monaco.editor.createModel(f.original, lang), modified: monaco.editor.createModel(f.modified, lang) });
    if (old) { old.original.dispose(); old.modified.dispose(); }
    W.diffOf = path;
    $("#ws-monaco").hidden = true;
    $("#ws-empty").hidden = true;
    $("#ws-diff").hidden = false;
    renderTabs();
    renderChanges();
  }

  async function push(fd) {
    const st = W.st;
    const again = st.pushed && st.branch === st.pushed;
    const branch = again ? st.branch : String(fd.get("branch") || "").trim();
    const msg = String(fd.get("message") || "").trim();
    if (!msg) { $("#ws-msg").focus(); return; }
    if (!(await ask(again ? "Push to the open pull request?" : "Push and open a pull request?",
      again ? `This pushes a new commit to ${branch} on ${W.repo}. LGTM reviews the pull request again.`
        : `This pushes the branch ${branch} to ${W.repo} on GitHub as ${st.login} and opens a pull request. LGTM reviews it right after.`,
      again ? "Commit and push" : "Push and open pull request"))) return;
    setBusy(true);
    note(`<span class="pulse"></span>Committing and pushing to GitHub…`);
    term.open(W.repo.split("/").pop(), again ? st.branch : (st.branch || st.default_branch || "main"));
    let result = null;
    try {
      const res = await fetch("/api/ws/push", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo: W.repo, branch, message: msg, title: (W.commit && W.commit.title) || msg, how: W.commit ? W.commit.how : "manual" }) });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `${res.status} ${res.statusText}`);
      // The server runs each command as soon as it can; the terminal types them out in order, with their real output.
      const events = [];
      let wake = null, ended = false;
      (async () => {
        const reader = res.body.getReader(), dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let nl;
          while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); if (line.trim()) events.push(JSON.parse(line)); if (wake) { wake(); wake = null; } }
        }
        ended = true; if (wake) { wake(); wake = null; }
      })();
      const next = async () => { while (!events.length && !ended) await new Promise((r) => (wake = r)); return events.shift(); };
      for (let ev = await next(); ev; ev = await next()) {
        if (ev.type === "cmd") await term.type(ev.cmd);
        else if (ev.type === "out") await term.out(ev.text, ev.ok);
        else if (ev.type === "error") throw new Error(ev.msg);
        else if (ev.type === "done") result = ev.result;
      }
      if (!result) throw new Error("The push stopped before it finished.");
    } catch (e) {
      await term.out(e.message, false);
      setBusy(false);
      note(`<span class="bad">${esc(e.message)}</span>`);
      return;
    }
    const r = result;
    await term.line(`✓ ${r.created ? "Opened" : "Updated"} pull request #${r.pr.number}. LGTM is picking it up…`, "ok");
    W.commit = null;
    setBusy(false);
    W.decos.forEach((x) => x.clear());
    await refreshTree();
    note(`<span class="good">Pushed ${esc(r.commit)} to ${esc(r.branch)}. ${r.created ? "Opened" : "Updated"} pull request #${r.pr.number}.</span>`);
    followPR(r.pr, r.commit);
  }

  // A terminal that types each command out at a brisk typing speed, then prints what it really returned.
  const term = {
    open(repo, branch) {
      const el = $("#ws-term");
      if (!el) return;
      el.hidden = false;
      el.innerHTML = `<header class="term-h"><span class="term-tab">Terminal</span><span class="term-path">~/${esc(repo)}</span><button type="button" class="ide-x" id="term-x" aria-label="Hide the terminal">${IC.x}</button></header><div class="term-b" id="term-b"></div>`;
      $("#term-x").addEventListener("click", () => { el.hidden = true; });
      this.branch = branch;
    },
    body() { return $("#term-b"); },
    scroll() { const b = this.body(); if (b) b.scrollTop = b.scrollHeight; },
    async type(cmd) {
      const b = this.body();
      if (!b) return;
      const row = document.createElement("div");
      row.className = "term-cmd";
      row.innerHTML = `<span class="term-ps">${esc(this.branch || "")} $</span> <span class="term-in"></span><span class="term-caret"></span>`;
      b.appendChild(row);
      const into = row.querySelector(".term-in");
      for (let i = 1; i <= cmd.length; i++) {
        if (!document.body.contains(row)) return;
        into.textContent = cmd.slice(0, i);
        this.scroll();
        await new Promise((r) => setTimeout(r, cmd[i - 1] === " " ? 18 : 13 + Math.random() * 10));   // brisk: about three times the earlier pace
      }
      row.querySelector(".term-caret").remove();
      await new Promise((r) => setTimeout(r, 220));
      const m = cmd.match(/^git checkout -b (\S+)/);
      if (m) this.branch = m[1];
    },
    async out(text, ok = true) {
      const b = this.body();
      if (!b) return;
      for (const line of (text || "").split("\n").filter((l) => l.trim() !== "")) {
        const div = document.createElement("div");
        div.className = `term-out${ok ? "" : " bad"}`;
        div.textContent = line;
        b.appendChild(div);
        this.scroll();
        await new Promise((r) => setTimeout(r, 45));
      }
      await new Promise((r) => setTimeout(r, 300));
    },
    async line(text, cls) {
      const b = this.body();
      if (!b) return;
      const div = document.createElement("div");
      div.className = `term-out ${cls || ""}`;
      div.textContent = text;
      b.appendChild(div);
      this.scroll();
    },
  };

  // ---------------------------------------------------------------- following LGTM's review
  function clearPR() {
    W.pr = null; W.run = null; W.prCommit = null;
    if (W.prTimer) { clearInterval(W.prTimer); W.prTimer = null; }
    drawPR();
  }

  function followPR(pr, commit) {
    W.pr = pr; W.prCommit = commit; W.run = null;
    const poll = async () => {
      try {
        const runs = await L().get(`/api/runs?repo=${enc(W.repo)}&source=connected&limit=30`);
        const mine = runs.filter((r) => r.pr_number === pr.number);
        W.run = (commit && mine.find((r) => (r.head_sha || "").startsWith(commit))) || (!commit && mine[0]) || W.run;
        drawPR();
        if (W.run && !["queued", "running"].includes(W.run.status) && W.prTimer) {
          clearInterval(W.prTimer); W.prTimer = null;
          if (W.mode === "app" && $("#ws-app") && !$("#ws-app").hidden) { W.app.found = await reviewedFindings(); renderApp(W.st || {}); }
        }
      } catch (e) { /* keep polling */ }
    };
    if (W.prTimer) clearInterval(W.prTimer);
    if (W.side === "changes") renderChanges(); else drawPR();
    poll();
    W.prTimer = setInterval(poll, 3000);
    L().S.timers.push(W.prTimer);
  }

  function reviewLine(run) {
    const { stageLabel, plural, secs } = L();
    if (!run) return `<span class="pulse"></span>Waiting for GitHub to tell LGTM about the push…`;
    if (run.status === "queued") return `<span class="pulse"></span>LGTM has queued the review`;
    if (run.status === "running") return `<span class="pulse"></span>LGTM is reviewing: ${esc(stageLabel(run.stage))}`;
    if (run.status !== "completed") return `<span class="bad">The review did not finish (${esc(run.status)})</span>`;
    return run.n_flagged ? `<span class="bad"><b>${plural(run.n_flagged, "security bug")}</b> reported on the pull request</span>${run.latency ? `<span class="ide-dim">in ${secs(run.latency)}</span>` : ""}`
      : `<span class="good"><b>No security bugs.</b> The check passed</span>${run.latency ? `<span class="ide-dim">in ${secs(run.latency)}</span>` : ""}`;
  }

  function drawPR() {
    const bar = $("#ws-review");
    const card = $("#ws-prcard");
    if (!W.pr) { if (bar) { bar.hidden = true; bar.innerHTML = ""; } if (card) card.remove(); return; }
    const pr = W.pr, run = W.run;
    const links = `${run ? `<a class="btn primary" href="#/runs/${enc(run.id)}">Watch the review</a>` : ""}
      <a class="btn" href="${esc(pr.url)}" target="_blank" rel="noopener"><span>Pull request #${pr.number}</span>${IC.ext}</a>
      <a class="btn" href="${esc(pr.url)}/checks" target="_blank" rel="noopener"><span>Check run</span>${IC.ext}</a>`;
    if (bar) { bar.hidden = false; bar.innerHTML = `<span class="ide-review-l"><b>LGTM</b>${reviewLine(run)}</span><span class="ide-review-r">${links}</span>`; }
    if (card) card.innerHTML = `<p class="ide-group">Pull request #${pr.number}</p><p class="ide-review-line">${reviewLine(run)}</p>`;
  }

  async function startOver() {
    if (W.animating) return;
    const st = W.st || {};
    if (st.changed && st.changed.length && !(await ask("Start over?", `This resets the workspace to the latest ${st.default_branch || "main"}. Edits you have not pushed are discarded.`, "Discard and start over"))) return;
    setBusy(true);
    note(`<span class="pulse"></span>Resetting to the latest ${esc(st.default_branch || "main")}…`);
    try {
      await L().post("/api/ws/open", { repo: W.repo });
      resetEditorState();
      if (W.editor) W.editor.setModel(null);
      clearPR();
      setBusy(false);
      W.side = "files";
      renderSide();
      await refreshTree();
      $("#ws-diff").hidden = true;
      $("#ws-empty").hidden = false;
      renderNote();
    } catch (e) { setBusy(false); note(`<span class="bad">${esc(e.message)}</span>`); }
  }

  // ---------------------------------------------------------------- App mode: the repository's own app, running from the workspace
  const PERSONAS = [["alice", "Alice", "customer"], ["bob", "Bob", "customer"], ["maria", "Maria", "manager"], ["root", "Root", "admin"]];
  const SQLI = "zzz%' UNION SELECT id, email, password_hash FROM users --";

  async function setMode(mode) {
    if (mode === "app" && (W.animating || !W.hasApp)) return;
    W.mode = mode;
    $$("[data-mode]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.mode === mode)));
    const app = mode === "app";
    ["ide-ai", "ide-note", "ide-main"].forEach((c) => { const el = document.querySelector(`.${c}`); if (el) el.hidden = app; });
    $("#ws-app").hidden = !app;
    if (app) await startApp();
    else if (W.editor) W.editor.layout();
  }

  async function startApp() {
    const el = $("#ws-app");
    const st = W.st || {};
    el.innerHTML = `<p class="app-wait"><span class="pulse"></span>Starting shoply from the code in your workspace…</p>`;
    W.app.tokens = {};
    W.app.attack = {};
    try {
      const r = await L().post("/api/ws/app/start", { repo: W.repo });
      W.app.routes = r.routes || [];
    } catch (e) {
      el.innerHTML = `<div class="app-fail"><p class="bad"><b>The app did not start.</b></p><pre>${esc(e.message)}</pre><button type="button" class="btn" id="app-retry">Try again</button></div>`;
      $("#app-retry").addEventListener("click", startApp);
      return;
    }
    W.app.log = [];
    W.app.found = await reviewedFindings();
    renderApp(st);
  }

  const has = (route) => W.app.routes.includes(route);

  async function call(method, path, body, persona = W.app.persona) {
    const go = async () => L().post("/api/ws/app/call", { repo: W.repo, method, path, body, token: W.app.tokens[persona] });
    if (!W.app.tokens[persona]) {
      const r = await L().post("/api/ws/app/call", { repo: W.repo, method: "POST", path: "/login", body: { username: persona, password: "demo" } });
      W.app.tokens[persona] = r.body && r.body.token;
    }
    const r = await go();
    W.app.log.unshift({ method, path: path.length > 70 ? path.slice(0, 67) + "…" : path, status: r.status, ms: r.ms, who: persona });
    W.app.log = W.app.log.slice(0, 6);
    drawLog();
    return r;
  }

  // The shop's catalogue lives in the storefront; shoply's API stores orders (total and address), which is all a checkout needs.
  const PRODUCTS = [
    { id: "house", name: "House Blend", kind: "Coffee beans, 250 g", price: 14.5, bg: "#f3e7da", art: "bag", c1: "#7a4a2a", c2: "#c98b56" },
    { id: "ethiopia", name: "Yirgacheffe", kind: "Single-origin coffee, 250 g", price: 18, bg: "#f6efe0", art: "bag", c1: "#2f5d50", c2: "#e2b54f" },
    { id: "matcha", name: "Ceremonial Matcha", kind: "Green tea powder, 40 g", price: 22, bg: "#e7f0dc", art: "tin", c1: "#5d8a3a", c2: "#b9d48f" },
    { id: "earlgrey", name: "Earl Grey", kind: "Loose-leaf black tea, 100 g", price: 11, bg: "#e6e8f2", art: "tin", c1: "#3b4a7a", c2: "#a7b3dd" },
    { id: "mug", name: "Stoneware Mug", kind: "Hand-glazed, 350 ml", price: 16, bg: "#f2e6e3", art: "mug", c1: "#b5574b", c2: "#e8b4a8" },
    { id: "pourover", name: "Pour-over Kit", kind: "Dripper, filters and carafe", price: 34, bg: "#e8eef0", art: "kit", c1: "#3f5560", c2: "#9fb6c0" },
  ];
  const ART = {
    bag: (a, b) => `<path d="M38 30h44l6 74H32z" fill="${a}"/><path d="M38 30l4-10h36l4 10z" fill="${b}"/><rect x="46" y="54" width="28" height="22" rx="3" fill="#fff" opacity=".9"/><path d="M52 62h16M52 68h10" stroke="${a}" stroke-width="2.5" stroke-linecap="round"/>`,
    tin: (a, b) => `<rect x="36" y="34" width="48" height="68" rx="6" fill="${a}"/><rect x="34" y="28" width="52" height="12" rx="4" fill="${b}"/><circle cx="60" cy="70" r="13" fill="#fff" opacity=".9"/><path d="M54 70c4-6 8-6 12 0" stroke="${a}" stroke-width="2.5" fill="none" stroke-linecap="round"/>`,
    mug: (a, b) => `<path d="M34 44h44v40a14 14 0 0 1-14 14H48a14 14 0 0 1-14-14z" fill="${a}"/><path d="M78 54h6a10 10 0 0 1 0 20h-6" stroke="${a}" stroke-width="6" fill="none"/><rect x="34" y="44" width="44" height="8" fill="${b}"/><path d="M48 24c0 6 6 6 6 12M60 22c0 6 6 6 6 12" stroke="${b}" stroke-width="3" fill="none" stroke-linecap="round"/>`,
    kit: (a, b) => `<path d="M40 30h40l-12 26H52z" fill="${a}"/><rect x="56" y="56" width="8" height="8" fill="${a}"/><path d="M42 66h36l-4 36H46z" fill="${b}"/><path d="M78 74h6v14h-6" stroke="${b}" stroke-width="5" fill="none"/><path d="M58 104h4" stroke="${a}" stroke-width="3"/>`,
  };
  const art = (p, size = 120) => `<svg viewBox="0 0 120 120" width="${size}" height="${size}" aria-hidden="true">${ART[p.art](p.c1, p.c2)}</svg>`;
  const money = (n) => `$${Number(n || 0).toFixed(2)}`;

  function renderApp(st) {
    const el = $("#ws-app");
    const who = PERSONAS.find((p) => p[0] === W.app.persona);
    const role = who[2];
    const search = has("GET /users/search"), detail = has("GET /orders/<int:order_id>");
    const attackHtml = attacks(W.app.found, search, detail);   // empty unless LGTM's review of this code flagged a bug
    W.app.cart = W.app.cart || {};
    W.app.bought = W.app.bought || {};
    el.innerHTML = `
      <div class="app-bar">
        <span class="app-dot"></span><span class="app-url">shoply.test</span>
        <span class="ide-dim">Running the code in your workspace${st.branch ? ` (${esc(st.branch)})` : ""}${st.changed && st.changed.length ? `, ${st.changed.length} change${st.changed.length === 1 ? "" : "s"} not yet pushed` : ""}. Demo data resets on restart.</span>
        <span class="ide-fill"></span>
        <button type="button" class="btn" id="app-restart">Restart with the latest code</button>
      </div>
      <div class="app-grid ${attackHtml ? "" : "solo"}">
        <div class="shop">
          <header class="shop-nav">
            <span class="shop-logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 9h12v5a6 6 0 0 1-6 6h0a6 6 0 0 1-6-6z" fill="currentColor"/><path d="M17 10h1.5a2.5 2.5 0 0 1 0 5H17" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M9 3c0 2 2 2 2 4M13 3c0 2 2 2 2 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>Shoply</span>
            <span class="ide-fill"></span>
            <label class="shop-who"><span class="ide-dim">Signed in as</span><select id="app-persona">${PERSONAS.map(([id, name, r]) => `<option value="${id}" ${id === W.app.persona ? "selected" : ""}>${name} (${r})</option>`).join("")}</select></label>
            <button type="button" class="shop-cart-btn" id="app-cart-btn">Cart <b id="app-cart-n">0</b></button>
          </header>
          <section class="shop-hero">
            <div><h2>Small-batch coffee and tea, roasted in Singapore.</h2><p>Free delivery over $40. Order by 2pm and it ships today.</p></div>
            <div class="shop-hero-art">${art(PRODUCTS[0], 96)}${art(PRODUCTS[4], 96)}${art(PRODUCTS[2], 96)}</div>
          </section>
          <section class="shop-grid">${PRODUCTS.map((p) => `<article class="prod">
              <div class="prod-art" style="background:${p.bg}">${art(p)}</div>
              <div class="prod-b"><h3>${esc(p.name)}</h3><p class="ide-dim">${esc(p.kind)}</p>
                <div class="prod-f"><b>${money(p.price)}</b><button type="button" class="btn" data-add="${p.id}">Add to cart</button></div></div></article>`).join("")}</section>
          <section class="shop-cart" id="app-cart"></section>
          <section class="shop-sec"><h3>My orders</h3><div id="app-mine" class="ide-dim">Loading…</div>
            ${detail ? `<form class="app-inline" id="app-track"><input name="id" type="number" min="1" placeholder="Order number" required><button class="btn" type="submit">Track an order</button></form><div id="app-track-out"></div>` : ""}</section>
          ${role !== "customer" ? `<section class="shop-sec staff"><h3>Staff dashboard <span class="tag">${esc(role)}</span></h3>
            ${search ? `<form class="app-inline" id="app-search"><input name="q" placeholder="Find a customer by name" autocomplete="off"><button class="btn" type="submit">Search</button></form>` : `<p class="ide-dim">No customer search yet. It appears here once the code has one.</p>`}
            <h4>Customers</h4><div id="app-users" class="ide-dim">Loading…</div>
            <h4>All orders</h4><div id="app-all" class="ide-dim">Loading…</div>
            ${role === "admin" ? `<h4>Store stats</h4><div id="app-stats" class="ide-dim">Loading…</div>` : ""}</section>` : ""}
        </div>
        ${attackHtml ? `<aside class="app-side">
          <section class="app-attack">${attackHtml}</section>
          <section class="app-log"><h3>Requests to shoply's API</h3><ul id="app-log"></ul></section>
        </aside>` : ""}
      </div>`;
    $("#app-restart").addEventListener("click", async () => { await refreshState(); startApp(); });
    $("#app-persona").addEventListener("change", (e) => { W.app.persona = e.target.value; renderApp(W.st || st); });
    $$("[data-add]").forEach((b) => b.addEventListener("click", () => { W.app.cart[b.dataset.add] = (W.app.cart[b.dataset.add] || 0) + 1; drawCart(); b.textContent = "Added"; setTimeout(() => (b.textContent = "Add to cart"), 900); }));
    $("#app-cart-btn").addEventListener("click", () => $("#app-cart").scrollIntoView({ behavior: "smooth", block: "center" }));
    const tr = $("#app-track");
    if (tr) tr.addEventListener("submit", async (e) => { e.preventDefault(); const r = await call("GET", `/orders/${+new FormData(e.target).get("id")}`); $("#app-track-out").innerHTML = r.status === 200 ? orderCard(r.body, true) : `<p class="bad">${esc((r.body && r.body.error) || r.status)}</p>`; });
    const se = $("#app-search");
    if (se) se.addEventListener("submit", async (e) => { e.preventDefault(); await runSearch(new FormData(e.target).get("q")); });
    $$("[data-attack]").forEach((b) => b.addEventListener("click", () => runAttack(b.dataset.attack)));
    drawCart();
    drawLog();
    loadData();
  }

  function drawCart() {
    const el = $("#app-cart");
    if (!el) return;
    const items = Object.entries(W.app.cart).filter(([, n]) => n > 0).map(([id, n]) => ({ ...PRODUCTS.find((p) => p.id === id), n }));
    const total = items.reduce((a, p) => a + p.price * p.n, 0);
    $("#app-cart-n").textContent = items.reduce((a, p) => a + p.n, 0);
    el.innerHTML = items.length ? `<h3>Your cart</h3>
      <ul class="cart">${items.map((p) => `<li><span class="cart-art" style="background:${p.bg}">${art(p, 40)}</span><span>${esc(p.name)} <span class="ide-dim">× ${p.n}</span></span><b>${money(p.price * p.n)}</b><button type="button" class="ide-link" data-rm="${p.id}">Remove</button></li>`).join("")}</ul>
      <form class="app-inline" id="app-checkout"><input name="address" placeholder="Shipping address" required value="${esc(W.app.address || "")}"><button class="btn primary" type="submit">Pay ${money(total)}</button></form>`
      : `<p class="ide-dim">Your cart is empty. Add something above.</p>`;
    el.querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { W.app.cart[b.dataset.rm] = 0; drawCart(); }));
    const co = $("#app-checkout");
    if (co) co.addEventListener("submit", async (e) => {
      e.preventDefault();
      const address = new FormData(co).get("address");
      W.app.address = address;
      const r = await call("POST", "/orders", { total: Math.round(total * 100) / 100, shipping_address: address });
      if (r.status === 201 && r.body) { W.app.bought[r.body.id] = items.map((p) => `${p.name} × ${p.n}`).join(", "); W.app.cart = {}; drawCart(); loadData(); }
    });
  }

  function orderCard(o, full) {
    const what = W.app.bought[o.id] || "Coffee and tea order";
    return `<div class="order"><div><b>Order #${esc(o.id)}</b><span class="ide-dim">${esc(what)}</span>${full ? `<span class="ide-dim">Ship to ${esc(o.shipping_address)} · customer #${esc(o.user_id)}</span>` : ""}</div><span class="pill ${esc(o.status)}">${esc(o.status)}</span><b>${money(o.total)}</b></div>`;
  }

  function table(rows, cols) {
    if (!Array.isArray(rows) || !rows.length) return `<p class="ide-dim">Nothing here.</p>`;
    cols = cols || Object.keys(rows[0]);
    return `<table class="app-table"><thead><tr>${cols.map((c) => `<th>${esc(c.replace(/_/g, " "))}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td>${esc(typeof r[c] === "number" && c === "total" ? money(r[c]) : r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  }

  async function loadData() {
    const put = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };
    const mine = await call("GET", "/orders/mine");
    put("#app-mine", mine.status === 200 ? (mine.body.length ? mine.body.map((o) => orderCard(o)).join("") : `<p class="ide-dim">No orders yet.</p>`) : `<p class="bad">${esc(mine.status)}</p>`);
    if ($("#app-users")) { const u = await call("GET", "/users"); put("#app-users", u.status === 200 ? table(u.body, ["id", "username", "role"]) : `<p class="bad">${esc((u.body && u.body.error) || u.status)}</p>`); }
    if ($("#app-all")) { const a = await call("GET", "/orders/all"); put("#app-all", a.status === 200 ? table(a.body, ["id", "user_id", "status", "total"]) : `<p class="bad">${esc((a.body && a.body.error) || a.status)}</p>`); }
    if ($("#app-stats")) { const s2 = await call("GET", "/admin/stats"); put("#app-stats", s2.status === 200 ? `<pre class="app-json">${esc(JSON.stringify(s2.body, null, 2))}</pre>` : `<p class="bad">${esc(s2.status)}</p>`); }
  }

  async function runSearch(q) {
    const r = await call("GET", `/users/search?name=${encodeURIComponent(q || "")}`);
    const el = $("#app-users");
    if (el) el.innerHTML = r.status === 200 ? table(r.body, Object.keys((r.body || [])[0] || { id: 1, username: 1, role: 1 })) : `<p class="bad">${esc((r.body && r.body.error) || r.status)}</p>`;
    return r;
  }

  // The flagged findings of the latest finished LGTM review of exactly the code in the workspace (its pull request and commit).
  async function reviewedFindings() {
    const st = await refreshState().catch(() => W.st || {});
    if (!st || !st.pr || !st.head || (st.changed && st.changed.length)) return null;
    try {
      const runs = await L().get(`/api/runs?repo=${enc(W.repo)}&source=connected&limit=60`);
      const run = runs.find((r) => r.pr_number === st.pr.number && (r.head_sha || "").startsWith(st.head) && r.status === "completed");
      if (!run || !run.n_flagged) return null;
      const d = await L().get(`/api/runs/${enc(run.id)}`);
      const findings = ((d.result && d.result.findings) || []).filter((f) => f.flagged);
      return findings.length ? { run, pr: st.pr, findings } : null;
    } catch (e) { return null; }
  }

  // Attack panel: only for bugs LGTM actually reported on this code, and only when the running app has the endpoint.
  function attacks(found, search, detail) {
    if (!found) return "";
    const CWE_NAMES = { "CWE-89": "SQL injection", "CWE-639": "Insecure direct object reference", "CWE-862": "Missing authorization", "CWE-863": "Incorrect authorization" };
    const sqli = found.findings.find((f) => f.cwe === "CWE-89");
    const idor = found.findings.find((f) => ["CWE-639", "CWE-862", "CWE-863", "CWE-285", "CWE-284"].includes(f.cwe) && /order/.test(f.file || ""));
    const judge = found.run.judge === "claude" ? "Claude judge" : "Kev judge";
    const head = (f) => `<p class="atk-found"><span class="atk-flag">LGTM blocked this code</span>Its review of pull request #${esc(found.pr.number)} (commit ${esc((found.run.head_sha || "").slice(0, 7))}) found <b>${esc(CWE_NAMES[f.cwe] || f.cwe)}</b> at <code>${esc(f.file)}:${esc(f.line)}</code>, confirmed by the ${judge}. <a href="#/runs/${enc(found.run.id)}/findings">Open the review</a></p>`;
    const out = [];
    if (sqli && search) out.push(`<div class="atk">${head(sqli)}
      <p>See what an attacker can do with it. Maria, a manager, searches for this instead of a name: it closes the quote and asks the database for every user's email and password hash.</p>
      <code class="atk-in">${esc(SQLI)}</code>
      <button type="button" class="btn primary" data-attack="sqli">Run the attack</button>
      <div class="atk-out" id="atk-sqli"></div></div>`);
    if (idor && detail) out.push(`<div class="atk">${head(idor)}
      <p>See what an attacker can do with it. Alice, a customer, asks for order #3, which belongs to Bob.</p>
      <button type="button" class="btn primary" data-attack="idor">Run the attack</button>
      <div class="atk-out" id="atk-idor"></div></div>`);
    return out.length ? `<h3>Exploit what LGTM found</h3>${out.join("")}` : "";
  }

  async function runAttack(kind) {
    if (kind === "sqli") {
      W.app.persona = "maria"; renderApp(W.st || {});
      await new Promise((r) => setTimeout(r, 50));
      const box = $("#app-search input"); if (box) box.value = SQLI;
      const r = await runSearch(SQLI);
      const leaked = Array.isArray(r.body) ? r.body.filter((x) => Object.values(x).some((v) => /^[0-9a-f]{64}$/.test(String(v)) || /@/.test(String(v)))) : [];
      $("#atk-sqli").innerHTML = leaked.length
        ? `<p class="atk-bad">Leaked ${leaked.length} users' emails and password hashes, including the admin's. This is the bug LGTM blocked.</p>`
        : r.status === 200 ? `<p class="atk-good">Blocked. The search treated the attack as plain text and found no one. This is the fixed code.</p>` : `<p class="ide-dim">The app answered ${esc(r.status)}.</p>`;
    } else if (kind === "idor") {
      W.app.persona = "alice"; renderApp(W.st || {});
      await new Promise((r) => setTimeout(r, 50));
      const r = await call("GET", "/orders/3", undefined, "alice");
      const out = $("#app-track-out"); if (out) out.innerHTML = r.status === 200 ? orderCard(r.body, true) : "";
      $("#atk-idor").innerHTML = r.status === 200 && r.body && r.body.user_id !== 1
        ? `<p class="atk-bad">Alice can read Bob's order, including his home address. This is the bug LGTM blocked.</p>`
        : `<p class="atk-good">Blocked: the app answered ${esc(r.status)}. Only the owner (or an admin) can see an order.</p>`;
    }
  }

  function drawLog() {
    const el = $("#app-log");
    if (!el) return;
    el.innerHTML = W.app.log.length ? W.app.log.map((l) => `<li><span class="m">${esc(l.method)}</span><code>${esc(l.path)}</code><span class="s s${String(l.status)[0]}">${esc(l.status)}</span><span class="ide-dim">${esc(l.who)}</span></li>`).join("") : `<li class="ide-dim">No requests yet.</li>`;
  }
})();
