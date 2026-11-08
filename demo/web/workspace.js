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
    ff: sv('<path d="M5 6l7 6-7 6zM13 6l7 6-7 6z"/>'),
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
          ${(() => { const src = W.presets.find((x) => x.upstream) || {}; const up = src.upstream; const target = up || repo; const tip = up ? (src.upstream_about || "Open the original project on GitHub") : "Open this repository on GitHub"; return `<a class="btn ide-orig" id="ws-orig" href="https://github.com/${esc(target)}" target="_blank" rel="noopener noreferrer" aria-label="${esc(tip)}" data-tip="${esc(tip)}">${IC.ext}<span>${up ? "Original repo" : "Repo on GitHub"}</span></a>`; })()}
          ${W.hasApp ? `<div class="ide-mode" role="tablist" aria-label="View"><button type="button" role="tab" data-mode="code" aria-selected="${W.mode === "code"}">Code</button><button type="button" role="tab" data-mode="app" aria-selected="${W.mode === "app"}">App</button></div>` : ""}
          <span class="ide-fill"></span>
          <span class="ide-dim" id="ws-who"></span>
          <button type="button" class="btn" id="ws-reset">Start over</button>
        </div>
        <div class="ide-ai">
          <span class="ide-ai-tag" id="ws-tag">${IC.spark}<span>AI</span></span>
          ${W.presets.length ? `<label class="sr-only" for="ws-task">Recorded change to replay</label>
            <select id="ws-task">${W.presets.map((p) => `<option value="${esc(p.id)}" ${p.id === W.task ? "selected" : ""}>${p.realworld ? "Real PR · " : ""}${esc(p.title)}</option>`).join("")}</select>
            <button type="button" class="btn primary" id="ws-play">${IC.play}<span id="ws-play-label">Write it live</span></button>
            <span class="ide-or">or</span>` : ""}
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
    if (play) play.addEventListener("click", () => {
      const p = W.presets.find((x) => x.id === W.task);
      return p && !p.realworld ? writeLive(W.task) : runTask(W.task);
    });
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
    const real = !!(p && p.realworld);
    const tag = $("#ws-tag span"), label = $("#ws-play-label");
    if (tag) tag.textContent = real ? "Real PR" : "AI";
    if (label) label.textContent = real ? "Replay this PR" : "Write it live";
    if (!p) return note("");
    if (!real) return note(`<span class="ide-ask"><span class="ide-tagl">Task</span>${esc(p.ask)}</span><span class="ide-dim">Written live by a local coding model, nothing scripted. <button type="button" class="linkish" id="ws-replay">Replay the prepared change instead</button></span>`), wireReplay();
    const link = (url, text) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)} ↗</a>`;
    note(`<span class="ide-ask"><span class="ide-tagl">Real ${esc(p.kind || "PR")}</span><span>${esc(p.author)} ${p.kind === "commit" ? "committed" : "merged"} “${esc(p.title)}” into ${esc(p.project)} on ${esc(p.merged)}. ${p.original_url ? link(p.original_url, "See the original") : ""}</span></span>`
      + `<span class="ide-ask"><span class="ide-tagl">Found later</span><span>Published as a security advisory on ${esc(p.advisory_date)}. ${p.advisory_url ? link(p.advisory_url, p.advisory) : esc(p.advisory)}</span></span>`);
  }
  function wireReplay() {
    const b = $("#ws-replay");
    if (b) b.addEventListener("click", () => runTask(W.task));
  }
  function note(html) { const el = $("#ws-note"); if (el) el.innerHTML = html; }
  // The line shown while a replay types: the Fast forward button is built once and stays put at the left;
  // only the text beside it changes from file to file.
  function writing(html) {
    const el = $("#ws-note");
    if (!el) return;
    let txt = el.querySelector(".ide-writing");
    if (!txt) {
      el.innerHTML = `<button type="button" class="btn ide-ff" id="ws-skip" title="Finish the replay instantly">${IC.ff}<span>Fast forward</span></button><span class="pulse"></span><span class="ide-writing"></span>`;
      el.querySelector("#ws-skip").addEventListener("click", () => (W.skip = true));
      txt = el.querySelector(".ide-writing");
    }
    txt.innerHTML = html;
  }

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
    W.commit = { branch: script.branch, message: script.message, title: script.title, how: "replay", preset: id };
    setBusy(false);
    W.side = "changes";
    renderSide();
    await refreshState();
    note(`<span class="good">${preset && preset.realworld ? `Replayed ${esc(preset.author)}'s change: ${L().plural(script.steps.length, "file")}. Check the changes on the left, then commit and push to open it as a pull request for LGTM to review.` : `Wrote ${L().plural(script.steps.length, "file")}. Check the changes on the left, then commit and push.`}</span>`);
  }

  async function play(steps) {
    const monaco = window.monaco;
    W.skip = false;
    const total = steps.reduce((a, s) => a + lineDiff(s.before.split("\n"), s.after.split("\n")).reduce((b, h) => b + h.lines.join("\n").length, 0), 0);
    const perFrame = Math.max(1, Math.ceil(total / (60 * 20)));   // at most about 20 seconds of typing at 60 fps; "Fast forward" skips to the end
    let n = 0;
    for (let idx = 0; idx < steps.length; idx++) {
      const step = steps[idx];
      if (!W.editor) return;
      if (W.skip && idx > 0) {   // "Fast forward": write every remaining file at once instead of opening each one
        const rest = steps.slice(idx);
        note(`<span class="pulse"></span><span>Applying the other ${L().plural(rest.length, "file")}…</span>`);
        await Promise.all(rest.map((x) => L().post("/api/ws/file", { repo: W.repo, path: x.path, content: x.after, deleted: !!x.deleted })));
        await refreshState();
        return;
      }
      n++;
      await openFile(step.path, { focus: false, content: step.before });
      const model = W.models.get(step.path).model;
      writing(`Writing <b>${esc(base(step.path))}</b>${steps.length > 1 ? ` (${n} of ${steps.length})` : ""}`);
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

  // ---------------------------------------------------------------- the assistant: a local model, live
  // The task's request goes to a small coding model on this machine; its file streams into the editor as it is
  // written. Nothing is scripted: the model may write safe code, and the review then passes.
  async function writeLive(id) {
    if (W.animating || !id) return;
    const preset = W.presets.find((p) => p.id === id);
    const st = W.st || {};
    if (st.changed && st.changed.length && !(await ask("Start from a clean copy?", "Your current edits in the workspace will be discarded.", "Discard and write it"))) return;
    setBusy(true);
    note(`<span class="pulse"></span>Getting ready…`);
    let r;
    try {
      r = await L().post("/api/ws/open", { repo: W.repo, preset: id });
    } catch (e) { setBusy(false); note(`<span class="bad">${esc(e.message)}</span>`); return; }
    resetEditorState(); W.editor.setModel(null); clearPR();
    await refreshTree();
    const step = r.script.steps[0];
    const path = step.path, before = step.before;
    await openFile(path, { focus: false, content: before });
    const entry = W.models.get(path);
    const tail = before.split("\n");
    let text = "", model = "", error = null, pending = false;
    // Small models sometimes wrap the file in the <file> tags of the prompt or in a Markdown fence.
    const clean = (t) => t.replace(/^\s*<file>\n?/, "").replace(/^\s*```[\w-]*\n/, "").replace(/\n?<\/file>\s*$/, "\n").replace(/\n```\s*$/, "\n");
    const draw = () => {   // what is written so far, then the rest of the old file below it
      pending = false;
      if (!W.editor) return;
      const lines = clean(text).split("\n");
      entry.model.setValue(lines.concat(tail.slice(lines.length)).join("\n"));
      W.editor.revealLineInCenterIfOutsideViewport(lines.length);
      W.editor.setPosition({ lineNumber: lines.length, column: lines[lines.length - 1].length + 1 });
    };
    writing(`Reading <b>${esc(base(path))}</b>…`);
    try {
      const res = await fetch("/api/ws/generate", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo: W.repo, path, prompt: preset.ask, engine: "local" }) });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `${res.status} ${res.statusText}`);
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
          if (!line.trim()) continue;
          const ev = JSON.parse(line);
          if (ev.type === "text") {
            if (!text) writing(`Writing <b>${esc(base(path))}</b> live`);
            text += ev.delta;
            if (!pending && !W.skip) { pending = true; requestAnimationFrame(draw); }
          } else if (ev.type === "done") model = ev.model || "";
          else if (ev.type === "error") error = ev.msg;
        }
      }
      if (error) throw new Error(error);
    } catch (e) {
      if (W.editor) entry.model.setValue(before);
      setBusy(false);
      note(`<span class="bad">${esc(e.message)}</span> <button type="button" class="linkish" id="ws-replay">Replay the prepared change instead</button>`);
      wireReplay();
      return;
    }
    let final = clean(text);
    if (before.endsWith("\n")) final = final.replace(/\s+$/, "") + "\n";   // keep the file's final newline
    entry.model.setValue(final);
    const changes = changedRanges(before, final);
    decorate(path, changes);
    await L().post("/api/ws/file", { repo: W.repo, path, content: final });
    W.commit = { branch: `${r.script.branch}-${stamp()}`, message: r.script.message, title: r.script.title, how: "live", preset: id };
    setBusy(false);
    W.side = "changes";
    renderSide();
    await refreshState();
    if (!changes.length) {
      note(`<span class="ide-dim">The model left the file unchanged. Try again, or</span> <button type="button" class="linkish" id="ws-replay">replay the prepared change</button>`);
      return wireReplay();
    }
    note(`<span class="good">${esc(model || "The model")} wrote ${L().plural(changes.reduce((a, [x, y]) => a + y - x + 1, 0), "line")} live. Check the changes on the left, then commit and push for LGTM to review.</span>`);
  }

  function setBusy(on) {
    W.animating = on;
    if (W.editor) W.editor.updateOptions({ readOnly: on || !!(W.active && W.models.get(W.active) && W.models.get(W.active).readonly) });
    $$("#ws-play, #ws-reset, #ws-push, #ws-task, #ws-repo").forEach((b) => (b.disabled = on));
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
        body: JSON.stringify({ repo: W.repo, branch, message: msg, title: (W.commit && W.commit.title) || msg, how: W.commit ? W.commit.how : "manual", preset: W.commit && W.commit.preset ? W.commit.preset : "" }) });
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
        await new Promise((r) => setTimeout(r, cmd[i - 1] === " " ? 9 : 6.5 + Math.random() * 5));   // brisk: about six times the earlier pace
      }
      row.querySelector(".term-caret").remove();
      await new Promise((r) => setTimeout(r, 110));
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
    W.app.log = W.app.log.slice(0, 4);
    const addr = $("#app-path"); if (addr) addr.textContent = path;
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

  // One screen, no scrolling: a small browser with three products, then either the customer's orders or the
  // staff tools, and (when LGTM blocked this code) the exploit panel beside it.
  const SHOWN = ["house", "matcha", "mug"], SHOWN_PERSONAS = ["alice", "maria", "root"], ADDRESS = "1 Raffles Place, #10-01";

  function renderApp(st) {
    const el = $("#ws-app");
    const who = PERSONAS.find((p) => p[0] === W.app.persona) || PERSONAS[0];
    const role = who[2], staff = role !== "customer";
    const search = has("GET /users/search"), detail = has("GET /orders/<int:order_id>");
    const attackHtml = attacks(W.app.found, search, detail);   // empty unless LGTM's review of this code flagged a bug
    W.app.bought = W.app.bought || {};
    const n = st.changed ? st.changed.length : 0;
    const last = W.app.log[0];
    el.innerHTML = `
      <div class="app-bar">
        <span class="app-dot"></span><span class="app-url">shoply.test</span>
        <span class="ide-dim">Running ${st.branch ? esc(st.branch) : "your workspace"}${n ? ` · ${n} change${n === 1 ? "" : "s"} not yet pushed` : ""}</span>
        <span class="ide-fill"></span>
        <button type="button" class="btn" id="app-restart">Restart with the latest code</button>
      </div>
      <div class="sh2 ${attackHtml ? "" : "solo"}">
        <div class="sh2-main">
          <div class="sh2-seg"><span>Signed in as</span>${PERSONAS.filter((p) => SHOWN_PERSONAS.includes(p[0])).map(([id, name, r]) => `<button type="button" data-as="${id}" aria-pressed="${id === W.app.persona}">${esc(name)}<em>${esc(r)}</em></button>`).join("")}</div>
          <div class="sh2-browser">
            <div class="sh2-url"><span aria-hidden="true">🔒</span><span class="host">shoply.test</span><span class="path" id="app-path">${esc(last ? last.path : "/")}</span></div>
            <nav class="sh2-nav"><b class="sh2-logo">☕ Shoply</b><span class="sh2-toast" id="app-toast" aria-live="polite"></span><span class="me">Hi, ${esc(who[1])}</span></nav>
            <div class="sh2-body">
              ${staff ? "" : `<div class="sh2-prods">${SHOWN.map((id) => PRODUCTS.find((p) => p.id === id)).map((p) => `<div class="sh2-prod">
                <div class="sh2-art" style="background:${p.bg}">${art(p, 108)}</div>
                <div><b>${esc(p.name)}</b><span class="ide-dim">${money(p.price)}</span></div>
                <button type="button" class="btn" data-buy="${p.id}">Buy</button></div>`).join("")}</div>`}
              ${staff ? `<section class="sh2-sec"><h3>Staff dashboard <span class="tag">${esc(role)}</span></h3>
                ${search ? `<form class="app-inline" id="app-search"><input name="q" placeholder="Find a customer by name" autocomplete="off"><button class="btn" type="submit">Search</button></form>` : `<p class="ide-dim">No customer search yet. It appears here once the code has one.</p>`}
                <div id="app-users" class="ide-dim">Loading…</div>
                <div id="app-all" class="ide-dim"></div>
                ${role === "admin" ? `<div id="app-stats" class="ide-dim"></div>` : ""}</section>`
              : `<section class="sh2-sec"><h3>My orders</h3><div id="app-mine" class="ide-dim">Loading…</div>
                ${detail ? `<form class="app-inline" id="app-track"><input name="id" type="number" min="1" placeholder="Look up an order number" required><button class="btn" type="submit">Track</button></form><div id="app-track-out"></div>` : ""}</section>`}
            </div>
          </div>
        </div>
        ${attackHtml ? `<aside class="app-side">
          <section class="app-attack">${attackHtml}</section>
          <section class="app-log"><h3>Requests to shoply's API</h3><ul id="app-log"></ul></section>
        </aside>` : ""}
      </div>`;
    $("#app-restart").addEventListener("click", async () => { await refreshState(); startApp(); });
    $$("[data-as]").forEach((b) => b.addEventListener("click", () => { W.app.persona = b.dataset.as; renderApp(W.st || st); }));
    $$("[data-buy]").forEach((b) => b.addEventListener("click", () => buy(b.dataset.buy)));
    const tr = $("#app-track");
    if (tr) tr.addEventListener("submit", async (e) => { e.preventDefault(); const r = await call("GET", `/orders/${+new FormData(e.target).get("id")}`); $("#app-track-out").innerHTML = r.status === 200 ? orderCard(r.body, true) : `<p class="bad">${esc((r.body && r.body.error) || r.status)}</p>`; });
    const se = $("#app-search");
    if (se) se.addEventListener("submit", async (e) => { e.preventDefault(); await runSearch(new FormData(e.target).get("q")); });
    $$("[data-attack]").forEach((b) => b.addEventListener("click", () => runAttack(b.dataset.attack)));
    drawLog();
    loadData();
  }

  // One click buys one item (the API stores the order's total and address, which is all it needs).
  async function buy(id) {
    const p = PRODUCTS.find((x) => x.id === id);
    const r = await call("POST", "/orders", { total: p.price, shipping_address: W.app.address || ADDRESS });
    const toast = $("#app-toast");
    if (r.status === 201 && r.body) {
      W.app.bought[r.body.id] = p.name;
      if (toast) { toast.textContent = `Ordered ${p.name}`; setTimeout(() => { if (toast.isConnected) toast.textContent = ""; }, 2200); }
      loadData();
    } else if (toast) toast.textContent = `Could not order (${r.status})`;
    const path = $("#app-path"); if (path) path.textContent = "/orders";
  }

  function orderCard(o, full) {
    const what = W.app.bought[o.id] || "Coffee and tea order";
    return `<div class="order"><div><b>Order #${esc(o.id)}</b><span class="ide-dim">${esc(what)}</span>${full ? `<span class="ide-dim">Ship to ${esc(o.shipping_address)} · customer #${esc(o.user_id)}</span>` : ""}</div><span class="pill ${esc(o.status)}">${esc(o.status)}</span><b>${money(o.total)}</b></div>`;
  }

  // A small table; long lists are cut to `max` rows so the page never needs scrolling. Hashes and emails show in red.
  function table(rows, cols, max = 4, title = "", labels = {}) {
    if (!Array.isArray(rows) || !rows.length) return `<p class="ide-dim">Nothing here.</p>`;
    cols = cols || Object.keys(rows[0]);
    const shown = rows.slice(0, max), more = rows.length - shown.length;
    const cell = (r, c) => { const v = r[c]; const bad = /^[0-9a-f]{64}$/.test(String(v)) || /^[^\s@]+@[^\s@]+$/.test(String(v)); return `<td${bad ? ' class="leakcell"' : ""}>${esc(typeof v === "number" && c === "total" ? money(v) : v)}</td>`; };
    return `${title ? `<h4 class="sh2-h4">${esc(title)}</h4>` : ""}<table class="app-table"><thead><tr>${cols.map((c) => `<th>${esc(labels[c] || c.replace(/_/g, " "))}</th>`).join("")}</tr></thead><tbody>${shown.map((r) => `<tr>${cols.map((c) => cell(r, c)).join("")}</tr>`).join("")}</tbody></table>${more > 0 ? `<p class="ide-dim sh2-more">+ ${more} more</p>` : ""}`;
  }

  async function loadData() {
    const put = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };
    const mine = await call("GET", "/orders/mine");
    const latest = (rows, n) => [...rows].sort((a, b) => b.id - a.id).slice(0, n);   // newest first, a few rows so everything fits on one screen
    put("#app-mine", mine.status === 200 ? (mine.body.length ? latest(mine.body, 2).map((o) => orderCard(o)).join("") + (mine.body.length > 2 ? `<p class="ide-dim sh2-more">+ ${mine.body.length - 2} older</p>` : "") : `<p class="ide-dim">No orders yet.</p>`) : `<p class="bad">${esc(mine.status)}</p>`);
    if ($("#app-users")) { const u = await call("GET", "/users"); put("#app-users", u.status === 200 ? table(u.body, ["id", "username", "role"], 4, "Customers") : `<p class="bad">${esc((u.body && u.body.error) || u.status)}</p>`); }
    if ($("#app-all")) { const a = await call("GET", "/orders/all"); put("#app-all", a.status === 200 ? table(latest(a.body, 99), ["id", "user_id", "status", "total"], 2, "Latest orders") : `<p class="bad">${esc((a.body && a.body.error) || a.status)}</p>`); }
    if ($("#app-stats")) { const s2 = await call("GET", "/admin/stats"); put("#app-stats", s2.status === 200 ? `<h4 class="sh2-h4">Store stats</h4><code class="sh2-stats">${esc(JSON.stringify(s2.body))}</code>` : `<p class="bad">${esc(s2.status)}</p>`); }
  }

  async function runSearch(q) {
    const r = await call("GET", `/users/search?name=${encodeURIComponent(q || "")}`);
    const el = $("#app-users");
    if (el) el.innerHTML = r.status === 200 ? table(r.body, Object.keys((r.body || [])[0] || { id: 1, username: 1, role: 1 }), 4, "Customers", Array.isArray(r.body) && r.body.some((x) => Object.values(x).some((v) => /^[0-9a-f]{64}$/.test(String(v)))) ? { username: "email", role: "password hash" } : {}) : r.status >= 500 ? `<p class="bad">The search crashed (error ${esc(r.status)})${r.body && r.body.crash ? `: <code>${esc(r.body.crash)}</code>` : ""}</p>`
      : `<p class="bad">${esc((r.body && r.body.error) || r.status)}</p>`;
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
      <p>Maria is a manager: she may see usernames and roles, never anyone's email or password hash. Instead of a name she types this into the search. It ends the name early and asks the database for every user's email and password hash.</p>
      <code class="atk-in">${esc(SQLI)}</code>
      <button type="button" class="btn primary" data-attack="sqli">Run the attack</button>
      <div class="atk-out" id="atk-sqli"></div></div>`);
    if (idor && detail) out.push(`<div class="atk">${head(idor)}
      <p>Alice is a customer: she may see only her own orders. She asks for order #3, which belongs to Bob.</p>
      <button type="button" class="btn primary" data-attack="idor">Run the attack</button>
      <div class="atk-out" id="atk-idor"></div></div>`);
    return out.length ? `<h3>Exploit what LGTM found</h3>${out.join("")}` : "";
  }

  async function runAttack(kind) {
    const out = $(`#atk-${kind}`);
    if (out) out.innerHTML = `<p class="ide-dim"><span class="pulse"></span>Running…</p>`;
    try {
      await attackSteps(kind);
    } catch (e) {
      const o = $(`#atk-${kind}`);
      if (o) o.innerHTML = `<p class="bad">${esc(e.message)}</p>`;
      const res = $(kind === "sqli" ? "#app-users" : "#app-track-out");
      if (res && /Loading/.test(res.textContent)) res.innerHTML = "";
    }
  }
  async function attackSteps(kind) {
    if (kind === "sqli") {
      W.app.persona = "maria"; renderApp(W.st || {});
      await new Promise((r) => setTimeout(r, 50));
      const box = $("#app-search input"); if (box) box.value = SQLI;
      const r = await runSearch(SQLI);
      const leaked = Array.isArray(r.body) ? r.body.filter((x) => Object.values(x).some((v) => /^[0-9a-f]{64}$/.test(String(v)) || /@/.test(String(v)))) : [];
      const box2 = $("#app-users"); if (leaked.length && box2) box2.insertAdjacentHTML("afterbegin", `<div class="leak">⚠ A name search just returned <b>every user's email and password hash</b>, including the admin's.</div>`);
      $("#atk-sqli").innerHTML = leaked.length
        ? `<p class="atk-bad">Leaked ${leaked.length} users' emails and password hashes, including the admin's. This is the bug LGTM blocked.</p>`
        : r.status === 200 ? `<p class="atk-good">Blocked. The search treated the attack as plain text and found no one. This is the fixed code.</p>`
        : crashed(r, "search");
    } else if (kind === "idor") {
      W.app.persona = "alice"; renderApp(W.st || {});
      await new Promise((r) => setTimeout(r, 50));
      const r = await call("GET", "/orders/3", undefined, "alice");
      const stolen = r.status === 200 && r.body && r.body.user_id !== 1;
      const out = $("#app-track-out"); if (out) out.innerHTML = r.status === 200 ? `${stolen ? `<div class="leak">⚠ You're signed in as <b>Alice</b>, but this is <b>another customer's</b> order, with their home address.</div>` : ""}${orderCard(r.body, true)}` : "";
      const path = $("#app-path"); if (path) path.textContent = "/orders/3";
      $("#atk-idor").innerHTML = stolen
        ? `<p class="atk-bad">Alice can read Bob's order, including his home address. This is the bug LGTM blocked.</p>`
        : r.status >= 500 ? crashed(r, "order page")
        : `<p class="atk-good">Blocked: the app said no (${esc(r.status)}). Only the owner (or an admin) can see an order.</p>`;
    }
  }

  // The app crashed instead of answering: nothing leaked, and the attack cannot show anything on this code.
  function crashed(r, what) {
    const why = r.body && r.body.crash;
    return `<p class="atk-meh"><b>Nothing leaked: the ${what} crashed</b> (error ${esc(r.status)}) before it could answer${why ? `: <code>${esc(why)}</code>` : "."}</p>
      <p class="ide-dim">The code under review has another bug that breaks this endpoint, so the attack cannot run against it. Fix that bug, or replay the prepared change, to see the attack.</p>`;
  }

  function drawLog() {
    const el = $("#app-log");
    if (!el) return;
    el.innerHTML = W.app.log.length ? W.app.log.map((l) => `<li><span class="m">${esc(l.method)}</span><code>${esc(l.path)}</code><span class="s s${String(l.status)[0]}">${esc(l.status)}</span><span class="ide-dim">${esc(l.who)}</span></li>`).join("") : `<li class="ide-dim">No requests yet.</li>`;
  }
})();
