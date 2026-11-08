// LGTM guided demo: one story in five steps, on shoply-demo.
// A local model writes a feature live, the page attacks what it wrote, a real pull request opens, LGTM reviews it on
// GitHub, its verified fix is committed, and the shop is attacked again as main, as the pull request and as the fix.
// Nothing is scripted. When the model writes safe or broken code, a recorded earlier run (saved as it happened,
// token by token) can be replayed instead, labelled with its date.
(function () {
  "use strict";
  const L = () => window.LGTM;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => L().esc(s);
  const enc = encodeURIComponent;
  const short = (s) => String(s || "").slice(0, 7);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const stamp = () => { const d = new Date(), p = (n) => String(n).padStart(2, "0"); return `${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`; };
  const rt = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
  const day = (iso) => new Date(iso).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

  const STEPS = [["codebase", "The codebase"], ["write", "AI writes a PR"], ["review", "LGTM reviews"], ["fix", "Commit the fix"], ["prove", "Prove it"]];
  const FILES = [
    ["app/routes/orders.py", "The order endpoints: create, your own orders, and every order for managers."],
    ["app/auth.py", "The decorators: <code>@require_auth</code> lets in anyone logged in; <code>is_owner_or_admin</code> checks ownership."],
    ["app/models.py", "Users and their orders, with shipping addresses."],
    ["security-policy.md", "The access rules. LGTM checks every pull request against them."],
  ];
  const KEY = "lgtm-demo";
  let D = null;

  const fresh = () => ({ info: null, step: 0, pr: null, file: { path: FILES[0][0], content: "", added: [], comments: [], tag: "main" },
    ai: null, probe: null, data: null, term: [], busy: null, error: null, prove: null, fix: null, timer: null });

  window.LGTMDemo = async function demo(args, query) {
    D = fresh();
    try { const s = JSON.parse(localStorage.getItem(KEY) || "{}"); D.pr = s.pr || null; D.step = s.step || 0; } catch (e) { /* private window */ }
    if (query.get("pr")) D.pr = +query.get("pr");
    if (query.get("step")) D.step = Math.max(0, Math.min(4, +query.get("step") - 1));
    L().view().innerHTML = `<section class="page dm" id="dm">
      <header class="dm-top"><ol class="dm-steps" id="dm-steps"></ol><div class="dm-ctl" id="dm-ctl"></div></header>
      <div class="dm-main">
        <aside class="dm-guide"><div id="dm-guide"><p class="muted"><span class="pulse"></span> Loading…</p></div>
          <div class="dm-nav"><button type="button" class="btn" id="dm-back">← Back</button><button type="button" class="btn primary" id="dm-next">Next →</button></div></aside>
        <section class="dm-ide" aria-label="Code">
          <div class="dm-bar"><span class="dm-dots"><i></i><i></i><i></i></span><b>shoply-demo</b><span class="dm-file" id="dm-file"></span><span class="dm-tag" id="dm-tag"></span></div>
          <div class="dm-code" id="dm-code" tabindex="0"></div>
          <div class="dm-term" id="dm-term" hidden></div>
        </section>
      </div></section>`;
    $("#dm-back").addEventListener("click", () => go(D.step - 1));
    $("#dm-next").addEventListener("click", () => go(D.step + 1));
    $("#dm").addEventListener("click", onClick);
    L().S.leave.push(() => { if (D && D.timer) clearInterval(D.timer); });
    try {
      D.info = await L().get("/api/demo/info");
    } catch (e) {
      $("#dm-guide").innerHTML = `<h2>The demo is not available</h2><p class="bad">${esc(e.message)}</p><p class="muted">Connect cyberjj999/shoply-demo to LGTM first.</p>`;
      return;
    }
    if (D.pr) await refresh();
    if (D.step === 0 || !D.pr) await showFile(FILES[0][0]);
    go(D.pr ? D.step : Math.min(D.step, 1));
  };

  // ---------------------------------------------------------------- navigation
  const first = () => (D.data && D.data.rounds[0]) || null;
  const latest = () => (D.data && D.data.rounds[D.data.rounds.length - 1]) || null;
  const done = (r) => r && r.status === "completed";
  const flaggedRound = () => D.data && [...D.data.rounds].reverse().find((r) => done(r) && r.n_flagged);
  function reachable(i) {
    if (i <= 1) return true;
    if (i === 2) return !!D.pr;
    if (i === 3) return done(first());
    return D.data && D.data.rounds.length > 1 && done(latest());
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify({ pr: D.pr, step: D.step })); } catch (e) { /* private window */ } }

  async function go(n) {
    if (n < 0 || n > 4 || !reachable(n)) return;
    D.step = n; save();
    if (n >= 2 && D.pr) poll();
    if (n === 0) await showFile(D.file.path && FILES.some(([p]) => p === D.file.path) ? D.file.path : FILES[0][0]);
    else if (n >= 2 && D.data) await showRound();
    render();
  }

  function render() {
    if (!D || !$("#dm")) return;
    $("#dm-steps").innerHTML = STEPS.map(([, label], i) => `<li><button type="button" data-go="${i}" aria-current="${i === D.step}" class="${i < D.step ? "done" : ""}" ${reachable(i) ? "" : "disabled"}><b>${i < D.step ? "✓" : i + 1}</b><span>${label}</span></button></li>`).join("");
    const backup = D.info && D.info.backup_pr;
    $("#dm-ctl").innerHTML = `${D.pr ? `<a class="btn" href="${esc(prUrl())}" target="_blank" rel="noopener noreferrer">PR #${D.pr} ↗</a>` : ""}
      ${backup && backup !== D.pr ? `<button type="button" class="btn" data-act="backup" title="Open a finished run of this story: PR #${backup}">Show a working run</button>` : ""}
      <button type="button" class="btn" data-act="reset" ${D.busy ? "disabled" : ""} title="Close the live pull request without merging and start again">Start over</button>`;
    $("#dm-guide").innerHTML = `<p class="dm-kicker">Step ${D.step + 1} of 5</p>${GUIDE[STEPS[D.step][0]]()}${D.error ? `<p class="bad">${esc(D.error)}</p>` : ""}`;
    $("#dm-back").hidden = D.step === 0;
    $("#dm-next").hidden = D.step === 4;
    $("#dm-next").disabled = !reachable(D.step + 1) || !!D.busy;
    drawCode(); drawTerm();
  }

  const prUrl = () => (D.data && D.data.pr && D.data.pr.url) || `https://github.com/${D.info.repo}/pull/${D.pr}`;
  const gh = (url, label) => url ? `<a class="dm-gh" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)} ↗</a>` : "";

  // ---------------------------------------------------------------- the five guides
  const GUIDE = {
    codebase() {
      return `<h2>A small online shop's API</h2>
        <p>Shoply sells coffee and tea. Customers log in and place orders; each order carries a shipping address.</p>
        <ul class="dm-rules"><li><b>Customers</b> (alice, bob) may see <b>only their own</b> orders.</li>
          <li><b>Managers</b> may list every order. Only <b>admins</b> delete or refund.</li></ul>
        <p class="muted">Click a file to read how the code enforces that.</p>
        <ol class="dm-files">${FILES.map(([p, what]) => `<li><button type="button" class="linkish" data-file="${esc(p)}">${esc(p)}</button><span>${what}</span></li>`).join("")}</ol>`;
    },

    write() {
      const a = D.ai, t = D.info.task, rec = D.info.recorded;
      const chat = `<div class="dm-chat"><div class="dm-msg dev"><b>Developer</b>${esc(t.ask)}</div>
        ${a ? `<div class="dm-msg ai"><b>${esc(a.model || D.info.model)}${a.replay ? `, recorded ${esc(day(a.replay))}` : ""}</b>${a.done ? `Wrote <code>${esc(a.path)}</code>.` : a.error ? "Stopped." : `<span class="pulse"></span> writing <code>${esc(a.path || "")}</code>…`}</div>` : ""}</div>`;
      const replayBtn = (primary) => rec ? `<button type="button" class="btn ${primary ? "primary" : ""}" data-act="replay">Replay the real run from ${esc(day(rec.at))}</button>` : "";
      if (D.pr && (!a || D.busy !== "push")) {
        return `<h2>PR #${D.pr} is open on GitHub</h2>${chat}
          <p>The AI's code was committed exactly as it came out, pushed, and opened as a pull request. GitHub told LGTM, and its review has started.</p>
          <p>${gh(prUrl(), `Open PR #${D.pr}`)}</p>`;
      }
      if (D.busy === "push") return `<h2>Opening the pull request</h2>${chat}<p class="muted"><span class="pulse"></span> Committing, pushing and opening the PR on GitHub. Watch the terminal.</p>`;
      if (!a || a.error) {
        return `<h2>A developer asks an AI for a feature</h2>
          <p>The shop needs an order tracking endpoint. The developer asks a small coding model running on this laptop (<b>${esc(D.info.model)}</b>), giving it <code>app/routes/orders.py</code> and the list of files. No security hints.</p>
          ${chat}
          ${a && a.error ? `<p class="bad">${esc(a.error)}</p>` : ""}
          <p><button type="button" class="btn primary big" data-act="ask" ${D.info.writer && !D.busy ? "" : "disabled"}>Ask the AI</button></p>
          ${rec ? `<p class="muted">${replayBtn(false)}</p>` : ""}
          ${D.info.writer ? "" : `<p class="muted">Ollama with ${esc(D.info.model)} is not running, so only the replay is available.</p>`}`;
      }
      if (!a.done) return `<h2>The AI is writing the code</h2>${chat}<p class="muted">Its reply streams into the editor as the model produces it.</p>`;
      const p = D.probe;
      if (!p) return `<h2>Trying the new endpoint</h2>${chat}<p class="muted"><span class="pulse"></span> Starting the shop with this code and sending requests…</p>`;
      const rows = probeRows(p);
      if (p.outcome !== "vulnerable") {
        return `<h2>${p.outcome === "safe" ? "This time the AI added the check" : "This time the AI's code doesn't work"}</h2>${chat}${rows}
          <p>${p.outcome === "safe" ? "Its endpoint refuses other customers' orders, so there is nothing for LGTM to catch. Models don't write the same code twice." : esc(p.why)}</p>
          <p>${replayBtn(true)} <button type="button" class="btn" data-act="ask" ${D.info.writer ? "" : "disabled"}>Ask again</button></p>
          <p class="muted"><button type="button" class="linkish" data-act="push">Open a PR with this code anyway</button></p>`;
      }
      return `<h2>The AI wrote the feature</h2>${chat}
        <p>It requires a login and returns the order. Looks fine at a glance. We sent it real requests:</p>${rows}
        <p>The developer doesn't know that, commits it as it is and opens a pull request.</p>
        <button type="button" class="btn primary big" data-act="push" ${D.busy ? "disabled" : ""}>Commit and open a PR</button>`;
    },

    review() {
      const r = first();
      if (!r) return `<h2>Waiting for GitHub…</h2><p class="muted"><span class="pulse"></span> GitHub is telling LGTM about PR #${D.pr}.</p>`;
      if (!done(r)) return waiting(r, "LGTM is reviewing the pull request", `GitHub sent the push to LGTM. Its agents read the change, follow the input, and every candidate must cite real code and pass the evidence judge before it reaches the PR.`);
      if (!r.n_flagged) return `<h2>LGTM passed the PR</h2><p><span class="dm-stamp ok">No security bug found</span></p><p>${gh(r.check_url, "See the check on GitHub")}</p>`;
      return `<h2>LGTM caught the bug</h2>
        <p><span class="dm-stamp bad">${L().plural(r.n_flagged, "finding")} on PR #${D.pr}, merge blocked</span></p>
        ${r.findings.map(findingCard).join("")}
        <p>${gh(r.review_url, "Open the review on GitHub")} ${gh(r.check_url, "The check run")} <a class="dm-gh" href="#/runs/${enc(r.id)}/findings">The review in LGTM</a></p>
        <p class="muted">Its comment is in the editor on the line it points at.</p>`;
    },

    fix() {
      const r = flaggedRound(), r2 = D.data.rounds.length > 1 ? latest() : null;
      const sugg = r && r.suggestions.length;
      if (D.busy === "fix") return `<h2>Committing LGTM's fix</h2><p class="muted"><span class="pulse"></span> Applying the suggestion, committing and pushing to the PR branch. Watch the terminal.</p>`;
      if (D.busy === "fixpush") return `<h2>Pushing the fix</h2><p class="muted"><span class="pulse"></span> Committing and pushing to the PR branch. Watch the terminal.</p>`;
      const fx = D.fix;
      if (!r2 && fx) {
        const chat = `<div class="dm-chat"><div class="dm-msg dev"><b>Developer</b>${rt(fx.prompt)}</div>
          <div class="dm-msg ai"><b>${esc(fx.model || D.info.model)}</b>${fx.done ? `Changed <code>${esc(fx.path)}</code>.` : fx.error ? "Stopped." : `<span class="pulse"></span> fixing <code>${esc(fx.path || "")}</code>…`}</div></div>`;
        if (fx.error) return `<h2>The AI could not fix it</h2>${chat}<p class="bad">${esc(fx.error)}</p><button type="button" class="btn primary" data-act="aifix">Ask again</button>`;
        if (!fx.done) return `<h2>The AI is fixing its code</h2>${chat}`;
        if (!fx.probe) return `<h2>Trying the fix</h2>${chat}<p class="muted"><span class="pulse"></span> Starting the shop with the fixed code and sending the same requests…</p>`;
        const ok = fx.probe.outcome === "safe";
        return `<h2>${ok ? "The AI fixed it" : fx.probe.outcome === "vulnerable" ? "The bug is still there" : "This fix doesn't work"}</h2>${chat}${probeRows(fx.probe)}
          ${ok ? `<p>Alice is refused Bob's order now, and everyone still sees their own. Commit it to the pull request: LGTM reviews the new commit.</p>
            <button type="button" class="btn primary big" data-act="fixpush">Commit and push the fix</button>`
          : `<p>${esc(fx.probe.why)}</p><button type="button" class="btn primary" data-act="aifix">Ask again</button>`}`;
      }
      if (!r2) {
        if (!r) return `<h2>Nothing to fix</h2><p>LGTM passed this pull request.</p>`;
        return `<h2>Fix it</h2>
          <p>Two ways a developer would fix this. Either one is committed to the PR branch and pushed, and LGTM checks the new commit.</p>
          ${sugg ? `<p><button type="button" class="btn primary big" data-act="fix" ${D.busy ? "disabled" : ""}>Commit LGTM's suggestion</button></p>
            <p class="muted">LGTM's comment came with a fix, written by Claude and checked by the evidence judge before it was offered. The same as GitHub's <b>Commit suggestion</b> button. ${gh(r.review_url, "See it on GitHub")}</p>`
          : `<p class="muted">This time the judge did not confirm a committable fix, so LGTM's comment explains the fix in words instead.</p>`}
          <p><button type="button" class="btn ${sugg ? "" : "primary big"}" data-act="aifix" ${D.info.writer && !D.busy ? "" : "disabled"}>Paste LGTM's comment back to the AI</button></p>
          <p class="muted">The developer gives ${esc(D.info.model)} LGTM's finding and asks it to fix the code. Its answer streams into the editor, and we attack it before committing.</p>`;
      }
      if (!done(r2)) return waiting(r2, "LGTM is checking the new commit", `The push added commit <code>${esc(short(r2.sha))}</code> to PR #${D.pr}.`);
      const fast = /verified-fix/.test(r2.trigger || "");
      return `<h2>${r2.n_flagged ? "LGTM still sees a problem" : "LGTM accepted the fix"}</h2>
        <p><span class="dm-stamp ${r2.n_flagged ? "bad" : "ok"}">${r2.n_flagged ? "Still blocked" : `Check passed${r2.latency ? ` in ${L().secs(r2.latency)}` : ""}`}</span></p>
        ${fast && !r2.n_flagged ? `<p>This commit applies exactly the fix LGTM's judge had already checked, and nothing else, so LGTM did not review it again. No loop of reviewing its own suggestion.</p>` : ""}
        <p>${gh(r2.check_url, "The check on GitHub")} <a class="dm-gh" href="#/runs/${enc(r2.id)}">This round in LGTM</a></p>`;
    },

    prove() {
      const v = D.prove;
      const intro = `<h2>Prove it: was the bug real, and does the fix work?</h2>
        <p>We run the shop three times, as <code>main</code>, as the AI's commit <code>${esc(short(first() && first().sha))}</code> and as the fixed commit <code>${esc(short(latest() && latest().sha))}</code>, and send the same requests to each.</p>`;
      if (!v) return intro + `<button type="button" class="btn primary big" data-act="prove" ${D.busy ? "disabled" : ""}>Run the attack</button>`;
      if (v.loading) return intro + `<p class="muted"><span class="pulse"></span> Starting the shop as ${esc(v.loading)} and sending requests…</p>`;
      if (v.error) return intro + `<p class="bad">${esc(v.error)}</p><button type="button" class="btn" data-act="prove">Try again</button>`;
      const cols = [["main", "main"], ["bug", "AI's PR"], ["fix", "With the fix"]];
      const cell = (k, p) => {
        if (!p) return "<td>–</td>";
        if (k === "main" && v.main.outcome === "missing") return `<td class="na">${esc(p.status)}<small>no endpoint yet</small></td>`;
        if (p.expect === "deny") return p.status === 200 ? `<td class="leak">${esc(p.status)}<small>read it</small></td>` : `<td class="okc">${esc(p.status)}<small>refused</small></td>`;
        return p.status === 200 ? `<td class="okc">200<small>works</small></td>` : `<td class="na">${esc(p.status)}</td>`;
      };
      const fixWorks = v.bug.outcome === "vulnerable" && v.fix.outcome === "safe";
      const closeBtn = D.pr === (D.info && D.info.backup_pr) ? `<p class="muted">This is the working run, so it stays as it is on GitHub.</p>`
        : D.data.pr.state === "OPEN" ? `<button type="button" class="btn" data-act="reset">Close PR #${D.pr} without merging</button>` : `<p><span class="dm-stamp ok">PR #${D.pr} closed, not merged</span></p>`;
      return `<h2>${fixWorks ? "The PR was exploitable. The fix closes it." : v.bug.outcome === "vulnerable" ? "The fix did not fully work" : "The attack"}</h2>
        <table class="dm-prove"><thead><tr><th></th>${cols.map(([, l]) => `<th>${l}</th>`).join("")}</tr></thead>
          <tbody>${v.bug.probes.map((p, i) => `<tr><th>${esc(p.what)}</th>${cols.map(([k]) => cell(k, v[k].probes[i])).join("")}</tr>`).join("")}</tbody></table>
        ${v.bug.outcome === "vulnerable" ? `<p>With the AI's code, Alice opened <code>/orders/3</code> and got Bob's order, with his address: <i>${esc((v.bug.probes[1].body || {}).shipping_address || "")}</i>.</p>` : ""}
        ${fixWorks ? `<p>With the fix, that request is refused, and Bob still sees his own order.</p>` : ""}
        ${closeBtn}`;
    },
  };

  function waiting(r, title, text) {
    return `<h2>${title}</h2><p>${text}</p>
      <p class="dm-live"><span class="pulse"></span> ${esc(r.status === "queued" ? "Queued" : L().stageLabel(r.stage))}</p>
      <p><a class="dm-gh" href="#/runs/${enc(r.id)}">Watch it live in LGTM</a> ${gh(prUrl(), "The PR on GitHub")}</p>`;
  }

  function findingCard(f) {
    const b = f.brief;
    return `<div class="dm-finding"><p><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span> <b>${esc(f.cwe)}</b> <code>${esc(f.file)}:${esc(f.line)}</code></p>
      ${b ? `<p class="dm-head">${rt(b.headline)}</p><dl>${[["Impact", b.impact], ["Breaks", b.breaks], ["Fix", b.fix]].filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd>${rt(v)}</dd>`).join("")}</dl>`
        : `<p>${esc((f.explanation || "").slice(0, 400))}…</p>`}</div>`;
  }

  function probeRows(p) {
    return `<ul class="dm-probes">${p.probes.map((x) => {
      const bad = x.expect === "deny" && x.status === 200, good = x.expect === "deny" ? x.status !== 200 && x.status < 500 : x.status === 200;
      const body = x.status === 200 && x.body && x.body.shipping_address ? `order of user ${x.body.user_id}, ${x.body.shipping_address}` : x.crash || "";
      return `<li class="${bad ? "bad" : good ? "good" : "meh"}"><span>${esc(x.what)}</span><code>GET ${esc(x.path)}</code><b>${esc(x.status || "no answer")}</b>${body ? `<small>${esc(body)}</small>` : ""}</li>`;
    }).join("")}</ul>`;
  }

  // ---------------------------------------------------------------- the editor and the terminal
  const PY = /(#.*$)|("""|'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(@[\w.]+)|\b(def|return|if|else|elif|from|import|class|not|in|and|or|None|True|False|for|with|as|raise|is|lambda|abort)\b/g;
  function hl(line, path) {
    if (!/\.py$/.test(path || "")) return esc(line);
    let out = "", last = 0;
    line.replace(PY, (m, c, s, d, k, i) => { out += esc(line.slice(last, i)); out += `<span class="${c ? "tc" : s ? "ts" : d ? "td" : "tk"}">${esc(m)}</span>`; last = i + m.length; return m; });
    return out + esc(line.slice(last));
  }
  function drawCode() {
    const el = $("#dm-code");
    if (!el) return;
    const f = D.file, added = new Set(f.added || []), byLine = {};
    (f.comments || []).forEach((c) => (byLine[c.line] = byLine[c.line] || []).push(c));
    const lines = (f.content || "").replace(/\n$/, "").split("\n");
    el.innerHTML = lines.map((l, i) => {
      const n = i + 1;
      return `<div class="dl ${added.has(n) ? "add" : ""} ${byLine[n] ? "flag" : ""}" ${n === f.focus ? 'id="dm-focus"' : ""}><span class="ln">${n}</span><span class="tx">${hl(l, f.path) || " "}</span></div>${(byLine[n] || []).map(commentHtml).join("")}`;
    }).join("") + (f.writing ? `<div class="dl"><span class="ln"></span><span class="tx"><span class="caret"></span></span></div>` : "");
    $("#dm-file").textContent = f.path || "";
    $("#dm-tag").textContent = f.tag || "";
    const focus = $("#dm-focus");
    if (f.writing) el.scrollTop = el.scrollHeight;
    else if (focus && f.scroll) { focus.scrollIntoView({ block: "center" }); f.scroll = false; }
  }
  function commentHtml(c) {
    return `<div class="dm-cmt"><p class="dm-cmt-h"><b>LGTM</b> <span class="sev ${esc(c.severity)}">${esc(c.severity)}</span> ${rt(c.headline || c.cwe)}</p>
      ${c.fix ? `<p>${rt(c.fix)}</p>` : ""}
      ${c.suggestion ? `<p class="muted">Suggested change, checked by the judge:</p><pre class="dm-sugg">${esc(c.suggestion)}</pre>` : ""}</div>`;
  }
  function drawTerm() {
    const el = $("#dm-term");
    if (!el) return;
    el.hidden = !D.term.length;
    el.innerHTML = D.term.map((t) => t.cmd ? `<div class="tc"><span class="pr">$</span> ${esc(t.cmd)}</div>` : `<div class="${t.bad ? "tb" : "to"}">${esc(t.text)}</div>`).join("");
    el.scrollTop = el.scrollHeight;
  }

  async function showFile(path) {
    const ref = D.step === 0 || !D.pr ? "main" : null;
    const r = await L().get(`/api/demo/view?pr=0&sha=${enc(ref || "main")}&path=${enc(path)}&base=main`).catch((e) => ({ content: `# ${e.message}`, added: [] }));
    D.file = { path, content: r.content, added: [], comments: [], tag: "main" };
  }

  // The file the pull request changed, at the round this step is about, with LGTM's comments on it.
  async function showRound() {
    const r = D.step >= 3 && D.data.rounds.length > 1 ? latest() : first();
    if (!r) return;
    const rf = flaggedRound() || first();
    const path = (rf && rf.findings[0] && rf.findings[0].file) || (D.ai && D.ai.path) || "app/routes/orders.py";
    const base = D.step >= 3 && D.data.rounds.length > 1 ? first().sha : r.base_sha;
    try {
      const v = await L().get(`/api/demo/view?pr=${D.pr}&sha=${enc(r.sha)}&path=${enc(path)}${base ? `&base=${enc(base)}` : ""}`);
      const comments = D.step === 2 && done(r) ? r.findings.filter((f) => f.file === path).map((f) => {
        const s = r.suggestions.find((x) => x.finding_key === f.key);
        return { line: f.line, severity: f.severity, cwe: f.cwe, headline: f.brief && f.brief.headline, fix: f.brief && f.brief.fix, suggestion: s && s.replacement };
      }) : [];
      D.file = { path, content: v.content, added: v.added, comments, tag: `commit ${short(r.sha)}`, focus: comments[0] ? comments[0].line : routeLine(v.content, v.added), scroll: true };
    } catch (e) { /* GitHub unreachable: keep what is shown */ }
  }

  // The first added line that starts a route, so the editor shows the new endpoint rather than an import.
  function routeLine(text, added) {
    const lines = (text || "").split("\n");
    return added.find((n) => /@\w+\.route\(|^\s*def /.test(lines[n - 1] || "")) || added[0];
  }

  // ---------------------------------------------------------------- following LGTM
  async function refresh() {
    if (!D.pr) return;
    const before = JSON.stringify(D.data && D.data.rounds.map((r) => [r.status, r.stage, r.n_flagged, (r.findings || []).map((f) => !!f.brief)]));
    D.data = await L().get(`/api/demo/rounds?pr=${D.pr}`).catch(() => D.data);
    const after = JSON.stringify(D.data && D.data.rounds.map((r) => [r.status, r.stage, r.n_flagged, (r.findings || []).map((f) => !!f.brief)]));
    return before !== after;
  }
  function poll() {
    if (D.timer) return;
    const tick = async () => {
      if (!$("#dm")) { clearInterval(D.timer); D.timer = null; return; }
      if (await refresh()) { if (D.step >= 2) await showRound(); render(); }
    };
    D.timer = setInterval(tick, 3000);
    L().S.timers.push(D.timer);
  }

  // ---------------------------------------------------------------- actions
  async function onClick(e) {
    const g = e.target.closest("[data-go]");
    if (g) return go(+g.dataset.go);
    const f = e.target.closest("[data-file]");
    if (f) { await showFile(f.dataset.file); drawCode(); return; }
    const b = e.target.closest("[data-act]");
    if (!b || b.disabled) return;
    const act = b.dataset.act;
    D.error = null;
    try {
      if (act === "ask") await write(false);
      else if (act === "replay") await write(true);
      else if (act === "push") await push();
      else if (act === "fix") await commitFix();
      else if (act === "aifix") await aiFix();
      else if (act === "fixpush") await fixPush();
      else if (act === "prove") await prove();
      else if (act === "reset") await reset();
      else if (act === "backup") { D.pr = D.info.backup_pr; D.ai = null; D.probe = null; D.prove = null; D.term = []; await refresh(); go(2); }
    } catch (err) { D.busy = null; D.error = err.message; render(); }
  }

  // Small models sometimes wrap the file in the prompt's <file> tags or in a Markdown fence.
  const clean = (t) => t.replace(/^\s*<file>\n?/, "").replace(/^\s*```[\w-]*\n/, "").replace(/\n?<\/file>\s*$/, "\n").replace(/\n```\s*$/, "\n");

  async function write(replay) {
    D.busy = "write"; D.probe = null; D.term = [];
    const start = await L().post("/api/demo/start", {});
    const before = start.before, tail = before.split("\n");
    D.ai = { path: start.path, text: "", times: [], model: D.info.model, replay: null };
    D.file = { path: start.path, content: before, added: [], comments: [], tag: "the AI's code (not committed)", writing: true };
    render();
    const t0 = performance.now();
    let pending = false;
    const add = (delta) => {
      D.ai.text += delta;
      if (!pending) {
        pending = true;
        requestAnimationFrame(() => {
          pending = false;
          const lines = clean(D.ai.text).split("\n");
          D.file.content = lines.concat(tail.slice(lines.length)).join("\n");
          drawCode();
        });
      }
    };
    if (replay) {
      const rec = await L().get("/api/demo/recorded");
      if (!rec.times) throw new Error("No recorded run is saved yet.");
      D.ai.replay = rec.at; D.ai.model = rec.model; render();
      let at = 0;
      for (const [t, delta] of rec.times) { if (!$("#dm")) return; if (t > at) await sleep((t - at) * 1000); at = t; add(delta); }
    } else {
      D.ai.model = await streamModel(start.path, D.info.task.ask, (delta) => { D.ai.times.push([(performance.now() - t0) / 1000, delta]); add(delta); }) || D.ai.model;
    }
    let final = clean(D.ai.text);
    if (before.endsWith("\n")) final = final.replace(/\s+$/, "") + "\n";
    await L().post("/api/ws/file", { repo: D.info.repo, path: start.path, content: final });
    const was = new Set(before.split("\n"));
    D.file = { path: start.path, content: final, added: final.split("\n").map((l, i) => (!was.has(l) && l.trim() ? i + 1 : 0)).filter(Boolean), comments: [], tag: "the AI's code (not committed)" };
    D.file.focus = routeLine(final, D.file.added); D.file.scroll = true;
    D.ai.done = true; render();
    D.probe = await L().post("/api/demo/probe", { ref: "draft" });
    if (!replay && D.probe.outcome === "vulnerable") {
      L().post("/api/demo/record", { model: D.ai.model, path: start.path, times: D.ai.times, outcome: "vulnerable" })
        .then(() => L().get("/api/demo/info")).then((i) => { D.info.recorded = i.recorded; }).catch(() => {});
    }
    D.busy = null; render();
  }

  // The local model rewrites one file; each piece of text goes to onDelta as it arrives. Returns the model's name.
  async function streamModel(path, prompt, onDelta) {
    const res = await fetch("/api/ws/generate", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo: D.info.repo, path, prompt, engine: "local" }) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `${res.status} ${res.statusText}`);
    const reader = res.body.getReader(), dec = new TextDecoder();
    let buf = "", model = "";
    for (;;) {
      const { value, done: end } = await reader.read();
      if (end) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        const ev = JSON.parse(line);
        if (ev.type === "text") onDelta(ev.delta);
        else if (ev.type === "done") model = ev.model || "";
        else if (ev.type === "error") throw new Error(ev.msg);
      }
    }
    return model;
  }

  // Step 4, second way: the developer pastes LGTM's finding back to the model, which rewrites the file.
  async function aiFix() {
    const r = flaggedRound(), f = r && r.findings[0];
    if (!f) return;
    D.busy = "aifix"; D.term = [];
    await L().post("/api/demo/checkout", { pr: D.pr });
    const path = f.file, b = f.brief || {};
    const prompt = `LGTM's security review of this change says: ${b.headline || f.cwe} ${b.impact || ""} Fix: ${b.fix || (f.explanation || "").slice(0, 300)} Fix the code.`.replace(/\s+/g, " ");
    // Every attempt starts from the pull request's code, not from an earlier attempt left in the workspace.
    const head = await L().get(`/api/demo/view?pr=${D.pr}&sha=${enc(latest().sha)}&path=${enc(path)}`);
    const before = head.content || "", tail = before.split("\n");
    await L().post("/api/ws/file", { repo: D.info.repo, path, content: before });
    D.fix = { prompt, path, text: "", model: D.info.model };
    D.file = { path, content: before, added: [], comments: [], tag: "the AI's fix (not committed)", writing: true };
    render();
    let pending = false;
    try {
      D.fix.model = await streamModel(path, prompt, (delta) => {
        D.fix.text += delta;
        if (!pending) {
          pending = true;
          requestAnimationFrame(() => { pending = false; const lines = clean(D.fix.text).split("\n"); D.file.content = lines.concat(tail.slice(lines.length)).join("\n"); drawCode(); });
        }
      }) || D.fix.model;
    } catch (e) { D.fix.error = e.message; D.busy = null; D.file.writing = false; render(); return; }
    let final = clean(D.fix.text);
    if (before.endsWith("\n")) final = final.replace(/\s+$/, "") + "\n";
    await L().post("/api/ws/file", { repo: D.info.repo, path, content: final });
    const was = new Set(before.split("\n"));
    const added = final.split("\n").map((l, i) => (!was.has(l) && l.trim() ? i + 1 : 0)).filter(Boolean);
    D.file = { path, content: final, added, comments: [], tag: "the AI's fix (not committed)", focus: added[0], scroll: true };
    D.fix.done = true; render();
    D.fix.probe = await L().post("/api/demo/probe", { ref: "draft" });
    D.busy = null; render();
  }

  async function fixPush() {
    D.busy = "fixpush"; D.term = []; render();
    const branch = await L().post("/api/demo/checkout", { pr: D.pr }).then((x) => x.branch).catch(() => "");
    await streamTerm("/api/ws/push", { repo: D.info.repo, branch, message: "Check the order owner before returning it (from the LGTM review)",
      title: "", how: "fix", preset: D.info.task.id });
    D.busy = null; D.fix = null;
    for (let i = 0; i < 10 && D.data.rounds.length < 2; i++) { await sleep(1500); await refresh(); }
    await showRound(); render();
  }

  async function streamTerm(url, body) {
    const res = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `${res.status} ${res.statusText}`);
    const reader = res.body.getReader(), dec = new TextDecoder();
    let buf = "", result = null;
    for (;;) {
      const { value, done: end } = await reader.read();
      if (end) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        const ev = JSON.parse(line);
        if (ev.type === "cmd") D.term.push({ cmd: ev.cmd });
        else if (ev.type === "out") (ev.text || "").split("\n").filter((x) => x.trim()).forEach((x) => D.term.push({ text: x, bad: ev.ok === false }));
        else if (ev.type === "done") result = ev.result;
        else if (ev.type === "error") throw new Error(ev.msg);
        drawTerm();
      }
    }
    return result;
  }

  async function push() {
    D.busy = "push"; D.term = []; render();
    const t = D.info.task;
    const r = await streamTerm("/api/ws/push", { repo: D.info.repo, branch: `${t.branch}-${stamp()}`, message: t.message, title: t.title,
      how: D.ai && D.ai.replay ? "recorded" : "live", preset: t.id });
    D.busy = null;
    if (!r || !r.pr) throw new Error("The push finished without a pull request.");
    D.pr = r.pr.number; D.data = null; save();
    await refresh();
    go(2);
  }

  async function commitFix() {
    D.busy = "fix"; D.term = []; render();
    await streamTerm("/api/demo/fix", { pr: D.pr });
    D.busy = null;
    for (let i = 0; i < 10 && D.data.rounds.length < 2; i++) { await sleep(1500); await refresh(); }
    await showRound(); render();
  }

  async function prove() {
    D.busy = "prove";
    const v = {};
    try {
      for (const [k, ref, label] of [["main", "main", "main"], ["bug", first().sha, `the AI's commit ${short(first().sha)}`], ["fix", latest().sha, `the fixed commit ${short(latest().sha)}`]]) {
        D.prove = { loading: label }; render();
        v[k] = await L().post("/api/demo/probe", { ref, pr: D.pr });
      }
      D.prove = v;
    } catch (e) { D.prove = { error: e.message }; }
    D.busy = null; render();
  }

  // An in-page confirm: the embedded browser blocks window.confirm.
  function confirmBox(title, text, yes) {
    return new Promise((resolve) => {
      const el = document.createElement("div");
      el.className = "dm-ask";
      el.innerHTML = `<div class="dm-ask-box" role="dialog" aria-modal="true" aria-label="${esc(title)}"><h3>${esc(title)}</h3><p>${esc(text)}</p>
        <div><button type="button" class="btn" data-a="no">Cancel</button><button type="button" class="btn primary" data-a="yes">${esc(yes)}</button></div></div>`;
      document.body.appendChild(el);
      el.addEventListener("click", (e) => { const b = e.target.closest("[data-a]"); if (b || e.target === el) { el.remove(); resolve(!!b && b.dataset.a === "yes"); } });
      $("[data-a=yes]", el).focus();
    });
  }

  async function reset() {
    const live = D.pr && D.pr !== (D.info && D.info.backup_pr);
    if (live && !(await confirmBox(`Close PR #${D.pr} and start over?`, "The pull request is closed on GitHub without merging, and the code goes back to main.", "Close it and start over"))) return;
    D.busy = "reset"; render();
    await L().post("/api/demo/close", { pr: live ? D.pr : null });
    const info = D.info;
    if (D.timer) clearInterval(D.timer);
    D = Object.assign(fresh(), { info: await L().get("/api/demo/info").catch(() => info) });
    save();
    await showFile(FILES[0][0]);
    go(1);
  }
})();
