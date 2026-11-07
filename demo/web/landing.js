// LGTM landing page (signed out): a looping, animated pull request shows what LGTM does, then how a review
// works and what it has caught. Uses helpers from app.js (window.LGTM).
(function () {
  "use strict";

  const L = () => window.LGTM;
  const GH = '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>';
  const SHIELD = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5 4 5.5v6.2c0 4.6 3.3 8.5 8 9.8 4.7-1.3 8-5.2 8-9.8V5.5z" fill="currentColor"/><path d="m8.5 12.2 2.4 2.4 4.8-5" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  // The pull request in the demo. Line 64 is typed in live; the fix replaces it.
  const LINES = [
    [58, ""],
    [59, '<k>@users_bp</k>.route(<s>"/search"</s>, methods=[<s>"GET"</s>])'],
    [60, '<k>@require_role</k>(<s>"manager"</s>)'],
    [61, '<k>def</k> <f>search_users</f>():'],
    [62, '    name = request.args.get(<s>"name"</s>, <s>""</s>)'],
    [63, "    rows = session.execute("],
    [64, null],
    [65, "    )"],
    [66, "    <k>return</k> jsonify([<f>dict</f>(r._mapping) <k>for</k> r <k>in</k> rows])"],
  ];
  const BAD = `        text(f"SELECT * FROM users WHERE username LIKE '%{name}%'")`;
  const FIX = [`        text("SELECT * FROM users WHERE username LIKE :q"),`, `        {"q": f"%{name}%"},`];
  const STEPS = ["Developer pushes", "LGTM reviews", "Finding on the line", "Fix clears the block"];
  const STAGES = ["Reading the diff", "Investigator follows name into the query", "SQL-injection reviewer", "Checking the cited evidence", "Kev judge"];

  window.LGTMLanding = function landing(query) {
    const { page, esc, S } = L();
    const app = S.me && S.me.app;
    const err = query.get("error");
    const signIn = app ? `<a class="btn primary" href="/auth/login">${GH}<span>Sign in with GitHub</span></a>` : `<a class="btn primary" href="/setup.html">${GH}<span>Create the GitHub App</span></a>`;
    page(`
      <div class="land">
        <section class="land-hero">
          <div class="land-copy">
            <h1>Security review on every pull request, with proof.</h1>
            <p class="lede">LGTM's agents read each change the way a security engineer would. They follow untrusted input into the code, check it against your access rules, and only block a merge when they can cite the lines that prove the bug.</p>
            ${err ? `<p class="notice warn">${err === "expired" ? "That sign-in link expired. Sign in again." : "GitHub did not grant access. Sign in again."}</p>` : ""}
            <div class="actions">${signIn}<a class="btn" href="#/onboarding">How setup works</a></div>
            <p class="land-fine">Installs on the repositories you choose. Reads code, writes checks and reviews, nothing else.</p>
          </div>
          <div class="land-stage">
            <figure class="pr" id="pr-demo" aria-label="Example: LGTM blocks a pull request with SQL injection, then passes it after the fix">
              <div class="pr-chrome" aria-hidden="true"><span class="pr-dots"><i></i><i></i><i></i></span><span class="pr-url">github.com/acme/shop/pull/42</span></div>
              <div class="pr-head">
                <p class="pr-title">Add user search for the support dashboard <span>#42</span></p>
                <p class="pr-meta"><span class="pr-state">Open</span><span><b>dev</b> wants to merge into <code>main</code></span></p>
              </div>
              <div class="pr-file">
                <div class="pr-file-h"><code>app/routes/users.py</code><span class="pr-plus">+8</span></div>
                <div class="pr-code" id="pr-code"></div>
                <div class="pr-comment" id="pr-comment">
                  <div class="pr-comment-h"><span class="pr-bot">${SHIELD}</span><b>lgtm-security-review</b><span class="pr-bot-tag">bot</span><span class="pr-comment-state" id="pr-cstate"></span></div>
                  <p><span class="pr-sev">High</span> <b>SQL injection (CWE-89)</b>, confirmed by the Kev judge.</p>
                  <p class="pr-why"><code>name</code> comes straight from <code>request.args</code> and is formatted into the query. Pass it as a bound parameter.</p>
                </div>
              </div>
              <div class="pr-checks">
                <div class="pr-check" id="pr-check"><span class="pr-ci" aria-hidden="true"></span><b>LGTM security review</b><span class="pr-check-t" id="pr-check-t"></span></div>
                <div class="pr-merge" id="pr-merge"></div>
              </div>
            </figure>
            <ol class="land-steps" id="pr-steps" aria-hidden="true">${STEPS.map((s, i) => `<li data-step="${i}"><span>${i + 1}</span>${esc(s)}</li>`).join("")}</ol>
          </div>
        </section>

        <section class="land-flow" aria-labelledby="flow-h">
          <h2 id="flow-h">What happens in the two minutes after you push</h2>
          <ol class="flow">
            <li><b>Pull request opened</b><span>GitHub tells LGTM within seconds and a check appears on the PR.</span></li>
            <li><b>Semgrep on the diff</b><span>Known-bad patterns in the changed files, each one triaged.</span></li>
            <li><b>Agents investigate</b><span>They follow input across files and read your security policy.</span></li>
            <li><b>Evidence check</b><span>Every claim must cite code that really exists.</span></li>
            <li><b>Kev judge</b><span>A second model decides whether that evidence proves the bug.</span></li>
            <li><b>Check and review</b><span>A failing check, comments on the lines, and a block that lifts when you fix it.</span></li>
          </ol>
        </section>

        <section class="land-proof" aria-label="What LGTM has caught">
          <div><p class="proof-big">CVE-2025-62367</p><p>We replayed taiga-back's 2016 change as a pull request. LGTM blocked it at <code>utils.py</code> line 147, the advisory's own location.</p></div>
          <div><p class="proof-big">Proof or silence</p><p>A finding reaches your pull request only if the code it cites exists and the judge agrees it proves the bug. Everything else is dropped.</p></div>
          <div><p class="proof-big">Fix, push, unblocked</p><p>Push the fix and LGTM reviews the new commit, marks the finding fixed and dismisses its own block.</p></div>
        </section>

        <section class="land-cta">
          <p>Install it on one repository and open a pull request.</p>
          <div class="actions">${signIn}</div>
        </section>
      </div>`, "landing");
    runDemo();
  };

  // ---------------------------------------------------------------- the animated pull request
  function runDemo() {
    const { S, esc } = L();
    const code = document.getElementById("pr-code");
    if (!code) return;
    const fig = document.getElementById("pr-demo");
    const comment = document.getElementById("pr-comment"), cstate = document.getElementById("pr-cstate");
    const check = document.getElementById("pr-check"), checkT = document.getElementById("pr-check-t"), merge = document.getElementById("pr-merge");
    const steps = Array.from(document.querySelectorAll("#pr-steps li"));
    let alive = true;
    const timers = [];
    S.leave.push(() => { alive = false; timers.forEach(clearTimeout); });
    const wait = (ms) => new Promise((r) => timers.push(setTimeout(r, ms)));
    const hl = (s) => esc(s)
      .replace(/\b(f?)&quot;(.*?)&quot;/g, (m, f, body) => `${f ? '<span class="tk">f</span>' : ""}<span class="ts">&quot;${body}&quot;</span>`)
      .replace(/\btext(?=\()/g, '<span class="tf">text</span>');
    const line = (n, html, cls = "add") => `<div class="l ${cls}" data-n="${n}"><span class="n">${n}</span><span class="m">${cls === "del" ? "−" : cls === "add" ? "+" : " "}</span><span class="c">${html}</span></div>`;
    const render = (mid, shift = 0) => {   // shift: lines below the change move down when the fix adds one
      code.innerHTML = LINES.map(([n, html]) => (n === 64 ? mid : n === 58 ? line(58, "", "ctx") : line(n > 64 ? n + shift : n, html))).join("")
        .replace(/<k>/g, '<span class="tk">').replace(/<\/k>/g, "</span>").replace(/<s>/g, '<span class="ts">').replace(/<\/s>/g, "</span>").replace(/<f>/g, '<span class="tf">').replace(/<\/f>/g, "</span>");
    };
    const setCheck = (state, text) => { check.dataset.state = state; checkT.textContent = text; };
    const setMerge = (state, text) => { merge.dataset.state = state; merge.textContent = text; };
    const setStep = (i) => steps.forEach((s, j) => { s.classList.toggle("on", j === i); s.classList.toggle("done", j < i); });

    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      render(line(64, hl(BAD), "add flag"));
      comment.classList.add("show"); cstate.textContent = "";
      setCheck("fail", "1 security finding"); setMerge("blocked", "Merging is blocked: the required check failed");
      setStep(2);
      return;
    }

    const loop = async () => {
      while (alive) {
        // 1. the developer's change is typed in
        fig.dataset.phase = "push"; setStep(0);
        comment.classList.remove("show", "resolved"); cstate.textContent = "";
        setCheck("wait", "Queued"); setMerge("wait", "Some checks haven't completed yet");
        render(line(64, "", "add typing"));
        const target = code.querySelector('[data-n="64"] .c');
        for (let i = 1; i <= BAD.length && alive; i += 2) { target.innerHTML = hl(BAD.slice(0, i)); await wait(22); }
        target.parentElement.classList.remove("typing");
        await wait(500);
        // 2. LGTM reviews it
        setStep(1); fig.dataset.phase = "review";
        for (const st of STAGES) { if (!alive) return; setCheck("run", `In progress: ${st}`); await wait(950); }
        // 3. the finding lands on the line
        setStep(2); fig.dataset.phase = "found";
        code.querySelector('[data-n="64"]').classList.add("flag");
        setCheck("fail", "Failed: 1 security finding"); setMerge("blocked", "Merging is blocked: the required check failed");
        await wait(250);
        comment.classList.add("show");
        await wait(4200);
        // 4. the fix is pushed and clears the block
        setStep(3); fig.dataset.phase = "fix";
        render(line(64, hl(BAD), "del") + line(64, "", "add typing fix") + line(65, "", "add fix"), 1);
        const a = code.querySelectorAll(".l.fix .c");
        cstate.textContent = "";
        for (let k = 0; k < FIX.length && alive; k++) {
          for (let i = 1; i <= FIX[k].length && alive; i += 2) { a[k].innerHTML = hl(FIX[k].slice(0, i)); await wait(18); }
        }
        code.querySelectorAll(".typing").forEach((x) => x.classList.remove("typing"));
        setCheck("run", "In progress: reviewing the new commit"); setMerge("wait", "Some checks haven't completed yet");
        await wait(1800);
        comment.classList.add("resolved"); cstate.textContent = "Fixed";
        setCheck("pass", "Passed: no security findings"); setMerge("ok", "All checks have passed");
        await wait(4200);
      }
    };
    loop();
  }
})();
