// LGTM landing page (signed out): what LGTM is, how it fits into a pull request in three steps, how a review
// works and what it has caught. Uses helpers from app.js (window.LGTM).
(function () {
  "use strict";

  const L = () => window.LGTM;
  const GH = '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>';
  const OWL = (cls = "") => `<img class="mascot ${cls}" src="/assets/mascot/owl.webp" alt="" width="720" height="672" decoding="async">`;
  // Line-art for steps 1 and 2 of "how it works" (step 3 is the owl).
  const ART_AI = '<svg viewBox="0 0 120 120" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="60" cy="9" r="4" fill="currentColor"/><path d="M60 13v10"/><rect x="31" y="23" width="58" height="36" rx="14"/><rect x="24" y="35" width="7" height="13" rx="3.5"/><rect x="89" y="35" width="7" height="13" rx="3.5"/><rect x="38" y="31" width="44" height="20" rx="10" fill="currentColor" stroke="none"/><circle cx="52" cy="41" r="3.6" fill="var(--bg)" stroke="none"/><circle cx="68" cy="41" r="3.6" fill="var(--bg)" stroke="none"/><rect x="22" y="66" width="76" height="46" rx="10"/><path d="M50 83l-9 8 9 8M70 83l9 8-9 8M63 81l-6 20"/><circle cx="76" cy="73" r="1.2" fill="currentColor"/><circle cx="82" cy="73" r="1.2" fill="currentColor"/><circle cx="88" cy="73" r="1.2" fill="currentColor"/></svg>';
  const ART_PR = `<svg viewBox="0 0 120 120" aria-hidden="true"><g transform="translate(8 4) scale(6.5)">${GH.replace(/^<svg[^>]*>/, "").replace("</svg>", "")}</g><circle cx="90" cy="96" r="25" fill="var(--bg)"/><g fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"><circle cx="79" cy="82" r="5.5"/><circle cx="79" cy="109" r="5.5"/><circle cx="103" cy="109" r="5.5"/><path d="M79 87.5v16M103 103.5V95a8 8 0 0 0-8-8h-5"/><path d="m93 81 -4 6 4 6"/></g></svg>`;

  // The held-out advisories LGTM flagged (docs/real-prs-eval.md; final run: benchmark/runs/final-2026-11).
  // `file` is where the flagged finding sat; null means it flagged the pull request but in a different file than the advisory names.
  const SQL = "SQL injection", AUTHZ = "Missing access check", IDOR = "Insecure direct object reference";
  const CASES = [
    ["django/django", 91498, SQL, "CVE-2026-1207", "GHSA-mwm9-4648-f68q", "A raster lookup's band index went straight into PostGIS SQL.", "django/contrib/gis/db/backends/postgis/operations.py"],
    ["collerek/ormar", 1799, SQL, "CVE-2026-26198", "GHSA-xxh2-68g9-8jqr", "The min() and max() aggregates trusted the column name they were given.", "ormar/queryset/actions/select_action.py"],
    ["alerta/alerta", 2535, SQL, "CVE-2026-34400", "GHSA-8prr-286p-4w7j", "Search terms were formatted into the alerts WHERE clause.", "alerta/database/backends/postgres/parser.py"],
    ["taigaio/taiga-back", 858, SQL, "CVE-2025-62367", "GHSA-chm9-9wwq-xffj", "The ?epic= parameter was formatted into a raw SQL subquery.", "taiga/projects/userstories/utils.py"],
    ["rucio/rucio", 324, SQL, "CVE-2026-29090", "GHSA-6j7p-qjhg-9947", "Dataset search filters were formatted into raw Postgres SQL.", "lib/rucio/core/did_meta_plugins/filter_engine.py"],
    ["rucio/rucio", 324, SQL, "CVE-2026-29080", "GHSA-vjr5-c9qv-hgm3", "The Oracle JSON filter built its query the same way.", "lib/rucio/core/did_meta_plugins/filter_engine.py"],
    ["piccolo-orm/piccolo", 1951, SQL, "CVE-2023-47128", "GHSA-xq59-7jf3-rjc6", "Savepoint names were interpolated into SAVEPOINT statements.", "piccolo/engine/postgres.py"],
    ["django-cms/django-cms", 10680, AUTHZ, "CVE-2026-54624", "GHSA-vgxm-h9gx-h9w7", "A new structure endpoint dropped the page permission check.", "cms/views.py"],
    ["khoj-ai/khoj", 37977, IDOR, "CVE-2024-52294", "GHSA-hq4h-w933-jm6c", "Any signed-in user could cancel anyone's subscription by passing their email.", "src/khoj/routers/subscription.py"],
    ["getsentry/sentry", 45706, IDOR, "CVE-2024-45606", "GHSA-v345-w9f2-mpm5", "Alert rules in other organizations could be muted.", "src/sentry/api/endpoints/rule_snooze.py"],
    ["getsentry/sentry", 45706, IDOR, "CVE-2024-45605", "GHSA-54m3-95j9-v89j", "Anyone could delete another user's notification settings.", "src/sentry/api/endpoints/user_notification_options_detail.py"],
    ["goauthentik/authentik", 26228, AUTHZ, null, "GHSA-hmrg-vpp4-gj88", "New event-stream handlers skipped the permission check on the existing one.", "authentik/enterprise/providers/ssf/views/stream.py"],
    ["makeplane/plane", 61959, IDOR, "CVE-2026-39374", "GHSA-4q54-h4x9-m329", "Any project member could change the dates of any issue on the instance.", "apiserver/plane/app/views/issue/base.py"],
    ["openedx/openedx-platform", 8218, AUTHZ, "CVE-2026-97702", "GHSA-95xv-3c54-c3pw", "A support endpoint let any learner look up other accounts.", "lms/djangoapps/support/rest_api/v1/views.py"],
    ["paperless-ngx/paperless-ngx", 47676, AUTHZ, null, "GHSA-96jx-fj7m-qh6x", "Global search showed other users' mail accounts and rules.", null],
  ];
  const stars = (n) => (n >= 10000 ? Math.round(n / 1000) + "k" : n >= 1000 ? (n / 1000).toFixed(1) + "k" : String(n));
  const caseCard = ([repo, n, kind, cve, ghsa, what, file]) => {
    const { esc } = L();
    return `<li class="case">
      <div class="case-top"><b>${esc(repo)}</b><span class="case-stars" title="GitHub stars">&#9733; ${stars(n)}</span></div>
      <p class="case-what">${esc(what)}</p>
      <p class="case-kind"><span>${esc(kind)}</span><a href="https://github.com/advisories/${ghsa}" target="_blank" rel="noopener">${cve || ghsa}</a></p>
      <p class="case-hit"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3 8.5 3.2 3.2L13 4.8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>${file ? `Flagged in <code>${esc(file)}</code>` : "Flagged in the pull request that introduced it"}</span></p>
    </li>`;
  };

  window.LGTMLanding = function landing(query) {
    const { page, S } = L();
    const app = S.me && S.me.app;
    const err = query.get("error");
    const signIn = app ? `<a class="btn primary" href="/auth/login">${GH}<span>Sign in with GitHub</span></a>` : `<a class="btn primary" href="/setup.html">${GH}<span>Create the GitHub App</span></a>`;
    page(`
      <div class="land">
        <section class="land-hero">
          ${OWL("hero-owl")}
          <h1>LGTM: your AI security reviewer on every pull request.</h1>
          ${err ? `<p class="notice warn">${err === "expired" ? "That sign-in link expired. Sign in again." : "GitHub did not grant access. Sign in again."}</p>` : ""}
          <div class="actions">${signIn}</div>
        </section>

        <section class="land-how" aria-label="How LGTM works">
          <ol class="how">
            <li><div class="how-t"><span class="how-n">1</span><div><b>Developer uses AI to add new features</b><span>New features in a big repository</span></div></div><div class="how-art">${ART_AI}</div></li>
            <li><div class="how-t"><span class="how-n">2</span><div><b>Pull request opens</b><span>The diff and SECURITY.md go to LGTM</span></div></div><div class="how-art">${ART_PR}</div></li>
            <li><div class="how-t"><span class="how-n">3</span><div><b>LGTM reviews and verifies</b><span>Flags the flaw and suggests a fix the developer can accept</span></div></div><div class="how-art how-owl"><img class="mascot" src="/assets/mascot/owl.webp" alt="LGTM, the owl mascot, giving a thumbs up" width="720" height="672" decoding="async"></div></li>
          </ol>
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

        <section class="land-caught" aria-labelledby="caught-h">
          <h2 id="caught-h">Proven on real vulnerabilities in real open-source repositories</h2>
          <p class="caught-sub">We ran LGTM on the pull requests that introduced 17 published security advisories. It flagged ${CASES.length}.</p>
          <ul class="cases">${CASES.map(caseCard).join("")}</ul>
        </section>

        <section class="land-cta">
          ${OWL("cta-owl")}
          <p>Install it on one repository and open a pull request.</p>
          <div class="actions">${signIn}</div>
        </section>
      </div>`, "landing");
  };
})();
