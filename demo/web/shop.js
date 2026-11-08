// Shoply's storefront, running real code: a small browser on the shop, as it behaves with a given version of the code.
// Used by the Workspace's App tab. Every page that shows data is a real request to shoply's API running that code
// (via /api/demo/shop), so whatever the code does is what you see: if an endpoint skips its ownership check, Bob can
// open Alice's order; if a search builds SQL from the input, Maria's search can return every user's password hash.
(function () {
  "use strict";
  const L = () => window.LGTM;
  const esc = (s) => L().esc(s);
  const $ = (s, el) => el.querySelector(s);
  const $$ = (s, el) => [...el.querySelectorAll(s)];

  const PEOPLE = { 1: "alice", 2: "bob", 3: "carol", 4: "dave", 5: "maria", 6: "root" };
  const IDS = { alice: 1, bob: 2, maria: 5 };
  const ACCOUNTS = [["alice", "customer"], ["bob", "customer"], ["maria", "manager"], ["", "signed out"]];
  const cap = (x) => (x ? x[0].toUpperCase() + x.slice(1) : "");
  const SQLI = "zzz%' UNION SELECT id, email, password_hash FROM users --";

  // The catalogue lives in the storefront; shoply's API stores orders (a total and an address), which is all a
  // checkout needs. The seed orders' contents are shown from ORDER_ITEMS for the same reason.
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
  const art = (p, size) => `<svg viewBox="0 0 120 120" width="${size}" height="${size}" style="width:${size}px;height:${size}px" aria-hidden="true">${ART[p.art](p.c1, p.c2)}</svg>`;
  const money = (n) => `$${Number(n || 0).toFixed(2)}`;
  const ORDER_ITEMS = { 1: ["ethiopia", "earlgrey"], 2: ["matcha"], 3: ["pourover", "house", "mug"], 4: ["house", "mug"], 5: ["earlgrey"], 6: ["pourover", "matcha", "mug"] };
  const ADDRESS = { alice: "12 Orchard Road, Singapore 238826", bob: "7 Marina Boulevard #22-01, Singapore 018980", maria: "50 Jurong Gateway Road, Singapore 608549" };
  const CLIENT = new Set(["/", "/track", "/staff"]);   // storefront pages that need no API call
  const leakedValue = (v) => /@/.test(String(v)) || /^[0-9a-f]{40,}$/.test(String(v)) || /^\$?pbkdf2|^scrypt|^\$2[aby]\$/.test(String(v));

  // mount(el, cfg): cfg.versions() -> [[id, label, ref]] (ref: "main", "draft" or a commit), cfg.version() -> the
  // default id, cfg.pr() -> the pull request number or null. Returns {draw, reload}.
  window.LGTMShop = function mount(el, cfg) {
    const S = { as: "alice", path: "/", version: null, resp: null, loading: false, key: "", bought: {}, toast: null, started: "" };
    const versions = () => cfg.versions();
    const current = () => { const vs = versions(); return S.version && vs.some(([v]) => v === S.version) ? S.version : cfg.version(); };
    const ref = () => (versions().find(([v]) => v === current()) || [, , "main"])[2];
    const keyNow = () => [ref(), cfg.pr && cfg.pr(), cfg.stamp ? cfg.stamp() : ""].join("|");
    const itemsOf = (o) => (ORDER_ITEMS[o.id] || S.bought[o.id] || ["house"]).map((id) => PRODUCTS.find((x) => x.id === id)).filter(Boolean);

    el.addEventListener("click", (e) => {
      const b = e.target.closest("[data-as], [data-version], [data-goto]");
      if (!b || !el.contains(b)) return;
      if (b.dataset.version) S.version = b.dataset.version;
      if (b.dataset.goas !== undefined) S.as = b.dataset.goas || null;
      else if (b.dataset.as !== undefined) S.as = b.dataset.as || null;
      if (b.dataset.goto) S.path = b.dataset.goto;
      S.toast = null;
      load();
    });

    async function load(method = "GET", json = null) {
      S.key = keyNow();
      const path = method === "POST" ? "/orders" : S.path;
      const body = { ref: ref(), pr: (cfg.pr && cfg.pr()) || null };
      if (CLIENT.has(path) && method === "GET") {
        if (S.started !== S.key) {   // start the shop for this version anyway, so the next click is quick
          S.started = S.key;
          L().post("/api/demo/shop", { ...body, as: null, path: "/health" }).catch(() => {});
        }
        S.resp = { status: 200, path, client: true };
        return draw();
      }
      S.loading = true; draw();
      const out = await L().post("/api/demo/shop", { ...body, as: S.as, path, method, json }).catch((e) => ({ status: 0, error: e.message }));
      out.path = path;
      S.loading = false;
      if (method === "POST" && out.status === 201 && out.data) {
        S.toast = `Order #${out.data.id} placed: ${json.item}. On its way to ${out.data.shipping_address}.`;
        S.bought[out.data.id] = [json.id];
        S.path = "/orders/mine";
        return load();
      }
      if (method === "POST") S.toast = out.status === 401 ? "Sign in to buy." : `The order failed (HTTP ${out.status}).`;
      else S.resp = out;
      draw();
    }

    function draw() {
      if (!el.isConnected) return;
      const me = S.as, v = current(), staff = me === "maria";
      const nav = [["/", "Shop"], ["/orders/mine", "My orders"], ["/track", "Track an order"], ...(staff ? [["/orders/all", "All orders"], ["/staff", "Find a customer"]] : []), [`/users/${IDS[me] || 1}`, "Account"]];
      const tries = [["bob", "/orders/1", "As Bob, track order #1 (Alice's)"], ["alice", "/orders/1", "As Alice, track her own order #1"],
        ["maria", `/users/search?name=${encodeURIComponent(SQLI)}`, "As Maria, search customers for the SQL text"], ["maria", "/users/search?name=al", "As Maria, search for \"al\""]];
      el.innerHTML = `
        <div class="dm-shopbar">
          <div class="dm-seg"><span>Signed in as</span>${ACCOUNTS.map(([id, role]) => `<button type="button" data-as="${id}" aria-pressed="${(id || null) === (me || null)}">${esc(cap(id) || "Nobody")}<em>${role}</em></button>`).join("")}</div>
          ${versions().length > 1 ? `<div class="dm-seg"><span>Running</span>${versions().map(([id, label]) => `<button type="button" data-version="${id}" aria-pressed="${id === v}">${esc(label)}</button>`).join("")}</div>` : ""}
        </div>
        <div class="dm-browser">
          <form class="dm-url"><span class="dm-lock" aria-hidden="true">🔒</span><span class="dm-host">shoply.test</span><input value="${esc(S.path)}" spellcheck="false" aria-label="Address"><button type="submit" class="btn">Go</button></form>
          <nav class="dm-snav"><button type="button" class="dm-logo" data-goto="/"><span class="dm-mark">☕</span>Shoply<small>coffee &amp; tea</small></button>
            <div class="dm-links">${nav.map(([path, label]) => `<button type="button" data-goto="${esc(path)}" class="${S.path === path ? "on" : ""}">${label}</button>`).join("")}</div>
            <span class="dm-me">${me ? `<span class="dm-av">${esc(cap(me)[0])}</span>${esc(cap(me))}` : "Not signed in"}</span></nav>
          ${S.toast ? `<div class="dm-toast">${esc(S.toast)}</div>` : ""}
          <div class="dm-spage ${S.loading ? "loading" : ""}">${S.loading && !S.resp ? `<p class="muted"><span class="pulse"></span> Starting the shop with this code…</p>` : page(S.resp)}</div>
        </div>
        <div class="dm-try"><span>Try</span>${tries.map(([as, path, label]) => `<button type="button" class="linkish" data-goto="${esc(path)}" data-goas="${as}">${esc(label)}</button>`).join("")}</div>`;
      $(".dm-url", el).addEventListener("submit", (e) => { e.preventDefault(); const val = $(".dm-url input", el).value.trim(); S.toast = null; S.path = val.startsWith("/") ? val : "/" + val; load(); });
      $$("[data-buy]", el).forEach((b) => b.addEventListener("click", () => {
        const p = PRODUCTS.find((x) => x.id === b.dataset.buy);
        S.toast = null;
        load("POST", { id: p.id, item: p.name, total: p.price, shipping_address: ADDRESS[me] || ADDRESS.alice });
      }));
      const tf = $("#shop-track", el);
      if (tf) tf.addEventListener("submit", (e) => { e.preventDefault(); const n = +new FormData(tf).get("n"); if (n) { S.path = `/orders/${n}`; load(); } });
      const sf = $("#shop-search", el);
      if (sf) sf.addEventListener("submit", (e) => { e.preventDefault(); S.path = `/users/search?name=${encodeURIComponent(new FormData(sf).get("q") || "")}`; load(); });
    }

    function orderRow(o, who) {
      const items = itemsOf(o);
      return `<button type="button" class="dm-orow" data-goto="/orders/${esc(o.id)}">
        <span class="dm-thumbs">${items.slice(0, 3).map((x) => `<span style="background:${x.bg}">${art(x, 34)}</span>`).join("")}</span>
        <span class="dm-otext"><b>Order #${esc(o.id)}</b><small>${esc(items.map((x) => x.name).join(", "))}${who ? ` · ${esc(cap(PEOPLE[o.user_id] || o.user_id))}` : ""}</small></span>
        <span class="dm-pill ${esc(o.status)}">${esc(o.status)}</span><b class="dm-amt">${money(o.total)}</b></button>`;
    }

    function track(o, leak) {
      const steps = ["pending", "shipped", "delivered"], at = Math.max(0, steps.indexOf(o.status));
      const items = itemsOf(o);
      return `${leak}<div class="dm-track">
          <div class="dm-track-head"><div><small>Order #${esc(o.id)}</small><h3>${o.status === "delivered" ? "Delivered" : o.status === "shipped" ? "On its way" : "Being packed"}</h3></div><b>${money(o.total)}</b></div>
          <ol class="dm-steps-line">${["Order placed", "Shipped", "Delivered"].map((l, i) => `<li class="${i <= at ? "done" : ""}"><span></span>${l}</li>`).join("")}</ol>
          <div class="dm-track-body">
            <ul class="dm-items">${items.map((x) => `<li><span style="background:${x.bg}">${art(x, 44)}</span><div><b>${esc(x.name)}</b><small>${esc(x.kind)}</small></div></li>`).join("")}</ul>
            <dl class="${leak ? "dm-leaked" : ""}"><dt>Customer</dt><dd>${esc(cap(PEOPLE[o.user_id] || o.user_id))}</dd><dt>Ships to</dt><dd class="dm-addr">${esc(o.shipping_address)}</dd></dl>
          </div></div>`;
    }

    function page(r) {
      if (!r) return "";
      const path = r.path || "", me = S.as, v = current();
      const blocked = (icon, title, text) => `<div class="dm-blocked"><div class="big">${icon}</div><h3>${title}</h3><p>${text}</p><code>HTTP ${esc(r.status || "–")}</code></div>`;
      if (r.client && path === "/") {
        return `<section class="dm-hero"><div><h2>Fresh coffee &amp; tea,<br>roasted in Singapore.</h2><p>Beans and leaves from small farms, packed the day they ship.</p></div><div class="dm-hero-art">${art(PRODUCTS[0], 92)}${art(PRODUCTS[2], 80)}${art(PRODUCTS[4], 86)}</div></section>
          <div class="dm-prods">${PRODUCTS.map((x) => `<article class="dm-prod"><div class="dm-art" style="background:${x.bg}">${art(x, 96)}</div>
            <div class="dm-pinfo"><b>${esc(x.name)}</b><small>${esc(x.kind)}</small></div>
            <div class="dm-pbuy"><span>${money(x.price)}</span><button type="button" class="btn primary" data-buy="${x.id}" ${me ? "" : 'disabled title="Sign in to buy"'}>Add to order</button></div></article>`).join("")}</div>`;
      }
      if (r.client && path === "/track") {
        return `<section class="dm-trackform"><h3>Track an order</h3><p>Enter your order number to see where it is.</p>
          <form id="shop-track"><input name="n" type="number" min="1" placeholder="Order number, e.g. 1" required><button type="submit" class="btn primary">Track</button></form>
          <p class="dm-hint">This page calls <code>GET /orders/&lt;number&gt;</code>.</p></section>`;
      }
      if (r.client && path === "/staff") {
        return `<section class="dm-trackform"><h3>Find a customer</h3><p>Support staff search customers by name.</p>
          <form id="shop-search"><input name="q" placeholder="Name, e.g. al" autocomplete="off"><button type="submit" class="btn primary">Search</button></form>
          <p class="dm-hint">This page calls <code>GET /users/search?name=…</code>.</p></section>`;
      }
      if (!r.status) return blocked("💥", "The shop does not start with this code", esc(r.crash || r.error || ""));
      if (r.status === 401) return blocked("🔑", "Please sign in", "This page is only for signed-in customers.");
      if (r.status === 403) return blocked("🚫", "You can't see this page", /^\/orders\/\d+$/.test(path) ? "This order belongs to another customer." : "It's for staff only.");
      if (r.status === 404) {
        const what = /^\/orders\/\d+$/.test(path) ? "order tracking" : /^\/users\/search/.test(path) ? "customer search" : "";
        return blocked("🔍", "Page not found", what ? `There's no ${what} in this version of the shop yet.` : "Nothing lives at this address.");
      }
      if (r.status >= 500) return blocked("💥", "The shop crashed", esc(r.crash || "Internal server error"));
      const d = r.data;
      if (path === "/orders/mine" && Array.isArray(d)) {
        return `<h3 class="dm-h">My orders</h3>${d.length ? `<div class="dm-olist">${d.map((o) => orderRow(o, false)).join("")}</div>` : `<p class="muted">No orders yet. <button type="button" class="linkish" data-goto="/">Visit the shop</button></p>`}`;
      }
      if (path === "/orders/all" && Array.isArray(d)) return `<h3 class="dm-h">Every customer's orders <span class="dm-staff">staff</span></h3><div class="dm-olist">${d.map((o) => orderRow(o, true)).join("")}</div>`;
      if (/^\/orders\/\d+$/.test(path) && d && d.shipping_address !== undefined) {
        const theirs = !me || IDS[me] !== d.user_id;
        const leak = theirs && me !== "maria" ? `<div class="dm-leak"><b>⚠ This isn't ${esc(cap(me) || "your")}'s order.</b> You're signed in as <b>${esc(cap(me) || "nobody")}</b>, but this is <b>${esc(cap(PEOPLE[d.user_id]))}</b>'s order, with their home address.</div>` : "";
        return track(d, leak);
      }
      if (/^\/users\/search/.test(path) && Array.isArray(d)) {
        const q = decodeURIComponent((path.split("name=")[1] || "").replace(/\+/g, " "));
        const leaked = d.some((u) => Object.values(u).some(leakedValue));
        return `<h3 class="dm-h">Customers matching “${esc(q)}”</h3>
          ${leaked ? `<div class="dm-leak"><b>⚠ A name search just returned every user's email and password hash.</b> The search text closed the SQL string and asked the database for them.</div>` : ""}
          ${d.length ? `<table class="dm-stable"><tr>${Object.keys(d[0]).map((k) => `<th>${esc(leaked ? { username: "email (leaked)", role: "password hash (leaked)" }[k] || k : k)}</th>`).join("")}</tr>
            ${d.map((u) => `<tr>${Object.values(u).map((x) => `<td class="${leakedValue(x) ? "dm-leakcell" : ""}">${esc(x)}</td>`).join("")}</tr>`).join("")}</table>` : `<p class="muted">No customers match.</p>`}`;
      }
      if (/^\/users\/\d+$/.test(path) && d && d.username) {
        return `<div class="dm-acct"><span class="dm-av big">${esc(cap(d.username)[0])}</span><div><h3>${esc(cap(d.username))}</h3><p>${esc(d.email || "")}</p><span class="dm-pill">${esc(d.role)}</span></div></div>`;
      }
      return `<pre class="dm-json">${esc(JSON.stringify(d, null, 2))}</pre>`;
    }

    return {
      // Show the shop for the code as it is now: reload the page when the version or the code changed.
      draw() { if (keyNow() !== S.key && !S.loading) load(); else draw(); },
      reload() { S.key = ""; load(); },
    };
  };
})();
