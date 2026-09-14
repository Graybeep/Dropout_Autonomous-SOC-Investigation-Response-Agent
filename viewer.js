// Extracted from viewer.html so the Content-Security-Policy can drop
// script-src 'unsafe-inline'. An injected <script> in trace prose now
// cannot execute: only same-origin script files are allowed to run.
// Loads after vendor/motion.js and at the end of <body>, so ordering and
// DOM availability are unchanged.
const SCENARIOS = [
  ["1","Scenario 1 - False alarm, patched host"],
  ["2","Scenario 2 - True positive, unpatched host"],
  ["3","Scenario 3 - Delayed evidence, re-hypothesise"],
  ["4","Scenario 4 - Human override"],
  ["5","Scenario 5 - Multi-alert correlation"],
  ["6","Scenario 6 - Tool failure, degraded recovery"],
  ["7","Scenario 7 - Configuration prevents exploitation"],
];

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const pill = (t, k) => `<span class="pill p-${k}">${esc(t)}</span>`;

// The model writes light markdown in its prose (**bold**, `code`). Render just
// those two, always AFTER escaping so nothing user-supplied becomes markup.
const md = s => esc(s)
  .replace(/^\s*#{1,6}\s+(.+)$/gm, '<span class="mdh">$1</span>')
  .replace(/^\s*&gt;\s+/gm, "")
  .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
  .replace(/`([^`\n]+)`/g, "<code>$1</code>");

let steps = [], timer = null, shown = 0;

// Motion is optional: if the vendored file is missing the CSS transition still
// reveals every card, so the viewer degrades instead of breaking.
const M = window.Motion || null;
const STILL = matchMedia("(prefers-reduced-motion: reduce)").matches;
const canAnimate = () => !!(M && M.animate) && !STILL;

// "Animate 1-2 key elements per view maximum" - so exactly two things move:
// the card being revealed, and a reconsideration fork or guard refusal when
// one appears. Nothing else.
function enter(el, i = 0) {
  if (!canAnimate()) return;
  // Deliberately does NOT animate opacity. The `.on` class already fades the
  // card in via CSS; if Motion also drove opacity from 0 and failed to run or
  // complete - a stalled rAF, a missing vendor file, a headless renderer - the
  // card would sit invisible with the class set. Motion only adds MOVEMENT on
  // top of a reveal that already works without it.
  const fork = el.classList.contains("k-reconsider") || el.classList.contains("k-event");
  const refused = el.dataset.refused === "1";
  M.animate(el,
    fork ? { x: [-18, 0] } : { y: [10, 0] },
    { duration: fork ? 0.42 : 0.34, delay: i * 0.045,
      ease: fork ? [0.34, 1.4, 0.64, 1] : [0.22, 1, 0.36, 1] });
  const card = el.querySelector(".card");
  if (!card) return;
  if (fork) M.animate(card,
    { borderColor: ["var(--purple)", "rgba(167,139,250,.35)"] }, { duration: .9 });
  if (refused) M.animate(card,
    { boxShadow: ["0 0 0 0 rgba(220,38,38,0)", "0 0 0 3px rgba(220,38,38,.38)",
                  "0 0 0 0 rgba(220,38,38,0)"] }, { duration: 1.1 });
}

// Sidebar nav replaces the old <select>. Badges are filled in lazily after
// the first trace renders (fillBadges), so a slow prefetch can never delay
// the page the demo actually opens on.
const SHORT = {
  "1":"False alarm, patched", "2":"True positive, unpatched",
  "3":"Delayed evidence", "4":"Human override",
  "5":"Multi-alert correlation", "6":"Tool failure recovery",
  "7":"Configuration prevents"
};
$("nav").innerHTML = SCENARIOS.map(([k]) =>
  `<a href="#${k}" data-k="${k}"><span class="n">${k}</span>
   <span class="t">${esc(SHORT[k] || "Scenario " + k)}</span>
   <span class="b" data-badge="${k}"></span></a>`).join("");

function setActive(k){
  $("nav").querySelectorAll("a").forEach(a =>
    a.classList.toggle("active", a.dataset.k === k));
}

const BADGE_TEXT = {SUCCEEDED:"SUCC", FAILED:"FAIL", INCONCLUSIVE:"INC"};
async function fillBadges(){
  for (const [k] of SCENARIOS){
    try {
      const r = await fetch(`traces/scenario_${k}.json`);
      if (!r.ok) continue;
      const d = await r.json();
      const c = (d.cases || [])[0];
      const o = c?.conclusions?.[c.conclusions.length - 1]?.outcome;
      const el = $("nav").querySelector(`[data-badge="${k}"]`);
      if (BADGE_TEXT[o] && el){
        el.textContent = BADGE_TEXT[o];
        el.style.color = `var(--${outcomeKind(o)})`;
        el.style.borderColor = `var(--${outcomeKind(o)})`;
      }
    } catch (e) { /* a missing trace just leaves the badge blank */ }
  }
}

// SUCCEEDED means the ATTACK succeeded, so it is the bad news and FAILED is
// the good news. Everything that colours an outcome derives it from here -
// the sidebar badge originally duplicated this mapping and inverted it.
function outcomeKind(o){
  return o === "SUCCEEDED" ? "bad" : o === "FAILED" ? "ok"
       : o === "INCONCLUSIVE" ? "warn" : "dim";
}
function outcomePill(o){ return pill(o, outcomeKind(o)); }

function argsOf(a){
  if (!a) return "";
  // submit_assessment's full payload is rendered properly by the scoring and
  // conclusion steps; inline it would drown the timeline.
  return Object.entries(a).filter(([k]) => k !== "reason").map(([k,v]) => {
    if (k === "factors" && Array.isArray(v))
      return `factors=[${v.map(f => f && f.factor).join(", ")}]`;
    let t = JSON.stringify(v);
    if (t && t.length > 80) t = t.slice(0, 79) + '…"';
    return `${k}=${t}`;
  }).join(", ");
}

function render(s){
  const k = s.kind;
  const tag = s.case_id ? `<span class="case-tag">${esc(s.case_id)}</span>` : "";

  if (k === "state_change")
    return `<div class="name">${esc(s.state)}</div>`+
           (s.note ? `<div class="note">${esc(s.note)}</div>` : "");

  if (k === "scenario_meta") return null;

  if (k === "thought" || k === "sufficiency")
    return `<div class="lbl">${k === "sufficiency" ? "Sufficiency assessment" : "Reasoning"}${tag}</div>
            <div class="txt">${md(s.text)}</div>`;

  if (k === "tool_call") {
    // submit_assessment carries the full hypothesis, sufficiency and
    // disconfirmation text; all three are rendered properly by the conclusion
    // card a few steps later, so show only the factors it declared. It also
    // has no `reason` parameter by design, so suppress the Why line.
    const args = s.tool === "submit_assessment"
      ? `factors=[${(s.args?.factors || []).map(f => f && f.factor).join(", ")}]`
      : argsOf(s.args);
    const why = (s.reason && s.reason !== "(no stated reason)")
      ? `<div class="reason"><b>Why:</b> ${md(s.reason)}</div>` : "";
    return `<div class="lbl">Tool call${s.attempt > 1 ? ` &middot; attempt ${s.attempt}` : ""}${tag}</div>
      <div class="mono sig">${esc(s.tool)}(${esc(args)})</div>${why}`;
  }

  if (k === "tool_result"){
    const st = s.status || "ok";
    const p = st === "ok" ? "ok" : st === "no_data" ? "warn"
            : st === "rejected" ? "bad" : "dim";
    // A refusal's WHOLE content is its `problems` list - collapsing that behind
    // "inspect payload" hid the one artefact the trace exists to show. Surface
    // it inline; the raw payload stays available underneath.
    const probs = (s.result && s.result.problems) || [];
    const refusal = probs.length
      ? `<div class="refusal">${probs.map(x =>
          `<div class="refusal-item">${md(x)}</div>`).join("")}
         ${s.result.remaining_attempts != null
            ? `<div class="refusal-meta">attempt ${esc(s.result.attempt)} &middot;
               ${esc(s.result.remaining_attempts)} remaining</div>` : ""}</div>`
      : "";
    return `<div class="lbl">Result ${pill(st, p)}${tag}</div>${refusal}
      <details><summary>inspect payload</summary>
      <pre>${esc(JSON.stringify(s.result, null, 2))}</pre></details>`;
  }

  if (k === "tool_failure"){
    const r = s.result || {};
    return `<div class="lbl">Tool failure ${pill(r.status || "unavailable","bad")}${tag}</div>
      <div class="mono sig sig-fail">${esc(s.tool)}: ${esc(r.reason||"")}</div>
      <div class="reason">${esc(r.detail||"")}</div>`;
  }

  if (k === "scoring"){
    const rows = (s.applied_factors||[]).map(f =>
      `<tr><td>${esc(f.label)}</td>
       <td class="d ${f.delta>0?"pos":"neg"}">${f.delta>0?"+":""}${f.delta.toFixed(2)}</td>
       <td>${esc(f.citation)}</td></tr>`).join("")
      || `<tr><td colspan="3" class="no-factors">no factors declared</td></tr>`;
    return `<div class="lbl">Deterministic scoring${tag}</div>
      <table><tr><th>Evidence finding</th><th>&Delta;</th><th>Citation</th></tr>${rows}</table>
      <div class="reason score-line">
        base ${s.base.toFixed(2)} &rarr; raw <b>${s.raw_sum>0?"+":""}${s.raw_sum.toFixed(2)}</b>
        &rarr; score <b>${s.score.toFixed(2)}</b> &rarr; ${outcomePill(s.outcome)}
        confidence <b>${s.confidence.toFixed(2)}</b></div>
      ${s.ceiling_note ? `<div class="reason ceiling">
        <b>Ceiling:</b> ${esc(s.ceiling_note)}</div>` : ""}`;
  }

  if (k === "conclusion")
    return `<div class="lbl">Conclusion &middot; ${esc(s.label)}${tag}</div>
      <div class="concl-head">${outcomePill(s.outcome)}
        <span class="concl-meta">score ${s.score.toFixed(2)}
        &middot; confidence ${s.confidence.toFixed(2)}</span></div>
      <div class="reason"><b>Hypothesis:</b> ${md(s.hypothesis)}</div>
      ${s.sufficiency?`<div class="reason"><b>Sufficiency:</b> ${md(s.sufficiency)}</div>`:""}
      ${s.disconfirming_evidence_checked?`<div class="reason">
        <b>Disconfirming check:</b> ${md(s.disconfirming_evidence_checked)}</div>`:""}`;

  if (k === "action"){
    if (s.skipped)
      return `<div class="lbl">Action withheld ${pill("guardrail 6","warn")}${tag}</div>
              <div class="txt">${md(s.detail)}</div>`;
    if (s.decision)
      return `<div class="lbl">Human override applied${tag}</div>
        <div>Decision ${pill(s.decision, s.decision==="benign"?"ok":"bad")}
        &rarr; status <b>${esc(s.resulting_status)}</b></div>
        <div class="reason"><b>Justification:</b> ${esc(s.justification)}</div>`;
    return `<div class="lbl">Action${tag}</div>
            <div class="txt">${md(s.detail || s.action || "")}</div>`;
  }

  if (k === "verification"){
    const ok = s.matches_policy;
    return `<div class="lbl">Verification ${pill(ok?"matches policy":"MISMATCH", ok?"ok":"bad")}${tag}</div>
      <div class="reason">Re-read firewall state from disk for <b>${esc(s.ip)}</b>:
        expected blocked <b>${esc(s.expected_blocked)}</b>,
        observed <b>${esc(s.blocked_after)}</b>.</div>
      ${s.record?`<div class="reason mono rule-line">rule: ${esc(s.record.rule)}
        ${s.record.precautionary?pill("precautionary","warn"):""}</div>`:""}`;
  }

  if (k === "event")
    return `<div class="fork">${esc(s.event_kind || "event")}</div>
            <div class="txt detail-gap">${md(s.detail)}</div>`;

  if (k === "reconsider"){
    const p = s.prior_conclusion;
    return `<div class="fork">Reconsider &middot; ${esc(s.trigger)}</div>
      <div class="txt detail-gap">${md(s.detail)}</div>
      <div class="side">
        <div><div class="h">Prior conclusion</div>
          ${p?`${outcomePill(p.outcome)} <span class="prior-meta">
          confidence ${p.confidence.toFixed(2)}</span>
          <div class="reason">${esc(p.hypothesis)}</div>`:"<span style='color:var(--dim2)'>none</span>"}</div>
        <div><div class="h">After this trigger</div>
          <span class="prior-meta">re-entering HYPOTHESIZE:
          the agent gathers new evidence before re-scoring</span></div>
      </div>`;
  }

  if (k === "error")
    return `<div class="lbl">Error${tag}</div><div class="txt">${esc(s.detail)}</div>`;

  return `<div class="lbl">${esc(k)}${tag}</div>
          <pre>${esc(JSON.stringify(s, null, 2))}</pre>`;
}

function paint(){
  const tl = $("tl");
  tl.innerHTML = "";
  steps.forEach((s, i) => {
    // The control plane logs the trigger as an EVENT and reconsider()
    // logs it again on the fork card. Render it once.
    const nxt = steps[i + 1];
    if (s.kind === "event" && nxt && nxt.kind === "reconsider"
        && (nxt.detail || "") === (s.detail || "")) return;
    const html = render(s);
    if (html === null) return;
    const d = document.createElement("div");
    // s.kind reaches the class attribute, so constrain it to the character set a
    // kind can legitimately use rather than trusting whatever the file contains.
    d.className = `step k-${String(s.kind || "unknown").replace(/[^a-z0-9_-]/gi, "")}`;
    // The guard refusal is the demo's set piece - flag it so it gets the one
    // extra animation the motion budget allows.
    if (s.kind === "tool_result" && s.status === "rejected") d.dataset.refused = "1";
    d.innerHTML = `<div class="card">${html}</div>`;
    tl.appendChild(d);
  });
}

function reveal(n){
  const els = document.querySelectorAll(".step");
  const fresh = [];
  els.forEach((e, i) => {
    const was = e.classList.contains("on");
    const now = i < n;
    e.classList.toggle("on", now);
    if (now && !was) fresh.push(e);
  });
  // State first, animation second. enter() is an OPTIONAL enhancement, so it
  // must not be able to take the reveal loop down with it: if it threw here
  // before `shown` was updated, every tick would re-reveal the same step and
  // playback would freeze after one card, with the button still reading Pause.
  // L-4 made Motion non-load-bearing for VISIBILITY; this makes it
  // non-load-bearing for PROGRESS too.
  shown = n;
  $("count").textContent = `${Math.min(n, els.length)} / ${els.length} steps`;
  // Stagger only when several appear at once (Show all); a single step during
  // playback animates immediately so it stays in step with the 400ms cadence.
  try {
    fresh.forEach((e, i) => enter(e, fresh.length > 1 ? Math.min(i, 12) : 0));
  } catch (err) {
    console.warn("motion enhancement failed, reveal continues:", err);
  }
  if (n && n <= els.length && els[n-1]) {
    const r = els[n-1].getBoundingClientRect();
    if (r.bottom > innerHeight - 40 || r.top < 90)
      els[n-1].scrollIntoView({behavior:"smooth", block:"center"});
  }
}

function stop(){ clearInterval(timer); timer = null; $("play").textContent = "Start"; }

$("play").onclick = () => {
  const total = document.querySelectorAll(".step").length;
  if (timer) return stop();
  if (shown >= total) {
    // Restarting from the top: bring the timeline into view first, or the
    // page appears to go blank wherever the reader happens to be scrolled.
    reveal(0);
    const tl = $("tl");
    if (tl) tl.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  $("play").textContent = "Pause";
  timer = setInterval(() => {
    if (shown >= total) return stop();
    reveal(shown + 1);
  }, 400);
};
$("all").onclick = () => { stop(); reveal(document.querySelectorAll(".step").length); };
$("reset").onclick = () => { stop(); reveal(0); };

async function load(key){
  stop();
  $("tl").innerHTML = `<div class="empty">loading&hellip;</div>`;
  $("verdicts").innerHTML = "";
  let data;
  try {
    const r = await fetch(`traces/scenario_${key}.json`);
    if (!r.ok) throw new Error(r.status);
    data = await r.json();
  } catch (e) {
    // Opening viewer.html by double-clicking it gives a file:// page, and every
    // browser blocks fetch() on that origin, so no trace can ever load. That is
    // not a missing file and saying "not found" sends people looking for one.
    // Detect the cause and say the actual thing, prominently.
    const isFile = location.protocol === "file:";
    $("summary").innerHTML = isFile
      ? `<b>No trace loaded.</b> Start a local server in this folder first;
         the README has the steps in order.`
      : `<b>Could not load traces/scenario_${key}.json.</b>
         Run <code>python run_all.py</code> to generate the traces.`;
    $("tl").innerHTML = `<div class="empty">no trace loaded</div>`;
    $("count").textContent = "";
    $("stats").innerHTML = "";
    $("crumb").innerHTML = `Scenario ${esc(key)} <i>&middot; trace missing</i>`;
    return;
  }

  const meta = (data.steps || []).find(s => s.kind === "scenario_meta");
  // Expectation notes run to a paragraph on the scenarios that need one
  // (scenario 7 is a full diagnosis). Inline, that buries the summary under a
  // grey wall, so anything long collapses behind a disclosure.
  const exp = meta?.expectation;
  const notes = exp?.notes || "";
  const expHtml = !exp ? "" : (notes.length > 220
    ? `<details class="exp-wrap"><summary>Expected: ${esc(exp.outcome)}
         &middot; why this is declared</summary>
       <div class="exp-body">${esc(notes)}</div></details>`
    : `<br><span class="exp-inline">Expected: ${esc(exp.outcome)}${
         notes ? " &middot; " + esc(notes) : ""}</span>`);

  $("summary").innerHTML = `<b>${esc(data.title || "")}</b><br>${esc(data.summary || "")}
    ${expHtml}
    ${data.error ? `<br><span class="run-error">Run error: ${esc(data.error)}</span>` : ""}`;

  $("verdicts").innerHTML = (data.cases || []).map(c => {
    const last = c.conclusions?.[c.conclusions.length - 1];
    const act = (c.actions || []).map(a =>
      a.action + (a.precautionary ? " (precautionary)" : "")).join(", ") || "none";
    // Takes a CLASS, not a colour: an inline style attribute here would need
    // style-src 'unsafe-inline' for the sake of one red word.
    const row = (k, v, cls) =>
      `<div class="vr"><span class="vk">${k}</span>
       <span class="vv${cls ? " " + cls : ""}">${v}</span></div>`;
    return `<div class="verdict">
      <div class="vhd"><span class="vid mono">${esc(c.case_id)}</span>
        ${last ? outcomePill(last.outcome) : pill("no conclusion","dim")}</div>
      ${row("status", esc(c.status))}
      ${row("action", esc(act))}
      ${last ? row("confidence",
        `${Number(last.confidence).toFixed(2)} <span class="exp-inline">/ score ${
          Number(last.score).toFixed(2)}</span>`) : ""}
      ${c.degraded_sources?.length
        ? row("degraded", esc(c.degraded_sources.join(", ")), "vv-bad") : ""}
    </div>`;
  }).join("");

  steps = data.steps || [];

  // KPI row. Every figure is derived from the trace, never hardcoded.
  const calls    = steps.filter(x => x.kind === "tool_call" && x.tool !== "submit_assessment").length;
  const refusals = steps.filter(x => x.kind === "tool_result" && x.status === "rejected").length;
  const recons   = steps.filter(x => x.kind === "reconsider").length;
  const secs     = steps.length ? steps[steps.length - 1].t : 0;
  const c0       = (data.cases || [])[0];
  const concl    = c0?.conclusions?.[c0.conclusions.length - 1];
  const degraded = [...new Set((data.cases || []).flatMap(c => c.degraded_sources || []))];

  $("stats").innerHTML = [
    [`Outcome`, concl ? outcomePill(concl.outcome) : pill("none","dim"),
      (data.cases || []).length > 1 ? `${data.cases.length} cases` : (c0?.case_id || "")],
    [`Confidence`, concl ? Number(concl.confidence).toFixed(2) : "n/a",
      concl ? `score ${Number(concl.score).toFixed(2)}` : ""],
    [`Evidence calls`, calls, `across the whole investigation`],
    [`Guard refusals`, refusals,
      refusals ? "resolved before concluding" : "none on this case"],
    [`Reconsiderations`, recons, recons ? "case re-opened" : "single pass"],
    [`Wall clock`, `${secs.toFixed(1)}s`,
      degraded.length ? `degraded: ${esc(degraded.join(", "))}` : "no source failed"],
  ].map(([k, v, sub]) =>
    `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div>
     <div class="s">${sub || "&nbsp;"}</div></div>`).join("");

  $("crumb").innerHTML = `${esc(data.title || "Scenario " + key)}
    <i>&middot; scenario ${esc(key)}</i>`;
  paint();
  // Count what is actually on screen. steps.length includes the hidden
  // scenario_meta entry and duplicate event cards paint() folds into the fork,
  // so using it here put "40 STEPS" beside a top-bar counter reading "39 / 39".
  const rendered = document.querySelectorAll(".step").length;
  $("tlmeta").innerHTML = `<span class="tl-meta">${rendered} steps</span>`;
  // Show the whole trace by default. Opening on an empty timeline (with the
  // hidden steps still occupying layout) reads as a broken page; Play restarts
  // the reveal from the top for the demo.
  reveal(document.querySelectorAll(".step").length);
  scrollTo({top: 0});
}

// Deep-link support: viewer.html#3 opens scenario 3 directly, so a demo can
// jump straight to a scenario without touching the dropdown.
function fromHash() {
  const k = location.hash.replace("#", "");
  return SCENARIOS.some(([v]) => v === k) ? k : SCENARIOS[0][0];
}

// An unknown hash (#9, #abc) falls back to scenario 1, and the address bar must
// then say #1 too, or a copied link claims a scenario the page is not showing.
// replaceState rewrites the URL without reloading, without a new Back-button
// entry, and without firing hashchange, so it cannot loop.
function syncHash(k) {
  if (location.hash !== "#" + k) {
    history.replaceState(null, "", location.pathname + location.search + "#" + k);
  }
}

addEventListener("hashchange", () => {
  const k = fromHash();
  syncHash(k);          // also when k === current: on #1, typing #9 must still correct
  if (k !== current) { current = k; setActive(k); load(k); }
});
$("foot").innerHTML =
  `<b class="foot-strong">${SCENARIOS.length} scenarios</b><br>` +
  `traces replayed from disk<br>` +
  `<span class="foot-note">no model runs in this view</span>`;

let current = fromHash();
syncHash(current);
setActive(current);
load(current).then(fillBadges);
