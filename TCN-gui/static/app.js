"use strict";

const $ = (id) => document.getElementById(id);
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const fmt = (v, d = 3) => (v === null || v === undefined || Number.isNaN(v)) ? "–"
  : Math.abs(v) >= 1000 ? v.toLocaleString("sk-SK", { maximumFractionDigits: 0 })
  : Number(v).toLocaleString("sk-SK", { maximumSignificantDigits: d });
const toDate = (t) => new Date(t * 1000);
let report = null;

function theme() {
  return {
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    font: { color: css("--ink"), family: "system-ui, sans-serif", size: 12 },
    margin: { l: 64, r: 20, t: 10, b: 40 },
    xaxis: { gridcolor: css("--grid"), zerolinecolor: css("--grid"), linecolor: css("--line") },
    yaxis: { gridcolor: css("--grid"), zerolinecolor: css("--grid"), linecolor: css("--line") },
    legend: { orientation: "h", y: -0.2 },
    hoverlabel: { bgcolor: css("--panel"), bordercolor: css("--line"), font: { color: css("--ink") } },
  };
}
const config = { responsive: true, displaylogo: false, modeBarButtonsToRemove: ["lasso2d", "select2d"] };
const heatScale = [[0, "#0b1f3a"], [0.25, "#1f4e8c"], [0.5, "#2f9e8f"], [0.75, "#e6b422"], [1, "#e8453c"]];

function plot(id, traces, layout = {}) {
  if (!window.Plotly) {
    $(id).textContent = "Knižnica Plotly sa nenačítala (bez internetu?). Dáta sú v odpovedi /api/analyze.";
    return;
  }
  const base = theme();
  const merged = { ...base, ...layout,
    xaxis: { ...base.xaxis, ...(layout.xaxis || {}) }, yaxis: { ...base.yaxis, ...(layout.yaxis || {}) } };
  Plotly.react(id, traces, merged, config);
}

function spans(t, flags) {
  const out = [];
  let start = null;
  flags.forEach((f, i) => {
    if (f && start === null) start = i;
    if ((!f || i === flags.length - 1) && start !== null) {
      out.push([t[start], t[f ? i : i - 1]]);
      start = null;
    }
  });
  return out;
}

async function discover() {
  try {
    const data = await (await fetch("/api/discover")).json();
    $("bundles").innerHTML = data.bundles.map((b) => `<option value="${escapeHtml(b)}">`).join("");
    $("inputs").innerHTML = data.inputs.map((p) => `<option value="${escapeHtml(p)}">`).join("");
    const saved = JSON.parse(localStorage.getItem("tcn-gui") || "{}");
    $("bundle").value = saved.bundle || data.bundles[0] || "";
    $("input").value = saved.input || "";
    $("profile").value = saved.profile || "";
  } catch (e) { /* page still works with typed paths */ }
}

async function run() {
  const body = { bundle: $("bundle").value.trim(), input: $("input").value.trim(),
                 profile: $("profile").value.trim(), allow_diagnostic: $("diagnostic").checked };
  if (!body.bundle || !body.input) { status("Vyber model aj snímky.", true); return; }
  try { localStorage.setItem("tcn-gui", JSON.stringify(body)); } catch (e) { /* private mode */ }
  $("run").disabled = true;
  status("Prehrávam session cez model… (hodina snímok trvá rádovo desiatky sekúnd)");
  const started = performance.now();
  try {
    const response = await fetch("/api/analyze", { method: "POST", body: JSON.stringify(body),
                                                    headers: { "Content-Type": "application/json" } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || response.statusText);
    report = data;
    status(`Hotovo za ${((performance.now() - started) / 1000).toFixed(1)} s · ${data.input.kind}: ${data.input.path}`);
    render();
  } catch (e) {
    status(String(e.message || e), true);
  } finally {
    $("run").disabled = false;
  }
}

function status(text, error = false) {
  $("status").textContent = text;
  $("status").classList.toggle("error", error);
}

function render() {
  const r = report;
  $("verdict").classList.remove("hidden");
  $("tabs").classList.remove("hidden");
  $("verdict").dataset.level = r.verdict.level;
  $("verdict-label").textContent = r.verdict.label;
  $("verdict-detail").textContent = r.verdict.detail;
  const s = r.summary;
  const stats = [
    ["Trvanie", `${fmt(s.duration_s / 60, 3)} min`], ["Snímok", fmt(s.rows)],
    ["Skórovaných okien", fmt(s.scored)], ["Nad prahom", fmt(s.above_threshold)],
    ["Alarmy modelu", fmt(s.model_alarm_events)], ["Nálezy integrity", fmt(s.integrity_rows)],
    ["Max. skóre / prah", s.score_max === null ? "–" : `${fmt(s.score_max / r.threshold, 3)}×`],
    ["Pravidlo", `${r.k} z ${r.n} nad ${fmt(r.threshold, 4)}`],
  ];
  $("stats").innerHTML = stats.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("");
  const c = r.input.context || {};
  const parts = [c.session_id, c.role && `rola ${c.role}`, c.scenario && `scenár ${c.scenario}`,
                 c.events && `${c.events.length} prevádzkových udalostí`].filter(Boolean);
  $("context").textContent = (parts.length ? parts.join(" · ") + " · " : "") + `model ${r.model.name}`;
  renderSession();
  renderModel();
  selectTab(document.querySelector(".tabs [aria-selected=true]").dataset.tab);
}

function renderSession() {
  const r = report, S = r.series, t = S.t.map(toDate);
  const shapes = [], annotations = [];
  for (const [a, b] of spans(S.t, S.model_alarm)) {
    shapes.push({ type: "rect", xref: "x", yref: "paper", x0: toDate(a), x1: toDate(b + 2.5), y0: 0, y1: 1,
                  fillcolor: css("--bad"), opacity: 0.16, line: { width: 0 } });
  }
  for (const e of (r.input.context.events || [])) {
    if (!e.start || !e.stop) continue;
    shapes.push({ type: "rect", xref: "x", yref: "paper", x0: toDate(e.start), x1: toDate(e.stop), y0: 0, y1: 1,
                  fillcolor: css("--event"), opacity: e.executed ? 0.14 : 0.05, line: { width: 0 } });
    annotations.push({ x: toDate(e.start), y: 1, xref: "x", yref: "paper", yanchor: "bottom", xanchor: "left",
                       text: e.type + (e.executed ? "" : " (nevykonaná)"), showarrow: false,
                       font: { size: 10, color: css("--event") } });
  }
  const integrityT = t.filter((_, i) => S.integrity[i].length);
  const scoreMax = Math.max(r.threshold, ...S.score.filter((v) => v !== null));
  plot("chart-score", [
    { x: t, y: S.score, type: "scattergl", mode: "lines", name: "skóre", line: { color: css("--accent"), width: 1.6 },
      hovertemplate: "%{x|%H:%M:%S}<br>skóre %{y:.4g}<extra></extra>" },
    { x: [t[0], t[t.length - 1]], y: [r.threshold, r.threshold], mode: "lines", name: "prah",
      line: { color: css("--bad"), dash: "dash", width: 1.4 }, hoverinfo: "skip" },
    { x: integrityT, y: integrityT.map(() => scoreMax * 1.05), mode: "markers", name: "nález integrity",
      marker: { symbol: "x", size: 10, color: css("--bad") },
      text: S.integrity.filter((f) => f.length).map((f) => f.join(", ")), hovertemplate: "%{text}<extra></extra>" },
  ], { shapes, annotations, yaxis: { title: "skóre", type: $("logscale").checked ? "log" : "linear" },
       margin: { l: 64, r: 20, t: 24, b: 40 } });

  const lg = $("logscale").checked;
  const L = (v) => (v === null || v === undefined ? null : lg ? Math.log10(Math.max(v, 1e-6)) : v);
  const B = r.bins, labels = B.gpa_mib.map((m) => `${fmt(m, 6)} MiB`);
  const z = B.ids.map((_, b) => S.score.map((_, i) => (B.errors[i] ? L(B.errors[i][b]) : null)));
  plot("chart-bins", [{ x: t, y: labels, z, type: "heatmap", colorscale: heatScale, zsmooth: false,
    colorbar: { title: { text: lg ? "log10 chyby" : "chyba", side: "right" }, thickness: 12 },
    hovertemplate: "%{x|%H:%M:%S}<br>bin %{y}<br>" + (lg ? "log10 chyby" : "chyba") + " %{z:.4g}<extra></extra>" }],
    { yaxis: { title: "GPA", type: "category", autorange: "reversed", showticklabels: B.ids.length <= 64 },
      margin: { l: 86, r: 20, t: 10, b: 40 } });
  const H = r.input_heat;
  plot("chart-input", [{ x: H.t.map(toDate), y: labels, z: B.ids.map((_, b) => H.values.map((row) => row[b])),
    type: "heatmap", colorscale: "Greys", reversescale: css("--bg").startsWith("#0"), zmin: 0, zmax: 1,
    colorbar: { title: { text: "zmenené", side: "right" }, thickness: 12 },
    hovertemplate: "%{x|%H:%M:%S}<br>bin %{y}<br>changed_ratio %{z:.3f}<extra></extra>" }],
    { yaxis: { type: "category", autorange: "reversed", showticklabels: false }, margin: { l: 86, r: 20, t: 10, b: 40 } });

  plot("chart-parts", [
    { x: t, y: S.global_part, stackgroup: "s", name: "0,5 · globálne príznaky", line: { width: 0 }, fillcolor: css("--accent") },
    { x: t, y: S.bin_part, stackgroup: "s", name: "0,5 · najhorší bin", line: { width: 0 }, fillcolor: css("--warn") },
    { x: [t[0], t[t.length - 1]], y: [r.threshold, r.threshold], mode: "lines", name: "prah",
      line: { color: css("--bad"), dash: "dash", width: 1.2 } },
  ], { yaxis: { title: "skóre" } });

  const top = B.top_by_mean.filter((b) => B.mean_error[b] !== null);
  plot("chart-topbins", [
    { y: top.map((b) => labels[b]), x: top.map((b) => B.mean_error[b]), type: "bar", orientation: "h",
      name: "priemerná chyba", marker: { color: css("--warn") } },
    { y: top.map((b) => labels[b]), x: top.map((b) => B.top_counts[b] || 0), type: "bar", orientation: "h",
      name: "okien ako najhorší", xaxis: "x2", marker: { color: css("--accent") }, opacity: 0.55 },
  ], { yaxis: { type: "category", autorange: "reversed" }, barmode: "group", margin: { l: 100, r: 20, t: 30, b: 40 },
       xaxis: { title: "chyba" }, xaxis2: { overlaying: "x", side: "top", title: "okná", showgrid: false } });

  const F = r.features;
  plot("chart-features", [{ x: t, y: F.names,
    z: F.names.map((_, f) => F.errors.map((row) => (row ? L(0.5 * row[f] / F.names.length) : null))),
    type: "heatmap", colorscale: heatScale, colorbar: { title: { text: lg ? "log10 príspevku" : "príspevok", side: "right" }, thickness: 12 },
    hovertemplate: "%{x|%H:%M:%S}<br>%{y}<br>" + (lg ? "log10 príspevku" : "príspevok") + " %{z:.4g}<extra></extra>" }],
    { yaxis: { type: "category", autorange: "reversed" }, margin: { l: 150, r: 20, t: 10, b: 40 } });

  const palette = [css("--accent"), css("--warn"), css("--ok"), css("--event"), css("--bad"), css("--muted")];
  plot("chart-activity", Object.entries(S.activity).map(([name, values], i) => ({
    x: t, y: values, stackgroup: "a", name, line: { width: 0 }, fillcolor: palette[i % palette.length] })),
    { yaxis: { title: "pravdepodobnosť", range: [0, 1] } });

  plot("chart-hist", [
    { x: S.score.filter((v) => v !== null), type: "histogram", nbinsx: 60, name: "okná", marker: { color: css("--accent") } },
  ], { shapes: [{ type: "line", x0: r.threshold, x1: r.threshold, yref: "paper", y0: 0, y1: 1,
                  line: { color: css("--bad"), dash: "dash" } }],
       xaxis: { title: "skóre" }, yaxis: { title: "počet okien" }, bargap: 0.05 });
}

function renderModel() {
  const m = report.model, cal = m.calibration || {};
  $("model-title").textContent = `Model ${m.name}` + (m.diagnostic ? " (diagnostický)" : "");
  const cards = [
    ["Vytvorený", m.created_utc ? new Date(m.created_utc).toLocaleString("sk-SK") : "–"],
    ["Okno", `${m.feature_contract.window_rows} snímok`], ["Biny pamäte", fmt(m.feature_contract.bins)],
    ["Prah", fmt(cal.threshold, 5)], ["Pravidlo alarmu", `${cal.k} z ${cal.n}`],
    ["Návrhová miera FP", cal.fpr_design !== undefined ? fmt(cal.fpr_design, 3) : "–"],
    ["Kalibračných skóre", fmt(cal.n_scores)],
    ["Epocha prediktora", `${m.selected_predictor_epoch} / ${m.epochs}`],
    ["Epocha klasifikátora", `${m.selected_classifier_epoch} / ${m.epochs}`],
    ["Normalizačných riadkov", fmt(m.normalization_rows)],
    ["Triedy záťaže", (m.classes || []).join(", ")],
    ["Architektúra", m.architecture ? `${m.architecture.blocks} blokov · ${m.architecture.channels} kanálov · k=${m.architecture.kernel}` : "–"],
  ];
  $("model-cards").innerHTML = cards.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("");
  const h = m.history || [], ep = h.map((x) => x.epoch);
  const vline = (e) => (e ? [{ type: "line", x0: e, x1: e, yref: "paper", y0: 0, y1: 1, line: { color: css("--ok"), dash: "dot" } }] : []);
  plot("chart-loss-pred", [
    { x: ep, y: h.map((x) => x.train_prediction_loss), name: "train", mode: "lines+markers", line: { color: css("--accent") } },
    { x: ep, y: h.map((x) => x.dev_prediction_loss), name: "dev", mode: "lines+markers", line: { color: css("--warn") } },
  ], { shapes: vline(m.selected_predictor_epoch), xaxis: { title: "epocha", dtick: 1 }, yaxis: { title: "strata" } });
  plot("chart-loss-class", [
    { x: ep, y: h.map((x) => x.train_classification_loss), name: "train", mode: "lines+markers", line: { color: css("--accent") } },
    { x: ep, y: h.map((x) => x.dev_classification_loss), name: "dev", mode: "lines+markers", line: { color: css("--warn") } },
  ], { shapes: vline(m.selected_classifier_epoch), xaxis: { title: "epocha", dtick: 1 }, yaxis: { title: "strata" } });
  const w = m.windows || {}, roles = Object.keys(w);
  plot("chart-roles", [
    { x: roles, y: roles.map((k) => w[k]), type: "bar", name: "okná", marker: { color: css("--accent") } },
    { x: roles, y: roles.map((k) => (m.corpus_sessions_by_role || {})[k] || 0), type: "bar", name: "session",
      yaxis: "y2", marker: { color: css("--event") } },
  ], { barmode: "group", yaxis: { title: "okná" }, yaxis2: { overlaying: "y", side: "right", title: "session", showgrid: false } });
  const env = { ...(m.environment || {}), score_formula: m.score_formula, loss_formula: m.loss_formula,
                classification_task: m.classification_task, path: m.path };
  $("model-env").innerHTML = Object.entries(env).filter(([, v]) => v !== undefined)
    .map(([k, v]) => `<tr><td>${k}</td><td>${escapeHtml(typeof v === "object" ? JSON.stringify(v) : String(v))}</td></tr>`).join("");
  $("model-limits").innerHTML = (m.limitations || []).map((l) => `<li>${escapeHtml(l)}</li>`).join("");
}

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

function selectTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  $("tab-session").classList.toggle("hidden", name !== "session");
  $("tab-model").classList.toggle("hidden", name !== "model");
  if (window.Plotly) document.querySelectorAll(`#tab-${name} .chart`).forEach((el) => Plotly.Plots.resize(el));
}

$("run").addEventListener("click", run);
$("logscale").addEventListener("change", () => report && renderSession());
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => report && render());
window.tcnRender = () => report && render();
discover();
