/* Guardiantus AV — dashboard client.
   No framework, no build step: the API is small and the DOM is small.
   Every API call carries the per-run session token from the page <meta>. */

"use strict";

const TOKEN = document.querySelector('meta[name="guardiantus-token"]').content;
const VERSION = document.querySelector('meta[name="guardiantus-version"]').content;

/* ------------------------------------------------------------------ utils */

const $ = (selector, scope = document) => scope.querySelector(selector);
const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "html") node.innerHTML = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name, cls = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  if (cls) svg.setAttribute("class", cls);
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#icon-${name}`);
  svg.append(use);
  return svg;
}

function bytes(value) {
  const n = Number(value) || 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = n;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${unit === 0 ? size : size.toFixed(1)} ${units[unit]}`;
}

function number(value) {
  return new Intl.NumberFormat().format(Number(value) || 0);
}

function when(timestamp) {
  if (!timestamp) return "never";
  const date = new Date(Number(timestamp) * 1000);
  const delta = (Date.now() - date.getTime()) / 1000;
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)} min ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)} h ago`;
  if (delta < 7 * 86400) return `${Math.floor(delta / 86400)} d ago`;
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/* `when` reads backwards; a scheduled run is in the future and needs its own
   phrasing, or "next run" ends up saying "just now" for hours on end. */
function until(timestamp) {
  const delta = Number(timestamp) * 1000 - Date.now();
  if (!timestamp || Number.isNaN(delta)) return "—";
  if (delta <= 0) return "any moment now";
  if (delta < 3600_000) return `in ${Math.max(1, Math.round(delta / 60_000))} min`;
  if (delta < 86_400_000) return `in ${Math.round(delta / 3_600_000)} h`;
  return new Date(Number(timestamp) * 1000).toLocaleString(undefined, {
    weekday: "short", hour: "2-digit", minute: "2-digit",
  });
}

function clock(timestamp) {
  return new Date(Number(timestamp) * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function duration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return `${minutes}m ${total % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function baseName(path) {
  const parts = String(path).split(/[/\\]/);
  return parts[parts.length - 1] || path;
}

/* Trim a long path from the left so the filename stays visible. Doing it here
   rather than with `direction: rtl` keeps the separators in the right order. */
function shortPath(path, max = 96) {
  const text = String(path || "");
  return text.length <= max ? text : `…${text.slice(-(max - 1))}`;
}

/* -------------------------------------------------------------------- api */

async function api(path, { method = "GET", body } = {}) {
  const response = await fetch(path, {
    method,
    headers: {
      "X-Guardiantus-Token": TOKEN,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let payload = {};
  try { payload = await response.json(); } catch { /* empty body */ }
  if (!response.ok) {
    const message = payload.error || payload.detail || `${response.status} ${response.statusText}`;
    throw new Error(message);
  }
  return payload;
}

/* ------------------------------------------------------------------ toast */

function toast(title, message = "", tone = "ok") {
  const node = el("div", { class: `toast toast--${tone}` },
    el("div", { class: "toast__body" },
      el("div", { class: "toast__title", text: title }),
      message ? el("div", { class: "toast__msg", text: message }) : null,
    ),
  );
  $("#toasts").append(node);
  setTimeout(() => {
    node.classList.add("toast--leaving");
    setTimeout(() => node.remove(), 220);
  }, tone === "risk" ? 8000 : 4200);
}

function fail(error) {
  toast("Something went wrong", error.message || String(error), "risk");
}

/* ------------------------------------------------------------------ modal */

function openModal(title, bodyNodes, footNodes = []) {
  $("#modal-title").textContent = title;
  $("#modal-body").replaceChildren(...[bodyNodes].flat().filter(Boolean));
  $("#modal-foot").replaceChildren(
    ...[footNodes].flat().filter(Boolean),
    el("button", { class: "btn", onclick: closeModal, text: "Close" }),
  );
  $("#modal").hidden = false;
}

function closeModal() { $("#modal").hidden = true; }

$("#modal").addEventListener("click", (event) => {
  if (event.target === $("#modal")) closeModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeModal();
});

function confirmAction(title, message, confirmLabel, onConfirm, tone = "danger") {
  openModal(title, el("p", { text: message }), [
    el("button", {
      class: `btn btn--${tone}`,
      text: confirmLabel,
      onclick: () => { closeModal(); onConfirm(); },
    }),
  ]);
}

/* ------------------------------------------------------------------ empty */

function emptyState(message, iconName = "check") {
  return el("div", { class: "empty" }, icon(iconName), el("div", { text: message }));
}

/* Probing package managers shells out to apt/brew/winget and can take a few
   seconds, so every slow panel shows what it is waiting for. */
function loadingState(message) {
  return el("div", { class: "empty" },
    el("div", { class: "progress progress--indeterminate" }, el("div", { class: "progress__bar" })),
    el("div", { class: "mt-2", text: message }),
  );
}

/* ------------------------------------------------------------------ state */

const state = {
  view: "dashboard",
  status: null,
  config: null,
  activeScans: [],
  // Scans the user has stopped, hidden until the server stops listing them.
  stoppedScans: new Set(),
  pollTimer: null,
  programCache: null,
};

/* ---------------------------------------------------------------- routing */

function showView(name) {
  state.view = name;
  $$(".view").forEach((section) => { section.hidden = section.id !== `view-${name}`; });
  $$(".nav__item").forEach((button) => {
    if (button.dataset.view === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  const loaders = {
    dashboard: refreshDashboard,
    scan: loadScanHistory,
    protection: loadProtection,
    quarantine: loadQuarantine,
    updates: loadUpdates,
    schedule: loadSchedule,
    events: loadEvents,
    settings: loadSettings,
  };
  loaders[name]?.();
}

$("#nav").addEventListener("click", (event) => {
  const button = event.target.closest(".nav__item");
  if (button) showView(button.dataset.view);
});

document.addEventListener("click", (event) => {
  const link = event.target.closest("[data-view-link]");
  if (link) showView(link.dataset.viewLink);
});

/* ------------------------------------------------------------------ theme */

function applyTheme(theme) {
  const resolved = theme === "system"
    ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : theme;
  document.documentElement.dataset.theme = resolved;
  $("#theme-label").textContent = resolved === "dark" ? "Light" : "Dark";
  $("#theme-toggle").replaceChildren(
    icon(resolved === "dark" ? "sun" : "moon"),
    el("span", { id: "theme-label", text: resolved === "dark" ? "Light" : "Dark" }),
  );
  localStorage.setItem("guardiantus-theme", theme);
}

$("#theme-toggle").addEventListener("click", () => {
  const current = document.documentElement.dataset.theme;
  applyTheme(current === "dark" ? "light" : "dark");
});

/* -------------------------------------------------------------- dashboard */

const HERO_ICON = { protected: "shield-check", attention: "shield-alert", at_risk: "shield-alert" };

const ISSUE_ACTIONS = {
  enable_realtime: { label: "Turn on", run: () => setRealtime(true) },
  update_signatures: { label: "Update now", run: () => updateSignatures() },
  quick_scan: { label: "Quick scan", run: () => startScan("quick") },
  review_quarantine: { label: "Review", run: () => showView("quarantine") },
};

async function refreshDashboard() {
  try {
    const data = await api("/api/status");
    state.status = data;
    renderDashboard(data);
  } catch (error) {
    fail(error);
  }
}

function renderDashboard(data) {
  const { protection, stats, system } = data;

  $("#hostname").textContent = system.hostname || "this device";
  $("#brand-version").textContent = `AV ${system.version || VERSION}`;

  const hero = $("#hero");
  hero.dataset.state = protection.state;
  const heroUse = $("#hero-icon use");
  heroUse.setAttribute("href", `#icon-${HERO_ICON[protection.state] || "shield"}`);
  $("#hero-title").textContent = protection.headline;
  $("#hero-subtitle").textContent = protection.issues.length
    ? `${protection.issues.length} thing(s) worth a look`
    : "Protection is on and everything is up to date";

  $("#hero-actions").replaceChildren(
    el("button", {
      class: "btn btn--primary",
      onclick: () => startScan("quick"),
    }, icon("scan"), "Quick scan"),
    el("button", {
      class: "btn",
      onclick: () => setRealtime(!protection.realtime.running),
    }, icon("shield"), protection.realtime.running ? "Turn off protection" : "Turn on protection"),
  );

  $("#stat-realtime").textContent = protection.realtime.running ? "On" : "Off";
  $("#stat-realtime-meta").textContent = protection.realtime.running
    ? `${protection.realtime.backend} · ${number(protection.realtime.events_handled)} events`
    : "Files are not being checked as they arrive";

  $("#stat-signatures").textContent = number(protection.signatures.total);
  $("#stat-signatures-meta").textContent = `v${protection.signatures.version || "—"} · updated ${when(protection.signatures.last_update)}`;

  $("#stat-threats").textContent = number(stats.detections_7d);
  $("#stat-threats-meta").textContent = `${number(stats.total_detections)} total · ${number(stats.files_scanned_total)} files scanned`;

  $("#stat-quarantine").textContent = number(protection.quarantine.count);
  $("#stat-quarantine-meta").textContent = protection.quarantine.count
    ? bytes(protection.quarantine.bytes)
    : "Vault is empty";

  const quarantineBadge = $("#badge-quarantine");
  quarantineBadge.hidden = !protection.quarantine.count;
  quarantineBadge.textContent = protection.quarantine.count;

  const issues = $("#issues");
  if (!protection.issues.length) {
    issues.replaceChildren(emptyState("Nothing needs doing.", "shield-check"));
  } else {
    issues.replaceChildren(...protection.issues.map((issue) => {
      const action = ISSUE_ACTIONS[issue.action];
      return el("div", { class: "issue", "data-severity": issue.severity },
        el("div", { class: "issue__severity" }),
        el("div", { class: "issue__title", text: issue.title }),
        el("div", { class: "spacer" }),
        action ? el("button", { class: "btn btn--sm", text: action.label, onclick: action.run }) : null,
      );
    }));
  }

  loadRecentEvents();
  loadRecentDetections();
}

async function loadRecentEvents() {
  try {
    const { events } = await api("/api/events?limit=8");
    const target = $("#recent-events");
    target.replaceChildren(
      ...(events.length ? events.map(eventRow) : [emptyState("Nothing yet.", "list")]),
    );
  } catch { /* dashboard degrades gracefully */ }
}

function eventRow(event) {
  return el("div", { class: `event event--${event.level}` },
    el("div", { class: "event__time", text: clock(event.ts) }),
    el("div", { class: "event__cat", text: event.category }),
    el("div", { class: "event__msg", text: event.message }),
  );
}

async function loadRecentDetections() {
  try {
    const { detections } = await api("/api/detections?limit=8");
    const target = $("#recent-detections");
    if (!detections.length) {
      target.replaceChildren(emptyState("Nothing has been found on this device.", "shield-check"));
      return;
    }
    target.replaceChildren(detectionTable(detections));
  } catch { /* ignore */ }
}

function severityBadge(severity) {
  const tone = { critical: "risk", high: "risk", medium: "warn", low: "", info: "" }[severity] ?? "";
  return el("span", { class: `badge ${tone ? `badge--${tone}` : ""}`, text: severity });
}

const HANDLED_LABELS = {
  reported: "left in place",
  quarantined: "quarantined",
  restored: "put back",
  allowed: "allowed",
  none: "nothing done",
};

const HANDLED_TONES = {
  quarantined: "badge--ok",
  allowed: "badge--ok",
  restored: "badge--ok",
  reported: "badge--warn",
};

function detectionTable(detections) {
  return el("table", { class: "table" },
    el("thead", {}, el("tr", {},
      el("th", { text: "Threat" }), el("th", { text: "File" }),
      el("th", { text: "Severity" }), el("th", { text: "Handled" }), el("th", { text: "When" }),
    )),
    el("tbody", {}, ...detections.map((detection) => el("tr", {
      class: "row--clickable",
      onclick: () => showDetectionDetail(detection),
    },
      el("td", {}, el("strong", { text: detection.threat_name || "Unknown" })),
      el("td", {}, el("span", { class: "path", title: detection.path, text: shortPath(detection.path, 72) })),
      el("td", {}, severityBadge(detection.severity)),
      el("td", {}, el("span", {
        class: `badge ${HANDLED_TONES[detection.handled] || ""}`,
        title: detection.handled === "reported" ? "Click the row to quarantine or allow it" : "",
        text: HANDLED_LABELS[detection.handled] || detection.handled,
      })),
      el("td", { text: when(detection.ts) }),
    ))),
  );
}

function showDetectionDetail(detection) {
  const payload = detection.payload || {};
  const rows = [
    ["Threat", detection.threat_name || "Unknown"],
    ["Verdict", detection.verdict === "malicious" ? "Confirmed threat" : "Suspicious"],
    ["Severity", detection.severity],
    ["File", detection.path],
    ["SHA-256", detection.sha256 || "—"],
    ["Size", bytes(payload.size || 0)],
    ["Found", new Date(detection.ts * 1000).toLocaleString()],
    ["Status", HANDLED_LABELS[detection.handled] || detection.handled],
  ];

  // A suspicion is reported and left alone, which is only useful if the
  // user can then act on it. Anything already dealt with just shows detail.
  const actions = detection.handled === "reported" ? [
    el("button", {
      class: "btn btn--danger",
      text: "Quarantine",
      onclick: () => { closeModal(); actOnDetection(detection, "quarantine"); },
    }),
    el("button", {
      class: "btn",
      text: "It's safe, allow it",
      onclick: () => { closeModal(); actOnDetection(detection, "allow"); },
    }),
  ] : [];

  openModal(detection.threat_name || "Detection", [
    el("dl", { class: "kv" }, ...rows.flatMap(([key, value]) => [
      el("dt", { text: key }),
      el("dd", {}, el("span", { class: key === "File" || key === "SHA-256" ? "mono" : "", text: String(value) })),
    ])),
    ...(payload.detections || []).map((item) => el("div", { class: "detection" },
      el("div", { class: "detection__name" }, `${item.name} `,
        el("span", { class: "badge", text: item.source }),
        item.confidence === "low" ? el("span", { class: "badge badge--warn", text: "unconfirmed" }) : null),
      el("div", { class: "detection__desc", text: item.description }),
    )),
    detection.handled === "reported"
      ? el("p", { class: "field__hint mt-3" },
          "This was found by behaviour, not by a known signature, so the file was "
          + "left where it is. Allowing it means Guardiantus will not flag it again.")
      : null,
  ], actions);
}

async function actOnDetection(detection, action) {
  try {
    await api(`/api/detections/${detection.id}/${action}`, { method: "POST" });
    toast(
      action === "allow" ? "File allowed" : "Moved to quarantine",
      action === "allow" ? "It will not be flagged again" : baseName(detection.path),
      action === "allow" ? "ok" : "warn",
    );
    refreshDashboard();
    if (state.view === "quarantine") loadQuarantine();
  } catch (error) { fail(error); }
}

/* ------------------------------------------------------------------ scans */

async function startScan(type, targets = null, autoQuarantine = null) {
  try {
    const body = { type };
    if (targets) body.targets = targets;
    if (autoQuarantine !== null) body.auto_quarantine = autoQuarantine;
    const result = await api("/api/scans", { method: "POST", body });
    toast("Scan started", `${type} scan`, "ok");
    if (state.view !== "scan") showView("scan");
    pollScans();
  } catch (error) {
    fail(error);
  }
}

$$("[data-scan]").forEach((button) => {
  button.addEventListener("click", () => startScan(button.dataset.scan));
});

$("#run-custom").addEventListener("click", () => {
  const path = $("#custom-path").value.trim();
  if (!path) { toast("Enter a path first", "", "warn"); return; }
  startScan("custom", [path], $("#custom-quarantine").checked);
});

$("#custom-path").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("#run-custom").click();
});

function scanCard(progress) {
  const indeterminate = progress.total_estimate === 0 && progress.state === "running";
  // Width is set through the CSSOM rather than a style attribute: the page
  // runs under a strict Content-Security-Policy that forbids inline styles.
  const bar = el("div", { class: "progress__bar" });
  bar.style.width = `${progress.percent}%`;
  return el("div", { class: "scan-live" },
    el("div", { class: "row row--between" },
      el("div", { class: "row" },
        el("span", { class: "badge badge--solid" },
          el("span", { class: "dot dot--pulse" }),
          `${progress.scan_type} scan`),
        el("span", { class: "field__hint", text: progress.message || progress.state }),
      ),
      el("div", { class: "row" },
        progress.state === "running"
          ? el("button", { class: "btn btn--sm", text: "Pause", onclick: () => scanControl(progress.scan_id, "pause") })
          : progress.state === "paused"
            ? el("button", { class: "btn btn--sm", text: "Resume", onclick: () => scanControl(progress.scan_id, "resume") })
            : null,
        el("button", {
          class: "btn btn--sm btn--danger",
          onclick: () => cancelScan(progress.scan_id),
          title: "Stop this scan",
        }, icon("stop"), "Stop"),
      ),
    ),
    el("div", { class: `progress ${indeterminate ? "progress--indeterminate" : ""}` }, bar),
    el("div", {
      class: "scan-live__path",
      title: progress.current_path || "",
      text: progress.current_path ? shortPath(progress.current_path) : "Preparing…",
    }),
    el("div", { class: "scan-live__metrics" },
      metric(number(progress.files_scanned), "files"),
      metric(bytes(progress.bytes_scanned), "data"),
      metric(number(progress.threats_found), "threats"),
      metric(duration(progress.elapsed), "elapsed"),
      metric(`${progress.percent}%`, "complete"),
    ),
  );
}

function metric(value, label) {
  return el("div", { class: "scan-live__metric" }, el("b", { text: value }), el("span", { text: label }));
}

async function scanControl(scanId, action) {
  try {
    await api(`/api/scans/${scanId}/${action}`, { method: "POST" });
    pollScans();
  } catch (error) { fail(error); }
}

async function cancelScan(scanId) {
  // Drop the card before the round-trip. The server marks the scan stopped
  // immediately, but a poll already in flight can still be carrying the old
  // "running" snapshot, and a card that reappears after "Scan stopped" reads
  // as the stop having been ignored.
  state.stoppedScans.add(scanId);
  renderActiveScans(state.activeScans);
  try {
    await api(`/api/scans/${scanId}`, { method: "DELETE" });
    toast("Scan stopped", "", "warn");
  } catch (error) {
    state.stoppedScans.delete(scanId);
    fail(error);
  }
  pollScans();
}

function renderActiveScans(active) {
  const live = active.filter((progress) => !state.stoppedScans.has(progress.scan_id));
  // The same live card appears on the dashboard and on the scan page; each
  // slot needs its own node, so build the cards twice rather than moving one.
  $("#live-scan-slot").replaceChildren(...live.map(scanCard));
  $("#scan-live-slot").replaceChildren(...live.map(scanCard));
  return live;
}

async function pollScans() {
  try {
    const { active, history } = await api("/api/scans?limit=25");
    state.activeScans = active;
    // Once the server agrees a scan is gone, stop holding its id.
    const stillActive = new Set(active.map((progress) => progress.scan_id));
    for (const id of state.stoppedScans) {
      if (!stillActive.has(id)) state.stoppedScans.delete(id);
    }
    renderActiveScans(active);

    renderScanHistory(history);

    if (active.length) {
      clearTimeout(state.pollTimer);
      state.pollTimer = setTimeout(pollScans, 900);
    } else if (state.lastActiveCount) {
      refreshDashboard();
    }
    state.lastActiveCount = active.length;
  } catch (error) {
    // A transient failure should not stop the poll loop entirely.
    clearTimeout(state.pollTimer);
    state.pollTimer = setTimeout(pollScans, 3000);
  }
}

/* The state values are the engine's vocabulary; these are the user's. */
const SCAN_STATE_LABELS = {
  completed: "done",
  cancelled: "stopped",
  failed: "failed",
  running: "running",
  paused: "paused",
  pending: "starting",
};

function renderScanHistory(history) {
  const target = $("#scan-history");
  if (!history || !history.length) {
    target.replaceChildren(emptyState("No scans yet.", "scan"));
    return;
  }
  target.replaceChildren(el("table", { class: "table" },
    el("thead", {}, el("tr", {},
      el("th", { text: "Type" }), el("th", { text: "Started" }), el("th", { text: "Duration" }),
      el("th", { text: "Files" }), el("th", { text: "Threats" }), el("th", { text: "Result" }),
    )),
    el("tbody", {}, ...history.map((scan) => {
      const elapsed = scan.finished_at ? scan.finished_at - scan.started_at : 0;
      return el("tr", {},
        el("td", {}, el("strong", { text: scan.scan_type })),
        el("td", { text: when(scan.started_at) }),
        el("td", { text: elapsed ? duration(elapsed) : "—" }),
        el("td", { text: number(scan.files_scanned) }),
        el("td", {}, scan.threats_found
          ? el("span", { class: "badge badge--risk", text: number(scan.threats_found) })
          : el("span", { class: "badge badge--ok", text: "0" })),
        el("td", {}, el("span", { class: "badge", text: SCAN_STATE_LABELS[scan.state] || scan.state })),
      );
    })),
  ));
}

async function loadScanHistory() { pollScans(); }
$("#refresh-scans").addEventListener("click", loadScanHistory);
$("#refresh-status").addEventListener("click", refreshDashboard);

/* ------------------------------------------------------------- protection */

async function setRealtime(enabled) {
  try {
    const status = await api("/api/realtime", { method: "POST", body: { enabled } });
    toast(
      enabled ? "Real-time protection on" : "Real-time protection off",
      enabled ? `Watching ${status.watch_paths.length} folder(s) via ${status.backend}` : "",
      enabled ? "ok" : "warn",
    );
    refreshDashboard();
    if (state.view === "protection") loadProtection();
  } catch (error) { fail(error); }
}

async function loadProtection() {
  try {
    const [status, config] = await Promise.all([api("/api/realtime"), api("/api/config")]);
    state.config = config;

    $("#realtime-toggle").checked = status.running;
    $("#realtime-action").value = config.realtime.action;
    $("#realtime-desc").textContent = status.watchdog_available
      ? "Scans files the moment they are created or changed."
      : "Checking every few seconds. Install the optional 'watchdog' package to react instantly instead.";

    $("#watch-paths").value = (config.realtime.watch_paths || []).join("\n");
    $("#excluded-paths").value = (config.scanning.excluded_paths || []).join("\n");
    $("#excluded-extensions").value = (config.scanning.excluded_extensions || []).join("\n");

    const rows = [
      ["Status", status.running ? `On for ${duration(status.uptime)}` : "Off"],
      ["Watching", status.watch_paths.length ? status.watch_paths.join(", ") : "—"],
      ["Files checked", number(status.events_handled)],
      ["Threats stopped", number(status.threats_blocked)],
      ["Last file seen", status.last_event.path ? baseName(status.last_event.path) : "—"],
    ];
    $("#realtime-stats").replaceChildren(...rows.flatMap(([key, value]) => [
      el("dt", { text: key }), el("dd", { text: String(value) }),
    ]));
  } catch (error) { fail(error); }
}

$("#realtime-toggle").addEventListener("change", (event) => setRealtime(event.target.checked));

$("#realtime-action").addEventListener("change", async (event) => {
  await saveConfig({ realtime: { action: event.target.value } }, "Detection action updated");
});

$("#save-watch-paths").addEventListener("click", async () => {
  const paths = $("#watch-paths").value.split("\n").map((line) => line.trim()).filter(Boolean);
  await saveConfig({ realtime: { watch_paths: paths } }, "Watched folders saved");
  loadProtection();
});

$("#save-exclusions").addEventListener("click", async () => {
  const lines = (id) => $(id).value.split("\n").map((line) => line.trim()).filter(Boolean);
  await saveConfig({
    scanning: {
      excluded_paths: lines("#excluded-paths"),
      excluded_extensions: lines("#excluded-extensions"),
    },
  }, "Exclusions saved");
});

/* ------------------------------------------------------------- quarantine */

async function loadQuarantine() {
  try {
    // The vault only lists what is still in it. Anything restored or deleted
    // is still worth being able to look up -- "did I put that file back?"
    const history = $("#quarantine-history").checked;
    const { entries } = await api(`/api/quarantine${history ? "?all=1" : ""}`);
    const target = $("#quarantine-list");
    if (!entries.length) {
      target.replaceChildren(emptyState(
        history ? "Nothing has ever been quarantined." : "Quarantine is empty.", "lock"));
      return;
    }
    target.replaceChildren(el("table", { class: "table" },
      el("thead", {}, el("tr", {},
        el("th", { text: "Threat" }), el("th", { text: "Original location" }),
        el("th", { text: "Severity" }), el("th", { text: "Size" }),
        el("th", { text: "Quarantined" }), el("th", { text: "" }),
      )),
      el("tbody", {}, ...entries.map((entry) => el("tr", {},
        el("td", {}, el("strong", { text: entry.threat_name })),
        el("td", {}, el("span", {
          class: "path", title: entry.original_path, text: shortPath(entry.original_path, 72),
        })),
        el("td", {}, severityBadge(entry.severity)),
        el("td", { text: bytes(entry.size) }),
        el("td", { text: when(entry.quarantined_at) }),
        el("td", {}, quarantineActions(entry)),
      ))),
    ));
  } catch (error) { fail(error); }
}

/* Entries that have already been restored or deleted are history: they show
   what happened to them instead of offering to do it again. */
function quarantineActions(entry) {
  if (entry.restored || entry.deleted) {
    return el("span", { class: "badge", text: entry.restored ? "put back" : "deleted" });
  }
  return el("div", { class: "row" },
    el("button", {
      class: "btn btn--sm",
      title: "Put the file back and stop flagging it",
      onclick: () => confirmAction(
        "Put this file back?",
        `It goes back to ${entry.original_path}, and Guardiantus will not flag it again. `
        + "Only do this if you are sure it is safe.",
        "Put it back",
        () => restoreQuarantine(entry.entry_id),
      ),
    }, icon("restore"), "Restore"),
    el("button", {
      class: "btn btn--sm btn--danger",
      title: "Delete permanently",
      onclick: () => confirmAction(
        "Delete this for good?",
        "The file is overwritten and removed. This cannot be undone.",
        "Delete",
        () => deleteQuarantine(entry.entry_id),
      ),
    }, icon("trash")),
  );
}

async function restoreQuarantine(entryId) {
  try {
    const result = await api(`/api/quarantine/${entryId}/restore`, { method: "POST" });
    toast("File put back", `${result.path} — it will not be flagged again`, "warn");
    loadQuarantine(); refreshDashboard();
  } catch (error) { fail(error); }
}

async function deleteQuarantine(entryId) {
  try {
    await api(`/api/quarantine/${entryId}`, { method: "DELETE" });
    toast("Deleted permanently", "", "ok");
    loadQuarantine(); refreshDashboard();
  } catch (error) { fail(error); }
}

$("#refresh-quarantine").addEventListener("click", loadQuarantine);
$("#quarantine-history").addEventListener("change", loadQuarantine);
$("#empty-quarantine").addEventListener("click", () => confirmAction(
  "Delete everything in quarantine?",
  "Every file in there is overwritten and gone for good.",
  "Delete all",
  async () => {
    try {
      const result = await api("/api/quarantine/empty", { method: "POST" });
      toast("Quarantine emptied", `${result.deleted} file(s) deleted`, "ok");
      loadQuarantine(); refreshDashboard();
    } catch (error) { fail(error); }
  },
));

/* ---------------------------------------------------------------- updates */

async function loadUpdates() {
  $("#signature-info").replaceChildren(loadingState("Reading the definitions…"));
  $("#program-list").replaceChildren(loadingState("Checking your programs…"));
  $("#manager-list").replaceChildren(loadingState("Looking for package managers…"));
  try {
    const signatures = await api("/api/updates/signatures");
    renderSignatureInfo(signatures);
  } catch (error) { fail(error); }
  try {
    const programs = await api("/api/updates/programs");
    state.programCache = programs;
    renderPrograms(programs);
    renderManagers(programs.managers || []);
  } catch (error) { fail(error); }
}

function renderSignatureInfo(info) {
  const rows = [
    ["Definitions", number(info.total)],
    ["Version", info.version || "—"],
    ["Last checked", when(info.last_check)],
    ["Last updated", when(info.last_update)],
    ["Source", info.feed_url || "built-in set only"],
  ];
  if (info.check) rows.push(["Available", info.check.message || "—"]);
  $("#signature-info").replaceChildren(...rows.flatMap(([key, value]) => [
    el("dt", { text: key }), el("dd", { text: String(value) }),
  ]));
}

async function updateSignatures() {
  try {
    toast("Updating definitions…", "", "ok");
    const result = await api("/api/updates/signatures", { method: "POST" });
    toast("Definitions updated", result.message || "Done", result.installed ? "ok" : "warn");
    loadUpdates(); refreshDashboard();
  } catch (error) { fail(error); }
}

$("#update-signatures").addEventListener("click", updateSignatures);
$("#check-signatures").addEventListener("click", async () => {
  try {
    const info = await api("/api/updates/signatures?check=1");
    renderSignatureInfo(info);
    toast("Definitions checked", info.check?.message || "Up to date", "ok");
  } catch (error) { fail(error); }
});

function renderPrograms(report) {
  const target = $("#program-list");
  const programs = report.programs || [];
  const badge = $("#badge-updates");
  badge.hidden = !programs.length;
  badge.textContent = programs.length;

  if (!programs.length) {
    target.replaceChildren(emptyState(
      report.managers_probed?.length
        ? "Everything is up to date."
        : "No package manager was found on this system.",
      "check",
    ));
    return;
  }

  target.replaceChildren(el("table", { class: "table" },
    el("thead", {}, el("tr", {},
      el("th", { text: "Program" }), el("th", { text: "Manager" }),
      el("th", { text: "Installed" }), el("th", { text: "Available" }), el("th", { text: "" }),
    )),
    el("tbody", {}, ...programs.map((program) => el("tr", {},
      el("td", {}, el("strong", { text: program.name })),
      el("td", {}, el("span", { class: "badge", text: program.manager })),
      el("td", { class: "mono", text: program.current_version || "—" }),
      el("td", {}, el("span", { class: "badge badge--warn", text: program.available_version })),
      el("td", {}, el("button", {
        class: "btn btn--sm",
        text: "Update",
        onclick: (event) => upgradeProgram(program, event.target),
      })),
    ))),
  ));
}

async function upgradeProgram(program, button) {
  button.disabled = true;
  button.textContent = "Updating…";
  try {
    const result = await api("/api/updates/programs", {
      method: "POST",
      body: { manager: program.manager, package: program.package_id },
    });
    toast(`${program.name} updated`, result.stdout ? result.stdout.slice(-160) : "", "ok");
    checkPrograms();
  } catch (error) {
    button.disabled = false;
    button.textContent = "Update";
    fail(error);
  }
}

function managerHint(manager) {
  if (!manager.available) return "Not present on this system.";
  return manager.needs_privileges
    ? "Updates need administrator rights. Start Guardiantus as an administrator to install them."
    : "Ready to use.";
}

function renderManagers(managers) {
  const target = $("#manager-list");
  if (!managers.length) {
    target.replaceChildren(emptyState("No package manager found.", "download"));
    return;
  }
  target.replaceChildren(...managers.map((manager) => el("div", { class: "setting" },
    el("div", { class: "setting__text" },
      el("div", { class: "setting__title", text: manager.label }),
      el("div", { class: "setting__desc", text: managerHint(manager) }),
    ),
    el("div", { class: "setting__control" },
      el("span", {
        class: `badge ${manager.available ? "badge--ok" : ""}`,
        text: manager.available ? "available" : "not installed",
      }),
    ),
  )));
}

async function checkPrograms() {
  const button = $("#check-programs");
  button.disabled = true;
  $("#program-list").replaceChildren(loadingState("Checking your programs…"));
  try {
    const report = await api("/api/updates/programs?refresh=1");
    state.programCache = report;
    renderPrograms(report);
    toast(
      report.updates_available ? `${report.updates_available} update(s) available` : "Everything is up to date",
      (report.errors || []).map((e) => `${e.manager}: ${e.error}`).join(", "),
      report.updates_available ? "warn" : "ok",
    );
  } catch (error) { fail(error); }
  button.disabled = false;
}

$("#check-programs").addEventListener("click", checkPrograms);

/* --------------------------------------------------------------- schedule */

/* Cron is precise and unreadable. Offer the handful of rhythms anyone
   actually wants, and fall back to showing the raw expression when a task
   is set to something these presets do not cover. */
const SCHEDULE_PRESETS = [
  { label: "Every 6 hours", cron: "0 */6 * * *" },
  { label: "Daily", cron: "0 12 * * *" },
  { label: "Nightly", cron: "0 3 * * *" },
  { label: "Weekly", cron: "0 3 * * 0" },
];

function scheduleControl(task) {
  const known = SCHEDULE_PRESETS.some((preset) => preset.cron === task.cron);
  const select = el("select", {
    class: "select select--compact",
    onchange: (event) => saveCron(task.name, event.target.value),
  },
    ...SCHEDULE_PRESETS.map((preset) => el("option", { value: preset.cron, text: preset.label })),
    known ? null : el("option", { value: task.cron, text: `Custom (${task.cron})` }),
  );
  select.value = task.cron;
  return select;
}

function taskTitle(task) {
  return { "quick-scan": "Quick scan", "full-scan": "Full scan",
    "signature-update": "Update threat definitions",
    "program-update-check": "Check installed programs" }[task.name] || task.name;
}

async function loadSchedule() {
  try {
    const { tasks } = await api("/api/schedule");
    const target = $("#schedule-list");
    if (!tasks.length) {
      target.replaceChildren(emptyState("Nothing is scheduled.", "clock"));
      return;
    }
    target.replaceChildren(...tasks.map((task) => el("div", { class: "setting" },
      el("div", { class: "setting__text" },
        el("div", { class: "setting__title", text: taskTitle(task) }),
        el("div", { class: "field__hint" },
          task.enabled ? `runs ${until(task.next_run)}` : "off",
          task.last_run ? ` · last ran ${when(task.last_run)}` : "",
          task.last_error ? ` · failed: ${task.last_error}` : "",
        ),
      ),
      el("div", { class: "setting__control" }, el("div", { class: "row" },
        scheduleControl(task),
        el("button", { class: "btn btn--sm", text: "Run now", onclick: () => runTask(task.name) }),
        el("label", { class: "switch" },
          el("input", {
            type: "checkbox", checked: task.enabled,
            onchange: (event) => toggleTask(task.name, event.target.checked),
          }),
          el("span", { class: "switch__track" }),
        ),
      )),
    )));
  } catch (error) { fail(error); }
}

async function saveCron(name, cron) {
  try {
    await api(`/api/schedule/${name}`, { method: "POST", body: { cron } });
    toast("Schedule updated", "", "ok");
    loadSchedule();
  } catch (error) { fail(error); loadSchedule(); }
}

async function toggleTask(name, enabled) {
  try {
    await api(`/api/schedule/${name}`, { method: "POST", body: { enabled } });
    toast(`${name} ${enabled ? "enabled" : "disabled"}`, "", "ok");
    loadSchedule();
  } catch (error) { fail(error); }
}

async function runTask(name) {
  try {
    await api(`/api/schedule/${name}`, { method: "POST", body: { run_now: true } });
    toast("Task started", name, "ok");
    setTimeout(() => { loadSchedule(); pollScans(); }, 600);
  } catch (error) { fail(error); }
}

/* ----------------------------------------------------------------- events */

async function loadEvents() {
  try {
    const category = $("#event-filter").value;
    const query = new URLSearchParams({ limit: "200" });
    if (category) query.set("category", category);
    const { events } = await api(`/api/events?${query}`);
    const target = $("#event-list");
    target.replaceChildren(
      ...(events.length ? events.map(eventRow) : [emptyState("Nothing logged yet.", "list")]),
    );
  } catch (error) { fail(error); }
}

$("#refresh-events").addEventListener("click", loadEvents);
$("#event-filter").addEventListener("change", loadEvents);

/* --------------------------------------------------------------- settings */

/* Restoring a file, or allowing a reported one, adds its digest here. Without
   somewhere to see that list, a mis-click is permanent and invisible. */
async function loadAllowlist() {
  try {
    const { entries } = await api("/api/allowlist");
    const target = $("#allowlist");
    if (!entries.length) {
      target.replaceChildren(emptyState(
        "Nothing is on the allow-list. Files you restore or allow end up here.", "check"));
      return;
    }
    target.replaceChildren(el("table", { class: "table" },
      el("thead", {}, el("tr", {},
        el("th", { text: "File" }), el("th", { text: "Fingerprint" }),
        el("th", { text: "Last seen" }), el("th", { text: "" }),
      )),
      el("tbody", {}, ...entries.map((entry) => el("tr", {},
        el("td", {}, entry.path
          ? el("span", { class: "path", title: entry.path, text: shortPath(entry.path, 60) })
          : el("span", { class: "field__hint", text: "unknown file" })),
        el("td", {}, el("span", { class: "mono", text: `${entry.sha256.slice(0, 16)}…` })),
        el("td", { text: entry.last_seen ? when(entry.last_seen) : "—" }),
        el("td", {}, el("button", {
          class: "btn btn--sm",
          title: "Check this file again in future scans",
          text: "Scan it again",
          onclick: () => revokeAllowed(entry.sha256),
        })),
      ))),
    ));
  } catch (error) { fail(error); }
}

async function revokeAllowed(digest) {
  try {
    await api(`/api/allowlist/${digest}`, { method: "DELETE" });
    toast("Back to normal", "This file will be checked again", "ok");
    loadAllowlist();
  } catch (error) { fail(error); }
}

$("#refresh-allowlist").addEventListener("click", loadAllowlist);

async function loadSettings() {
  try {
    const [config, system] = await Promise.all([api("/api/config"), api("/api/system")]);
    state.config = config;

    $$("[data-config]").forEach((input) => {
      const [section, key] = input.dataset.config.split(".");
      const value = config[section]?.[key];
      if (input.type === "checkbox") input.checked = Boolean(value);
      else input.value = value ?? "";
      // A sensitivity that is not one of the three presets (set by hand in
      // config.json, or by an older build) would leave the select blank.
      if (input.tagName === "SELECT" && input.selectedIndex < 0) {
        input.append(el("option", { value: String(value), text: `Custom (${value})` }));
        input.value = String(value);
      }
    });

    const engine = system.engine;
    const rows = [
      ["Version", system.version],
      ["Platform", system.platform],
      ["Python", system.python],
      ["Data directory", system.data_dir],
      ["Signature sets", (engine.signatures.sets || []).map((s) =>
        `${s.name} (${s.hashes} hashes, ${s.patterns} patterns)`).join(" · ") || "—"],
      ["YARA backend", `${engine.yara.backend} · ${engine.yara.rule_count} rules`],
      ["Uptime", duration(system.uptime)],
    ];
    $("#about-info").replaceChildren(...rows.flatMap(([key, value]) => [
      el("dt", { text: key }), el("dd", {}, el("span", { class: "mono", text: String(value) })),
    ]));
    loadAllowlist();
  } catch (error) { fail(error); }
}

async function saveConfig(patch, message) {
  try {
    state.config = await api("/api/config", { method: "PUT", body: patch });
    if (message) toast(message, "", "ok");
    return true;
  } catch (error) {
    fail(error);
    return false;
  }
}

document.addEventListener("change", (event) => {
  const input = event.target.closest("[data-config]");
  if (!input) return;
  const [section, key] = input.dataset.config.split(".");
  let value;
  if (input.type === "checkbox") value = input.checked;
  // A <select> reports type "select-one", so numeric ones say so explicitly.
  else if (input.type === "number" || input.dataset.configType === "number") value = Number(input.value);
  else value = input.value;
  saveConfig({ [section]: { [key]: value } }, "Saved");
});

/* ------------------------------------------------------------------- boot */

function boot() {
  applyTheme(localStorage.getItem("guardiantus-theme") || "system");
  const initial = (location.hash || "#dashboard").slice(1);
  showView($(`#view-${initial}`) ? initial : "dashboard");
  refreshDashboard();
  pollScans();
  setInterval(() => {
    if (!state.activeScans.length) refreshDashboard();
  }, 15000);
}

window.addEventListener("hashchange", () => {
  const name = location.hash.slice(1);
  if ($(`#view-${name}`) && name !== state.view) showView(name);
});

boot();
