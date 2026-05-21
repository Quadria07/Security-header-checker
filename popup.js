"use strict";

// ── DOM refs ──────────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const els = {
  loading:      $("loading"),
  results:      $("results"),
  urlDisplay:   $("url-display"),
  footerNotice: $("footer-notice"),
  cookieChecks: $("cookie-checks"),
  warningsList: $("warnings-list"),
  riskBadge:    $("risk-badge"),

  https: { row: $("row-https"), icon: $("icon-https"), status: $("status-https") },
  csp:   { row: $("row-csp"),   icon: $("icon-csp"),   status: $("status-csp")   },
  hsts:  { row: $("row-hsts"),  icon: $("icon-hsts"),  status: $("status-hsts")  },
  xfo:   { row: $("row-xfo"),   icon: $("icon-xfo"),   status: $("status-xfo")   },
  xcto:  { row: $("row-xcto"),  icon: $("icon-xcto"),  status: $("status-xcto")  },
};

// ── State map ─────────────────────────────────────────────────────────────────

const STATE = {
  ok:   { symbol: "✔", cls: "status-ok",   rowCls: "status-ok-row"   },
  warn: { symbol: "⚠", cls: "status-warn", rowCls: "status-warn-row" },
  fail: { symbol: "✘", cls: "status-fail", rowCls: "status-fail-row" },
  info: { symbol: "–", cls: "status-info", rowCls: "status-info-row" },
};

// ── Render helpers ────────────────────────────────────────────────────────────

// Updates a static check row (header rows defined in HTML)
function setCheck(key, state, message) {
  const el    = els[key];
  const entry = STATE[state] ?? STATE.info;

  el.icon.textContent   = entry.symbol;
  el.icon.className     = `indicator ${entry.cls}`;
  el.status.textContent = message;
  el.status.className   = `check-status ${entry.cls}`;

  el.row.classList.remove("status-ok-row", "status-warn-row", "status-fail-row", "status-info-row");
  el.row.classList.add(entry.rowCls);
}

// Builds and returns a check-row element for dynamic sections (cookies, warnings)
function makeRow(state, name, message) {
  const entry = STATE[state] ?? STATE.info;

  const row        = document.createElement("div");
  const icon       = document.createElement("span");
  const info       = document.createElement("div");
  const checkName  = document.createElement("div");
  const checkStatus = document.createElement("div");

  row.className         = `check-row ${entry.rowCls}`;
  icon.className        = `indicator ${entry.cls}`;
  icon.textContent      = entry.symbol;
  info.className        = "info";
  checkName.className   = "check-name";
  checkName.textContent = name;
  checkStatus.className   = `check-status ${entry.cls}`;
  checkStatus.textContent = message;

  info.appendChild(checkName);
  info.appendChild(checkStatus);
  row.appendChild(icon);
  row.appendChild(info);

  return row;
}

// Builds and returns a warning item element
function makeWarningItem(text, level) {
  const item = document.createElement("div");
  const cls  = level === "critical" ? "warning-item critical"
             : level === "pass"     ? "warning-item pass"
             :                        "warning-item";
  item.className   = cls;
  item.textContent = text;
  return item;
}

// ── Analysis ──────────────────────────────────────────────────────────────────

function analyseHttps(url) {
  if (url.startsWith("https://")) {
    setCheck("https", "ok", "Connection is encrypted");
    return true;
  }
  setCheck("https", "fail", "Not secure — plain HTTP");
  return false;
}

// Returns findings object consumed by buildWarnings() and calculateRisk()
function analyseHeaders(data) {
  const found = { csp: false, hsts: false, xfo: false, xcto: false };

  if (data.csp) {
    setCheck("csp", "ok", "Present — controls resource loading sources");
    found.csp = true;
  } else {
    setCheck("csp", "fail", "Missing — increases XSS risk");
  }

  if (data.hsts) {
    if (data.hsts.toLowerCase().includes("max-age=")) {
      setCheck("hsts", "ok", "Present with max-age — enforces HTTPS");
      found.hsts = true;
    } else {
      setCheck("hsts", "warn", "Present but missing max-age directive");
    }
  } else {
    setCheck("hsts", "fail", "Missing — HTTPS not enforced by server");
  }

  if (data.xfo) {
    const val = data.xfo.toUpperCase();
    if (val === "DENY" || val === "SAMEORIGIN") {
      setCheck("xfo", "ok", `${data.xfo} — clickjacking protection enabled`);
      found.xfo = true;
    } else {
      setCheck("xfo", "warn", "Present but value is non-standard");
    }
  } else {
    setCheck("xfo", "fail", "Missing — page may be embeddable in iframes");
  }

  if (data.xcto) {
    if (data.xcto.toLowerCase().trim() === "nosniff") {
      setCheck("xcto", "ok", "nosniff — MIME sniffing disabled");
      found.xcto = true;
    } else {
      setCheck("xcto", "warn", "Present but value is not 'nosniff'");
    }
  } else {
    setCheck("xcto", "fail", "Missing — browser may sniff content types");
  }

  return found;
}

// Returns findings object consumed by buildWarnings() and calculateRisk()
function analyseCookies(summary) {
  els.cookieChecks.replaceChildren();

  const found = {
    hasInsecure:        false,
    hasMissingSameSite: false,
    hasMissingHttpOnly: false,
    total:              0,
  };

  if (summary.error) {
    els.cookieChecks.appendChild(makeRow("info", "Cookie Access", summary.error));
    return found;
  }

  if (summary.total === 0) {
    els.cookieChecks.appendChild(makeRow("info", "Cookies", "No cookies detected on this page"));
    return found;
  }

  found.total = summary.total;
  const n     = summary.total;

  // Secure flag
  if (summary.insecure === 0) {
    els.cookieChecks.appendChild(makeRow("ok", "Secure Flag", `All ${n} cookie(s) have Secure flag`));
  } else {
    found.hasInsecure = true;
    els.cookieChecks.appendChild(makeRow("fail", "Secure Flag", `${summary.insecure} of ${n} cookie(s) missing Secure flag`));
  }

  // SameSite
  if (summary.missingSameSite === 0) {
    els.cookieChecks.appendChild(makeRow("ok", "SameSite", `All ${n} cookie(s) have SameSite set`));
  } else {
    found.hasMissingSameSite = true;
    els.cookieChecks.appendChild(makeRow("warn", "SameSite", `${summary.missingSameSite} of ${n} cookie(s) missing SameSite attribute`));
  }

  // HttpOnly
  if (summary.missingHttpOnly === 0) {
    els.cookieChecks.appendChild(makeRow("ok", "HttpOnly", `All ${n} cookie(s) have HttpOnly flag`));
  } else {
    found.hasMissingHttpOnly = true;
    els.cookieChecks.appendChild(makeRow("warn", "HttpOnly", `${summary.missingHttpOnly} of ${n} cookie(s) missing HttpOnly flag`));
  }

  return found;
}

// ── Warnings ──────────────────────────────────────────────────────────────────

function buildWarnings(isHttps, headerFound, cookieFound) {
  els.warningsList.replaceChildren();

  const warnings = [];

  if (!isHttps)              warnings.push({ text: "Site is not served over HTTPS — data is transmitted in plaintext",          level: "critical" });
  if (!headerFound.csp)      warnings.push({ text: "No CSP — no policy restricting which scripts or resources can load",        level: "warn" });
  if (!headerFound.hsts)     warnings.push({ text: "No HSTS — browser is not told to enforce HTTPS on future visits",          level: "warn" });
  if (!headerFound.xfo)      warnings.push({ text: "No X-Frame-Options — site may be vulnerable to clickjacking",              level: "warn" });
  if (!headerFound.xcto)     warnings.push({ text: "No X-Content-Type-Options — browser may misinterpret response types",      level: "warn" });
  if (cookieFound.hasInsecure)        warnings.push({ text: "Cookies missing Secure flag — may be sent over plain HTTP",       level: "warn" });
  if (cookieFound.hasMissingSameSite) warnings.push({ text: "Cookies missing SameSite — increased cross-site request risk",    level: "warn" });
  if (cookieFound.hasMissingHttpOnly) warnings.push({ text: "Cookies missing HttpOnly — readable by JavaScript on the page",   level: "warn" });

  if (warnings.length === 0) {
    els.warningsList.appendChild(makeWarningItem("No major issues detected based on available data", "pass"));
    return;
  }

  for (const w of warnings) {
    els.warningsList.appendChild(makeWarningItem(w.text, w.level));
  }
}

// ── Risk level ────────────────────────────────────────────────────────────────
//
// Three buckets — simple and explainable.
// High   → no HTTPS at all
// Medium → HTTPS but one or more issues detected
// Low    → HTTPS and no issues found

function calculateRisk(isHttps, headerFound, cookieFound) {
  if (!isHttps) return "high";

  const issues = [
    !headerFound.csp,
    !headerFound.hsts,
    !headerFound.xfo,
    !headerFound.xcto,
    cookieFound.hasInsecure,
    cookieFound.hasMissingSameSite,
    cookieFound.hasMissingHttpOnly,
  ].filter(Boolean).length;

  if (issues >= 3) return "high";
  if (issues >= 1) return "medium";
  return "low";
}

function renderRiskBadge(level) {
  const labels = { low: "Low Risk", medium: "Medium Risk", high: "High Risk" };
  els.riskBadge.textContent = labels[level] ?? "";
  els.riskBadge.className   = `risk-badge visible risk-${level}`;
}

// ── Fallback states ───────────────────────────────────────────────────────────

function setHeadersNotApplicable(message) {
  ["csp", "hsts", "xfo", "xcto"].forEach((key) => setCheck(key, "info", message));
}

function setHeadersNoData() {
  ["csp", "hsts", "xfo", "xcto"].forEach((key) =>
    setCheck(key, "warn", "No data — reload the page to capture headers")
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function run() {
  // 1. Get active tab from Chrome API (trusted source — not user input)
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    showError("Could not access tab information.");
    return;
  }

  const url = tab?.url ?? "";

  // 2. Validate — only http/https pages are checkable
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    showError("No checkable URL on this tab.");
    return;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    showError("Not a web page — nothing to check.");
    return;
  }

  // 3. Show URL safely — textContent only, never innerHTML
  els.urlDisplay.textContent = url.length > 65 ? url.slice(0, 62) + "…" : url;

  // 4. HTTPS check
  const isHttps = analyseHttps(url);

  // 5. Header results from background worker
  let headerFound = { csp: false, hsts: false, xfo: false, xcto: false };

  if (!isHttps) {
    setHeadersNotApplicable("Only checked over HTTPS");
  } else {
    let headerData = null;
    try {
      const res = await chrome.runtime.sendMessage({ type: "GET_HEADERS", tabId: tab.id });
      headerData = res?.data ?? null;
    } catch { /* service worker may not be ready on first install */ }

    if (!headerData) {
      setHeadersNoData();
      showResults("Reload the page to capture live response headers.");
      return;
    }

    headerFound = analyseHeaders(headerData);
  }

  // 6. Cookie results from background worker
  let cookieFound = {
    hasInsecure: false, hasMissingSameSite: false,
    hasMissingHttpOnly: false, total: 0,
  };

  try {
    const res = await chrome.runtime.sendMessage({ type: "GET_COOKIES", url });
    if (res?.data) cookieFound = analyseCookies(res.data);
  } catch {
    els.cookieChecks.appendChild(makeRow("info", "Cookies", "Could not retrieve cookie data"));
  }

  // 7. Warnings, risk badge, done
  buildWarnings(isHttps, headerFound, cookieFound);
  renderRiskBadge(calculateRisk(isHttps, headerFound, cookieFound));
  showResults(null);
}

// ── UI state ──────────────────────────────────────────────────────────────────

function showResults(notice) {
  els.loading.hidden = true;
  els.results.hidden = false;

  if (notice) {
    els.footerNotice.textContent = notice;
    els.footerNotice.hidden = false;
  } else {
    els.footerNotice.hidden = true;
  }
}

function showError(message) {
  els.loading.textContent = message;
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", run);
