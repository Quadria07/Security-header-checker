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
  riskCard:     $("risk-card"),
  riskIcon:     $("risk-icon"),
  riskLevel:    $("risk-level"),
  riskDesc:     $("risk-desc"),

  https: { row: $("row-https"), icon: $("icon-https"), status: $("status-https") },
  csp:   { row: $("row-csp"),   icon: $("icon-csp"),   status: $("status-csp")   },
  hsts:  { row: $("row-hsts"),  icon: $("icon-hsts"),  status: $("status-hsts")  },
  xfo:   { row: $("row-xfo"),   icon: $("icon-xfo"),   status: $("status-xfo")   },
  xcto:  { row: $("row-xcto"),  icon: $("icon-xcto"),  status: $("status-xcto")  },
};

// ── State config ──────────────────────────────────────────────────────────────

const STATE = {
  ok:   { symbol: "✓", cls: "ok"   },
  warn: { symbol: "!", cls: "warn" },
  fail: { symbol: "✕", cls: "fail" },
  info: { symbol: "–", cls: "info" },
};

// ── Render helpers ────────────────────────────────────────────────────────────

function setCheck(key, state, message) {
  const el    = els[key];
  const entry = STATE[state] ?? STATE.info;

  el.icon.textContent = entry.symbol;
  el.status.textContent = message;

  el.row.className = `check-row ${entry.cls}`;
}

// Builds a check-row element for dynamic sections (cookies)
function makeRow(state, name, technicalLabel, message) {
  const entry = STATE[state] ?? STATE.info;

  const row    = document.createElement("div");
  const badge  = document.createElement("div");
  const body   = document.createElement("div");
  const label  = document.createElement("div");
  const tech   = document.createElement("span");
  const desc   = document.createElement("div");

  row.className   = `check-row ${entry.cls}`;
  badge.className = "check-badge";
  badge.textContent = entry.symbol;
  body.className  = "check-body";
  label.className = "check-name";
  tech.className  = "check-technical";
  tech.textContent = technicalLabel;
  desc.className  = `check-desc`;
  desc.textContent = message;

  // Plain name text node first, then the technical pill
  label.appendChild(document.createTextNode(name + " "));
  label.appendChild(tech);
  body.appendChild(label);
  body.appendChild(desc);
  row.appendChild(badge);
  row.appendChild(body);

  return row;
}

// Builds an insight item
function makeInsight(text, level) {
  const item = document.createElement("div");
  item.className   = `insight-item ${level}`;
  item.textContent = text;
  return item;
}

// ── Risk card ─────────────────────────────────────────────────────────────────

const RISK_CONFIG = {
  low: {
    icon:  "✅",
    label: "Low Risk",
    desc:  "This site has good security practices in place.",
    cls:   "risk-low",
  },
  medium: {
    icon:  "⚠️",
    label: "Medium Risk",
    desc:  "Some security protections are missing or misconfigured.",
    cls:   "risk-medium",
  },
  high: {
    icon:  "🚨",
    label: "High Risk",
    desc:  "This site is missing important security protections.",
    cls:   "risk-high",
  },
};

function renderRiskCard(level) {
  const cfg = RISK_CONFIG[level] ?? RISK_CONFIG.high;
  els.riskIcon.textContent  = cfg.icon;
  els.riskLevel.textContent = cfg.label;
  els.riskDesc.textContent  = cfg.desc;
  els.riskCard.className    = `risk-card ${cfg.cls}`;
}

// ── Analysis ──────────────────────────────────────────────────────────────────

function analyseHttps(url) {
  if (url.startsWith("https://")) {
    setCheck("https", "ok", "Your connection to this site is encrypted");
    return true;
  }
  setCheck("https", "fail", "This site is not encrypted — data can be intercepted");
  return false;
}

function analyseHeaders(data) {
  const found = { csp: false, hsts: false, xfo: false, xcto: false };

  if (data.csp) {
    setCheck("csp", "ok", "The site controls what scripts are allowed to run");
    found.csp = true;
  } else {
    setCheck("csp", "fail", "No policy set — malicious scripts could run on this page");
  }

  if (data.hsts) {
    if (data.hsts.toLowerCase().includes("max-age=")) {
      setCheck("hsts", "ok", "Browser will always use a secure connection to this site");
      found.hsts = true;
    } else {
      setCheck("hsts", "warn", "Header present but not fully configured");
    }
  } else {
    setCheck("hsts", "fail", "Browser is not told to enforce secure connections");
  }

  if (data.xfo) {
    const val = data.xfo.toUpperCase();
    if (val === "DENY" || val === "SAMEORIGIN") {
      setCheck("xfo", "ok", "Site cannot be embedded inside another page");
      found.xfo = true;
    } else {
      setCheck("xfo", "warn", "Header present but value is non-standard");
    }
  } else {
    setCheck("xfo", "fail", "Site could be embedded in fake pages to trick users");
  }

  if (data.xcto) {
    if (data.xcto.toLowerCase().trim() === "nosniff") {
      setCheck("xcto", "ok", "Browser handles file types safely");
      found.xcto = true;
    } else {
      setCheck("xcto", "warn", "Header present but value is not 'nosniff'");
    }
  } else {
    setCheck("xcto", "fail", "Browser may mishandle certain file types");
  }

  return found;
}

function analyseCookies(summary) {
  els.cookieChecks.replaceChildren();

  const found = {
    hasInsecure: false, hasMissingSameSite: false,
    hasMissingHttpOnly: false, total: 0,
  };

  if (summary.error) {
    els.cookieChecks.appendChild(makeRow("info", "Cookie access", "", summary.error));
    return found;
  }

  if (summary.total === 0) {
    els.cookieChecks.appendChild(makeRow("info", "No cookies", "", "This page does not use any cookies"));
    return found;
  }

  found.total = summary.total;
  const n = summary.total;

  if (summary.insecure === 0) {
    els.cookieChecks.appendChild(makeRow("ok", "Sent securely", "Secure flag", `All ${n} cookie(s) are only sent over encrypted connections`));
  } else {
    found.hasInsecure = true;
    els.cookieChecks.appendChild(makeRow("fail", "Sent insecurely", "Secure flag", `${summary.insecure} of ${n} cookie(s) can be sent over unencrypted connections`));
  }

  if (summary.missingSameSite === 0) {
    els.cookieChecks.appendChild(makeRow("ok", "Cross-site protected", "SameSite", `All ${n} cookie(s) are protected from cross-site attacks`));
  } else {
    found.hasMissingSameSite = true;
    els.cookieChecks.appendChild(makeRow("warn", "Cross-site exposure", "SameSite", `${summary.missingSameSite} of ${n} cookie(s) may be sent in cross-site requests`));
  }

  if (summary.missingHttpOnly === 0) {
    els.cookieChecks.appendChild(makeRow("ok", "Hidden from scripts", "HttpOnly", `All ${n} cookie(s) are hidden from JavaScript`));
  } else {
    found.hasMissingHttpOnly = true;
    els.cookieChecks.appendChild(makeRow("warn", "Readable by scripts", "HttpOnly", `${summary.missingHttpOnly} of ${n} cookie(s) can be read by JavaScript on the page`));
  }

  return found;
}

// ── Insights ──────────────────────────────────────────────────────────────────

function buildInsights(isHttps, headerFound, cookieFound) {
  els.warningsList.replaceChildren();

  const items = [];

  if (!isHttps)
    items.push({ text: "🚨 This site uses plain HTTP — anyone on your network could see or intercept your data", level: "critical" });
  if (!headerFound.csp)
    items.push({ text: "⚠ No content policy — the site doesn't restrict which scripts can run, increasing XSS risk", level: "warn" });
  if (!headerFound.hsts)
    items.push({ text: "⚠ No HTTPS enforcement — your browser isn't told to always use a secure connection here", level: "warn" });
  if (!headerFound.xfo)
    items.push({ text: "⚠ No iframe protection — this page could be embedded in a fake site to trick you into clicking things", level: "warn" });
  if (!headerFound.xcto)
    items.push({ text: "⚠ No file type protection — the browser might mishandle certain file types served by this site", level: "warn" });
  if (cookieFound.hasInsecure)
    items.push({ text: "⚠ Some cookies can travel over unencrypted connections — session data may be exposed", level: "warn" });
  if (cookieFound.hasMissingSameSite)
    items.push({ text: "⚠ Some cookies lack cross-site protection — they could be sent in requests from other websites", level: "warn" });
  if (cookieFound.hasMissingHttpOnly)
    items.push({ text: "⚠ Some cookies are readable by JavaScript — if a script is compromised, cookies could be stolen", level: "warn" });

  if (items.length === 0) {
    els.warningsList.appendChild(makeInsight("✓ No major issues detected — this site has solid security headers in place", "pass"));
    return;
  }

  for (const item of items) {
    els.warningsList.appendChild(makeInsight(item.text, item.level));
  }
}

// ── Risk calculation ──────────────────────────────────────────────────────────

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

// ── Fallbacks ─────────────────────────────────────────────────────────────────

function setHeadersNotApplicable(message) {
  ["csp", "hsts", "xfo", "xcto"].forEach((k) => setCheck(k, "info", message));
}

function setHeadersNoData() {
  ["csp", "hsts", "xfo", "xcto"].forEach((k) =>
    setCheck(k, "warn", "No data — reload the page to capture headers")
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function run() {
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    showError("Could not access tab information.");
    return;
  }

  const url = tab?.url ?? "";

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

  els.urlDisplay.textContent = url.length > 60 ? url.slice(0, 57) + "…" : url;

  const isHttps = analyseHttps(url);

  let headerFound = { csp: false, hsts: false, xfo: false, xcto: false };

  if (!isHttps) {
    setHeadersNotApplicable("Only checked on encrypted (HTTPS) sites");
  } else {
    let headerData = null;
    try {
      const res = await chrome.runtime.sendMessage({ type: "GET_HEADERS", tabId: tab.id });
      headerData = res?.data ?? null;
    } catch { /* service worker not ready */ }

    if (!headerData) {
      setHeadersNoData();
      showResults("Reload this page to capture live security headers.");
      return;
    }

    headerFound = analyseHeaders(headerData);
  }

  let cookieFound = {
    hasInsecure: false, hasMissingSameSite: false,
    hasMissingHttpOnly: false, total: 0,
  };

  try {
    const res = await chrome.runtime.sendMessage({ type: "GET_COOKIES", url });
    if (res?.data) cookieFound = analyseCookies(res.data);
  } catch {
    els.cookieChecks.appendChild(makeRow("info", "Cookie check", "", "Could not retrieve cookie data"));
  }

  buildInsights(isHttps, headerFound, cookieFound);
  renderRiskCard(calculateRisk(isHttps, headerFound, cookieFound));
  showResults(null);
}

// ── UI helpers ────────────────────────────────────────────────────────────────

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
  const text = document.createElement("p");
  text.textContent = message;
  text.style.cssText = "color:#6e7681;font-size:12px;text-align:center;padding:48px 16px;";
  els.loading.replaceChildren(text);
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", run);