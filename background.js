"use strict";

// ── Header store ──────────────────────────────────────────────────────────────
//
// Stores only the 4 security headers we care about, keyed by tabId.
// Nothing else from the request is kept — no full URLs, no cookies, no body.
// Capped at MAX_TABS entries to prevent unbounded memory growth.

const MAX_TABS = 50;

const HEADERS_WE_TRACK = new Set([
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
]);

// { [tabId]: { csp, hsts, xfo, xcto, capturedAt } }
const headerStore = new Map();

// ── Header capture ────────────────────────────────────────────────────────────

chrome.webRequest.onResponseStarted.addListener(
  (details) => {
    // Only the top-level page response — not images, scripts, or iframes
    if (details.type !== "main_frame") return;

    const entry = {
      csp:        null,
      hsts:       null,
      xfo:        null,
      xcto:       null,
      capturedAt: Date.now(),
    };

    for (const header of details.responseHeaders ?? []) {
      const name = header.name.toLowerCase().trim();
      if (!HEADERS_WE_TRACK.has(name)) continue;

      // Store raw value as-is — analysis happens in popup.js
      const value = (header.value ?? "").trim();
      if (name === "content-security-policy")   entry.csp  = value;
      if (name === "strict-transport-security") entry.hsts = value;
      if (name === "x-frame-options")           entry.xfo  = value;
      if (name === "x-content-type-options")    entry.xcto = value;
    }

    // Evict oldest entry if at capacity
    if (headerStore.size >= MAX_TABS) {
      headerStore.delete(headerStore.keys().next().value);
    }

    headerStore.set(details.tabId, entry);
  },
  { urls: ["*://*/*"] },
  ["responseHeaders"]
);

// ── Cleanup on tab close ──────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  headerStore.delete(tabId);
});

// ── Cookie summary ────────────────────────────────────────────────────────────
//
// Reads cookie metadata only — never accesses cookie values.
// chrome.cookies.getAll can see HttpOnly cookies, unlike document.cookie.
// Scoped to the specific tab URL to avoid reading unrelated site cookies.

async function getCookieSummary(tabUrl) {
  let cookies;

  try {
    cookies = await chrome.cookies.getAll({ url: tabUrl });
  } catch {
    return { error: "Could not access cookies for this page." };
  }

  if (!cookies.length) {
    return { total: 0, insecure: 0, missingSameSite: 0, missingHttpOnly: 0 };
  }

  let insecure        = 0;
  let missingSameSite = 0;
  let missingHttpOnly = 0;

  for (const cookie of cookies) {
    // Deliberately never read cookie.value
    if (!cookie.secure)   insecure++;
    if (!cookie.httpOnly) missingHttpOnly++;
    if (!cookie.sameSite || cookie.sameSite === "no_restriction") missingSameSite++;
  }

  return {
    total: cookies.length,
    insecure,
    missingSameSite,
    missingHttpOnly,
  };
}

// ── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "GET_HEADERS") {
    const { tabId } = message;

    if (typeof tabId !== "number") {
      sendResponse({ error: "Invalid tabId" });
      return false;
    }

    sendResponse({ data: headerStore.get(tabId) ?? null });
    return false;
  }

  if (message?.type === "GET_COOKIES") {
    const { url } = message;

    if (!url || typeof url !== "string") {
      sendResponse({ error: "Invalid URL" });
      return false;
    }

    // Return true to keep the message channel open for the async response
    getCookieSummary(url).then((summary) => sendResponse({ data: summary }));
    return true;
  }

  return false;
});
