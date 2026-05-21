# Security Header Checker

A Chrome Extension that checks the security posture of the current browser tab. It reads response headers and cookie flags, then shows a plain summary of what is configured and what is missing.

Built with Manifest V3, no external libraries, and a minimal permission set.

---

## What it checks

**Connection**
- Whether the page is served over HTTPS

**Response Headers**
- `Content-Security-Policy` — controls which scripts and resources can load
- `Strict-Transport-Security` — instructs browsers to enforce HTTPS on future visits
- `X-Frame-Options` — prevents the page from being embedded in iframes (clickjacking)
- `X-Content-Type-Options` — stops browsers from guessing content types

**Cookie Flags**
- `Secure` — cookie should only be sent over HTTPS
- `SameSite` — reduces cross-site request exposure
- `HttpOnly` — prevents JavaScript from reading the cookie

**Security Insights**
- Plain-language warnings for each missing or misconfigured item
- A simple risk level: Low / Medium / High

---

## How to install (developer mode)

1. Download or clone this repository
2. Open Chrome and go to `chrome://extensions`
3. Enable **Developer mode** (toggle in the top right)
4. Click **Load unpacked**
5. Select the folder containing `manifest.json`

Then navigate to any website, reload the tab, and click the extension icon.

> **Why reload?** The background worker captures headers when a page loads. If the extension was just installed, it missed the previous load. One reload is enough.

---

## How it works

```
Page loads
  → background.js intercepts the response via chrome.webRequest
  → stores only 4 header values in memory, keyed by tab ID
  → clears data when the tab is closed

User opens popup
  → popup.js asks background for headers (GET_HEADERS)
  → popup.js asks background for cookie metadata (GET_COOKIES)
  → background calls chrome.cookies.getAll({ url }) — scoped to current site
  → popup analyses the results and renders the UI
```

No data is written to disk. No external requests are made. The in-memory store is capped at 50 tabs.

---

## Permissions

```json
"permissions": ["activeTab", "tabs", "webRequest", "cookies"],
"host_permissions": ["*://*/*"]
```

| Permission | Why it is needed |
|---|---|
| `activeTab` | Read the current tab's URL |
| `tabs` | Query which tab is active |
| `webRequest` | Intercept response headers before CORS applies |
| `cookies` | Read cookie metadata (flags only, never values) |
| `host_permissions *://*/*` | Required by `webRequest` to see headers across all sites |

---

## Limitations

**Header detection requires a page reload after installation.**
The background worker only captures headers it observes in real time. It cannot retroactively read headers from a page that already loaded.

**Cookie values are never accessed.**
The extension reads `.secure`, `.sameSite`, and `.httpOnly` flags only. The `.value` property is not touched anywhere in the code.

**`webRequest` in MV3 is read-only.**
The extension can observe headers but cannot modify them. It has no ability to inject or alter any page content.

**This is a passive analysis tool.**
It does not perform active scanning, make external requests, or send data anywhere. Results are based only on what Chrome exposes locally.

**CSP analysis is presence-only.**
The extension checks whether a CSP header exists. It does not parse or validate the policy directives inside it.

---

## Manual testing guide

**Test HTTPS vs HTTP**
- Open any `http://` site — HTTPS row should show red, headers should show "Only checked over HTTPS"
- Open any `https://` site — HTTPS should show green, headers should be evaluated

**Test header detection**
- `https://github.com` — has CSP, HSTS, and most headers (expect mostly green)
- `https://example.com` — minimal headers (expect several missing)

**Test cookie flags**
- Log in to any site that sets session cookies, then open the popup
- Cookie rows will show how many cookies are missing Secure, SameSite, or HttpOnly

**Test the "no data" state**
- Install the extension, open a tab that was already loaded
- Open the popup — should show "reload the page" notice
- Reload the tab, open popup again — should now show full results

---

## Project structure

```
security-header-checker/
├── manifest.json       — extension config, permissions
├── background.js       — header capture, cookie summary, message handlers
├── popup.html          — UI structure and styles
├── popup.js            — analysis logic and rendering
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Example result

On a site missing CSP but with HSTS and good cookie flags, you would see:

```
[Medium Risk]

HTTPS              ✔  Connection is encrypted
Content-Security-Policy  ✘  Missing — increases XSS risk
Strict-Transport-Security  ✔  Present with max-age
X-Frame-Options    ✔  SAMEORIGIN — clickjacking protection enabled
X-Content-Type-Options  ✔  nosniff — MIME sniffing disabled

Secure Flag        ✔  All 3 cookie(s) have Secure flag
SameSite           ✔  All 3 cookie(s) have SameSite set
HttpOnly           ✔  All 3 cookie(s) have HttpOnly flag

⚠ No CSP — no policy restricting which scripts or resources can load
```
