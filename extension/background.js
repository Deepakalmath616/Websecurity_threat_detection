// ============================================================
// background.js — Service Worker for Web Threat Detector
// Runs in the background and monitors tab navigations and
// file downloads, sending each URL to the backend for analysis.
// ============================================================

const API_BASE = "http://127.0.0.1:5000";
// ------------------------------------------------------------
// Helper: Send a URL to the backend and log the threat result.
// @param {string} endpoint  - API path, e.g. "/check-url"
// @param {string} url       - The URL to analyse
// @param {string} context   - Label used in console output
// ------------------------------------------------------------
async function checkUrl(endpoint, url, context) {
  // Guard: skip empty, undefined, or internal Chrome URLs
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
    return;
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      // Server returned a non-2xx status code
      console.warn(`[Web Threat Detector] ${context} — server error ${response.status} for: ${url}`);
      return;
    }

    const data = await response.json();

    // Expected response shape: { status: "Safe" | "Suspicious" | "Malicious", ... }
    const status = data.status || "Unknown";
    console.log(`[Web Threat Detector] ${context} — ${status}: ${url}`);

    // Optional: surface a browser notification for high-severity results
    if (status === "Malicious" || status === "Suspicious") {
      console.warn(`[Web Threat Detector] ⚠️  ${status} URL detected: ${url}`);
    }

  } catch (error) {
    // Network failure or backend not running — fail silently so the
    // extension does not interfere with normal browsing.
    console.error(`[Web Threat Detector] ${context} — API unreachable:`, error.message);
  }
}

// ------------------------------------------------------------
// Tab Monitor: fires whenever a tab's URL changes or a page
// finishes loading.  We only act on "complete" status to avoid
// duplicate checks during redirects.
// ------------------------------------------------------------
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only proceed when the page has fully loaded
  if (changeInfo.status !== "complete") return;

  const url = tab.url;
  checkUrl("/check-url", url, "Tab navigation");
});

// ------------------------------------------------------------
// Download Monitor: fires as soon as Chrome registers a new
// download, giving us the source URL before the file lands.
// ------------------------------------------------------------
chrome.downloads.onCreated.addListener((downloadItem) => {
  const url = downloadItem.url;
  checkUrl("/check-download", url, "Download");
});
