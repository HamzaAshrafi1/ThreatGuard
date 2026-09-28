// ─── Persistent log: reload from storage on service worker startup ────────────
// Service workers can be killed and restarted at any time by Chrome.
// Without this, logs[] resets to [] on every restart and the popup shows nothing.
let logs = [];

chrome.storage.local.get("phishLogs", (data) => {
  if (data.phishLogs) logs = data.phishLogs;
});

// ─── Message Router ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── 1. PREDICT — proxy to FastAPI /predict ────────────────────────────────
  // Content scripts cannot call http:// directly (mixed-content block),
  // so they route through the background service worker which has no such limit.
  if (msg.type === "PREDICT") {
    fetch("http://127.0.0.1:8000/predict", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ text: msg.text })
    })
      .then(res => res.json())
      .then(data => sendResponse(data))
      .catch(() => sendResponse(null));

    return true; // CRITICAL — keeps the message channel open for async response
  }

  // ── 2. FEEDBACK — proxy to FastAPI /feedback (online learning) ───────────
  // Called when user clicks "✅ Safe" or "🚨 Phishing" on a flagged banner.
  // The API's SGDClassifier immediately partial_fits on this confirmed sample.
  if (msg.type === "FEEDBACK") {
    fetch("http://127.0.0.1:8000/feedback", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        text:          msg.text,
        label:         msg.label,          // 0 = safe, 1 = phishing
        reported_prob: msg.reported_prob   // the probability shown to the user
      })
    })
      .then(res => res.json())
      .then(data => sendResponse({ ok: true, data }))
      .catch(err => sendResponse({ ok: false, error: err.message }));

    return true; // keep channel open
  }

  // ── 3. PHISH_DETECTED — store log entry ──────────────────────────────────
  // NOTE: payload.el is a DOM element and cannot be serialized.
  //       content.js strips it before sending (see dispatch() in content.js).
  if (msg.type === "PHISH_DETECTED") {
    logs.unshift({
      platform:   msg.data.source,
      score:      msg.data.result.score,
      reasons:    msg.data.result.reasons,
      risk_level: msg.data.result.risk_level || "UNKNOWN", // from API response
      text:       msg.data.text || "",                     // pre-stripped in content.js
      mode:       msg.data.mode || "unknown",
      time:       new Date().toLocaleTimeString()
    });

    logs = logs.slice(0, 20); // keep last 20 only
    chrome.storage.local.set({ phishLogs: logs });
  }
});