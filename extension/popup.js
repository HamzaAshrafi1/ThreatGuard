const container = document.getElementById("logs");
const clearBtn  = document.getElementById("clearBtn");
const healthDot = document.getElementById("healthDot");
const healthTxt = document.getElementById("healthTxt");

// ─── Server Health Check ───────────────────────────────────────────────────────
// Pings the FastAPI /health endpoint so the user knows whether AI detection
// is active or whether the extension is running in fallback-only mode.
fetch("http://127.0.0.1:8000/health")
  .then(res => res.json())
  .then(data => {
    healthDot.className = "dot dot-online";
    healthTxt.textContent = `AI Online · Feedback: ${data.feedback_count ?? 0}`;
  })
  .catch(() => {
    healthDot.className = "dot dot-offline";
    healthTxt.textContent = "AI Offline · Fallback mode";
  });

// ─── Load Logs ─────────────────────────────────────────────────────────────────
chrome.storage.local.get("phishLogs", (data) => {
  const logs = data.phishLogs || [];

  if (logs.length === 0) {
    container.innerHTML = `<div class="empty">No threats detected ✅</div>`;
    return;
  }

  logs.forEach(log => {
    const card = document.createElement("div");

    // ── Severity ──
    // Use risk_level from API when available (HIGH / MEDIUM / LOW).
    // Fall back to score-based calculation for old log entries or fallback mode.
    let severity;
    if (log.risk_level && log.risk_level !== "UNKNOWN") {
      severity = log.risk_level.toLowerCase(); // "high" | "medium" | "low"
    } else {
      if      (log.score >= 7) severity = "high";
      else if (log.score >= 4) severity = "medium";
      else                     severity = "low";
    }

    card.className = `card ${severity}`;

    // ── Mode badge label ──
    const modeLabel = {
      hybrid:   "🤖 AI + Rules",
      fallback: "📋 Rules only",
      unknown:  "❓ Unknown"
    }[log.mode] || "❓ Unknown";

    const modeCls = {
      hybrid:   "badge-hybrid",
      fallback: "badge-fallback",
      unknown:  "badge-unknown"
    }[log.mode] || "badge-unknown";

    const displayScore = parseFloat(log.score).toFixed(2);

    // ── Safe text rendering (avoid innerHTML with user data) ──
    const platform = document.createElement("div");
    platform.className = "platform";
    platform.textContent = log.platform.toUpperCase();

    const scoreRow = document.createElement("div");
    scoreRow.className = "score-row";

    const scoreEl = document.createElement("span");
    scoreEl.className = "score";
    scoreEl.textContent = `Score: ${displayScore}`;

    const badge = document.createElement("span");
    badge.className = `badge ${modeCls}`;
    badge.textContent = modeLabel;

    scoreRow.appendChild(scoreEl);
    scoreRow.appendChild(badge);

    const reasons = document.createElement("div");
    reasons.className = "reasons";
    // textContent is safe — no HTML injection possible
    reasons.textContent = (log.reasons || []).join(" · ");

    const time = document.createElement("div");
    time.className = "time";
    time.textContent = log.time;

    card.appendChild(platform);
    card.appendChild(scoreRow);
    card.appendChild(reasons);
    card.appendChild(time);

    container.appendChild(card);
  });
});

// ─── Clear Logs ────────────────────────────────────────────────────────────────
clearBtn.addEventListener("click", () => {
  chrome.storage.local.remove("phishLogs", () => {
    container.innerHTML = `<div class="empty">Logs cleared ✅</div>`;
  });
});