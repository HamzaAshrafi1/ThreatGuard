console.log("[PhishGuard] loaded");

// ─── Platform ─────────────────────────────────────────────────────────────────
const platform = location.hostname.includes("web.whatsapp.com")
  ? "whatsapp"
  : location.hostname.includes("mail.google.com")
  ? "gmail"
  : null;

if (!platform) throw new Error("[PhishGuard] Unsupported host");
console.log("[PhishGuard] Platform:", platform);

// ─── Dedup ────────────────────────────────────────────────────────────────────
const seen = new Set();

// ─── Flagged IDs — persisted so we can re-highlight after React re-renders ───
// Stores { result, waDataId, text } — text needed for feedback submission
const flaggedMessages = new Map(); // id → { result, waDataId, text }

// ─── LRU Cache (max 500 entries) ─────────────────────────────────────────────
const LRU_MAX = 500;
const requestCache = new Map();

function lruSet(key, value) {
  if (requestCache.has(key)) requestCache.delete(key);
  if (requestCache.size >= LRU_MAX) {
    requestCache.delete(requestCache.keys().next().value);
  }
  requestCache.set(key, value);
}

function lruGet(key) {
  if (!requestCache.has(key)) return undefined;
  const value = requestCache.get(key);
  requestCache.delete(key);
  requestCache.set(key, value);
  return value;
}

// ─── Throttle ─────────────────────────────────────────────────────────────────
const lastProcessed = new Map();
const THROTTLE_TIME = 5000;

// ─── FastAPI Call — routed via background to avoid mixed-content block ────────
async function callAPI(text) {
  if (!text) return null;

  const cached = lruGet(text);
  if (cached !== undefined) return cached;

  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "PREDICT", text }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve(null);
        } else {
          if (
            typeof response.phishing_probability !== "number" ||
            typeof response.prediction !== "string"
          ) {
            console.warn("[PhishGuard] Unexpected API response shape:", response);
            resolve(null);
          } else {
            lruSet(text, response);
            resolve(response);
          }
        }
      });
    } catch (err) {
      console.warn("[PhishGuard] Runtime unavailable:", err.message);
      resolve(null);
    }
  });
}

// ─── Feedback Submission ──────────────────────────────────────────────────────
// Sends a confirmed label to the API's /feedback endpoint via background.
// The API immediately calls partial_fit() on the online correction model.
function sendFeedback(text, label, reportedProb, btn) {
  btn.disabled = true;
  btn.style.opacity = "0.5";
  btn.innerText = "Sending…";

  try {
    chrome.runtime.sendMessage(
      { type: "FEEDBACK", text, label, reported_prob: reportedProb },
      (response) => {
        if (chrome.runtime.lastError || !response?.ok) {
          btn.innerText = "⚠️ Failed";
          btn.style.color = "#ff6b6b";
          console.warn("[PhishGuard] Feedback failed:", chrome.runtime.lastError);
        } else {
          btn.innerText = label === 1 ? "✅ Reported" : "✅ Marked Safe";
          btn.style.color = "#22c55e";
          console.log("[PhishGuard] Feedback accepted:", response.data);
        }
      }
    );
  } catch (err) {
    btn.innerText = "⚠️ Failed";
    console.warn("[PhishGuard] Feedback send error:", err.message);
  }
}

// ─── Extract URLs from plain text ─────────────────────────────────────────────
function extractURLsFromText(text) {
  const spaced = text.replace(/(https?:\/\/|www\.)/gi, " $1");
  const urlRegex = /https?:\/\/[^\s]+|www\.[^\s]+/gi;
  return (spaced.match(urlRegex) || []).map(u =>
    u.startsWith("http") ? u : "https://" + u
  );
}

// ─── Local fallback model ─────────────────────────────────────────────────────
function analyzeMessage({ text = "", body = "", subject = "", links = [] }) {
  const content = `${text} ${body} ${subject}`.toLowerCase();

  let score = 0;
  const reasons = [];

  // 1. High-risk phishing intent
  const credentialFields = [
    "otp", "one-time password", "password", "account id", "account number",
    "username", "date of birth", "mobile number", "phone number", "full name",
    "bank details", "card details", "cvv", "verify your identity",
    "confirm your identity", "verify your account", "confirm your account",
    "personal details", "sensitive information"
  ];

  let credentialHits = 0;
  credentialFields.forEach(field => {
    if (content.includes(field)) {
      credentialHits++;
      score += 2;
      reasons.push(`Sensitive data request: ${field}`);
    }
  });

  if (credentialHits >= 3) {
    score += 4;
    reasons.push("Mass credential harvesting pattern");
  }

  // 2. Urgency / coercion
  const urgencyPatterns = [
    "act now", "immediately", "within 24 hours", "within the next",
    "12 hours", "24 hours", "account will be blocked", "account.*blocked",
    "permanent suspension", "permanently suspended", "restricted",
    "temporarily restricted", "security alert", "unusual activity",
    "unauthorized access", "precautionary measure", "failure to",
    "loss of.*services", "loss of access"
  ];

  let urgencyHits = 0;
  urgencyPatterns.forEach(p => {
    const matched = p.includes(".*")
      ? new RegExp(p).test(content)
      : content.includes(p);
    if (matched) {
      urgencyHits++;
      score += 2;
      reasons.push(`Urgency: ${p}`);
    }
  });

  // 3. Impersonation signals
  const impersonation = [
    "security team", "support department", "customer support",
    "customer security", "official notice", "help desk", "trust and safety",
    "fraud department", "verification team", "compliance team",
    "actively monitoring"
  ];

  impersonation.forEach(p => {
    if (content.includes(p)) {
      score += 1.5;
      reasons.push(`Impersonation: ${p}`);
    }
  });

  // 4. Link-based signals
  links.forEach(link => {
    try {
      const url = new URL(link);
      const domain = url.hostname;

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        score += 3;
        reasons.push("IP-based URL");
      }
      if (/(bit\.ly|tinyurl\.com|t\.co|goo\.gl)/.test(domain)) {
        score += 3;
        reasons.push("Shortened URL");
      }
      if (/\.(xyz|tk|ml|ga|cf)$/.test(domain)) {
        score += 2;
        reasons.push("Suspicious TLD");
      }
    } catch {}
  });

  if (links.length > 2) {
    score += 2;
    reasons.push("Multiple links");
  }

  // 5. Intent boost
  const intentScore = credentialHits + urgencyHits;
  if (intentScore >= 5) {
    score += 3;
    reasons.push("Strong phishing intent detected");
  }

  return { score, reasons };
}

// ─── Feedback Button Factory ──────────────────────────────────────────────────
// Creates the two inline feedback buttons shown under every flagged banner.
// Both buttons share the same container; clicking one disables the other.
function createFeedbackButtons(text, reportedProb) {
  const row = document.createElement("div");
  Object.assign(row.style, {
    display:    "flex",
    gap:        "6px",
    marginTop:  "6px"
  });

  // ── "Mark as Safe" button ──
  const safeBtn = document.createElement("button");
  safeBtn.innerText = "✅ Mark Safe";
  Object.assign(safeBtn.style, {
    fontSize:     "11px",
    padding:      "3px 8px",
    border:       "1px solid #22c55e",
    borderRadius: "4px",
    background:   "transparent",
    color:        "#22c55e",
    cursor:       "pointer"
  });

  // ── "Confirm Phishing" button ──
  const phishBtn = document.createElement("button");
  phishBtn.innerText = "🚨 Confirm Phishing";
  Object.assign(phishBtn.style, {
    fontSize:     "11px",
    padding:      "3px 8px",
    border:       "1px solid #ef4444",
    borderRadius: "4px",
    background:   "transparent",
    color:        "#ef4444",
    cursor:       "pointer"
  });

  safeBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    phishBtn.disabled = true;
    phishBtn.style.opacity = "0.4";
    sendFeedback(text, 0, reportedProb, safeBtn);
  });

  phishBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    safeBtn.disabled = true;
    safeBtn.style.opacity = "0.4";
    sendFeedback(text, 1, reportedProb, phishBtn);
  });

  row.appendChild(safeBtn);
  row.appendChild(phishBtn);
  return row;
}

// ─── WhatsApp UI ──────────────────────────────────────────────────────────────
function highlightWA(el, result, text) {
  if (!el) return;

  el.dataset.pgFlagged = "true";

  if (el.dataset.pgStyled === "true") return;
  el.dataset.pgStyled = "true";

  el.style.background   = "linear-gradient(135deg,#ffe6e6,#fff5f5)";
  el.style.boxShadow    = "0 0 0 2px rgba(255,0,0,0.4)";
  el.style.borderRadius = "10px";

  const existing = el.querySelector(".pg-banner");
  if (existing) existing.remove();

  // ── Banner ──
  const banner = document.createElement("div");
  banner.className = "pg-banner";

  // Risk badge colour based on API risk_level (HIGH / MEDIUM / LOW)
  const riskColors = { HIGH: "#b30000", MEDIUM: "#b45309", LOW: "#166534" };
  const riskColor  = riskColors[result.risk_level] || "#b30000";

  const titleLine = document.createElement("div");
  titleLine.innerText = `⚠️ Suspicious Message • Score ${result.score.toFixed(2)} [${result.risk_level || "?"}]`;
  Object.assign(titleLine.style, {
    color:      riskColor,
    fontSize:   "12px",
    fontWeight: "600"
  });

  banner.appendChild(titleLine);

  // ── Feedback buttons (only when API was used, prob is meaningful) ──
  if (result.prob !== undefined) {
    banner.appendChild(createFeedbackButtons(text, result.prob));
  }

  el.prepend(banner);
}

// ─── Gmail UI ─────────────────────────────────────────────────────────────────
function highlightGmail(el, result, text) {
  if (!el || el.dataset.pgFlagged) return;
  el.dataset.pgFlagged = "true";

  const wrapper = document.createElement("div");
  Object.assign(wrapper.style, {
    border:       "2px solid #ef4444",
    borderRadius: "10px",
    padding:      "10px",
    marginBottom: "10px",
    background:   "#fff5f5"
  });

  // ── Banner ──
  const riskColors = { HIGH: "#b30000", MEDIUM: "#b45309", LOW: "#166534" };
  const riskColor  = riskColors[result.risk_level] || "#b30000";

  const banner = document.createElement("div");
  banner.innerText = `⚠️ Phishing Email • Score ${result.score.toFixed(2)} [${result.risk_level || "?"}]`;
  Object.assign(banner.style, {
    color:        riskColor,
    fontWeight:   "bold",
    marginBottom: "6px"
  });

  wrapper.appendChild(banner);

  // ── Feedback buttons ──
  if (result.prob !== undefined) {
    wrapper.appendChild(createFeedbackButtons(text, result.prob));
  }

  el.parentNode.insertBefore(wrapper, el);
  wrapper.appendChild(el);
}

// ─── Toast ────────────────────────────────────────────────────────────────────
const toastQueue  = [];
let   toastRunning = false;

function showToast(mode) {
  toastQueue.push(mode);
  if (!toastRunning) processToastQueue();
}

function processToastQueue() {
  if (toastQueue.length === 0) { toastRunning = false; return; }

  toastRunning = true;
  const mode  = toastQueue.shift();
  const toast = document.createElement("div");
  toast.innerText = `⚠️ PhishGuard (${mode.toUpperCase()}): Suspicious content detected`;

  Object.assign(toast.style, {
    position:   "fixed",
    top:        "20px",
    right:      "20px",
    padding:    "12px 16px",
    background: "#1f1f1f",
    color:      "#fff",
    borderRadius: "8px",
    fontSize:   "13px",
    zIndex:     "2147483647",
    opacity:    "0",
    transition: "opacity 0.2s ease"
  });

  document.body.appendChild(toast);
  setTimeout(() => (toast.style.opacity = "1"), 10);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => { toast.remove(); processToastQueue(); }, 200);
  }, 3000);
}

// ─── MAIN DISPATCH ────────────────────────────────────────────────────────────
async function dispatch(source, id, payload) {

  // ── Re-highlight if React wiped the DOM (WA SPA re-renders) ──
  if (flaggedMessages.has(id)) {
    const cached = flaggedMessages.get(id);

    if (source === "whatsapp" && cached.waDataId) {
      const freshEl = document.querySelector(
        `[data-id="${CSS.escape(cached.waDataId)}"]`
      );
      if (freshEl && !freshEl.dataset.pgStyled) {
        highlightWA(freshEl, cached.result, cached.text);
      }
    }
    return;
  }

  if (seen.has(id)) return;
  seen.add(id);

  const now = Date.now();
  if (lastProcessed.has(id) && now - lastProcessed.get(id) < THROTTLE_TIME) return;
  lastProcessed.set(id, now);

  const textInput = payload.text || payload.body || "";

  if (textInput.trim().split(/\s+/).length < 4 && (payload.links || []).length === 0) {
    console.log("[PhishGuard] Skipped (too short):", textInput);
    return;
  }

  let apiResult = await callAPI(textInput);

  let result;
  let isPhishing = false;
  let mode = "unknown";

  if (apiResult) {
    const mlScore     = apiResult.phishing_probability * 10;
    const fallback    = analyzeMessage(payload);
    const hybridScore = Math.min(10, mlScore + fallback.score * 0.3);

    const reasons = ["ML Model Detection"];
    if (fallback.reasons.length > 0) reasons.push(...fallback.reasons);

    result = {
      score:      hybridScore,
      reasons,
      risk_level: apiResult.risk_level || "UNKNOWN",  // pass through from API
      prob:       apiResult.phishing_probability       // raw prob for feedback
    };

    isPhishing = apiResult.prediction === "phishing" && hybridScore >= 5;
    mode       = "hybrid";

    console.log("[PhishGuard] 🟢 MODE: HYBRID");
    console.log(
      "  ML score:", mlScore.toFixed(2),
      "| Fallback boost:", fallback.score,
      "| Hybrid:", hybridScore.toFixed(2),
      "| Risk:", apiResult.risk_level
    );

  } else {
    const fallbackResult = analyzeMessage(payload);
    result     = { ...fallbackResult, risk_level: "UNKNOWN" };
    isPhishing = fallbackResult.score >= 5;
    mode       = "fallback";
    console.log("[PhishGuard] 🟡 MODE: FALLBACK | Score:", result.score);
  }

  if (isPhishing) {
    flaggedMessages.set(id, {
      result,
      waDataId: payload.waDataId || null,
      text:     textInput                 // stored for feedback re-use on re-render
    });

    if (source === "whatsapp") highlightWA(payload.el, result, textInput);
    if (source === "gmail")    highlightGmail(payload.el, result, textInput);

    showToast(mode);

    // FIX: strip the non-serialisable DOM element before sending to background
    chrome.runtime.sendMessage({
      type: "PHISH_DETECTED",
      data: {
        source,
        result,
        mode,
        text: textInput   // plain text only — no el, no waDataId DOM reference
      }
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WHATSAPP EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════════
function waExtract(el) {
  const bubble = el.closest(".message-in, .message-out");
  if (!bubble) return;

  const waDataId = bubble.getAttribute("data-id") || null;
  const id =
    waDataId ||
    bubble.getAttribute("data-testid") ||
    `wa-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

  const textEl = bubble.querySelector('[data-testid="selectable-text"]');
  const text   = textEl?.innerText || "";

  const anchorLinks = [...bubble.querySelectorAll("a[href]")].map(a => a.href);
  const textLinks   = extractURLsFromText(text);
  const links       = [...new Set([...anchorLinks, ...textLinks])];

  if (!text && links.length === 0) return;

  dispatch("whatsapp", id, { text, links, el: bubble, waDataId });
}

// ═══════════════════════════════════════════════════════════════════════════════
// GMAIL EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════════
function gmailExtract(el) {
  if (!el.classList.contains("aiL")) return;

  const id = el.closest("[data-legacy-message-id]")?.getAttribute("data-legacy-message-id");
  if (!id || seen.has(id)) return;

  const subject = document.querySelector("h2.hP")?.innerText || "";

  const clone = el.cloneNode(true);
  clone.querySelectorAll(".gmail_quote, blockquote").forEach(n => n.remove());

  const body = clone.innerText.trim();
  if (!body) return;

  const links = [...clone.querySelectorAll("a")].map(a => a.href).filter(Boolean);

  dispatch("gmail", id, { subject, body, links, el });
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIAL SCAN
// ═══════════════════════════════════════════════════════════════════════════════
function initialScan() {
  if (platform === "whatsapp") {
    document.querySelectorAll(".message-in, .message-out").forEach(waExtract);
    console.log("[PhishGuard] Initial WA scan done");
  }
  if (platform === "gmail") {
    document.querySelectorAll(".a3s.aiL").forEach(el => {
      setTimeout(() => gmailExtract(el), 300);
    });
    console.log("[PhishGuard] Initial Gmail scan done");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MUTATION OBSERVER
// ═══════════════════════════════════════════════════════════════════════════════
const observer = new MutationObserver((mutations) => {
  for (const m of mutations) {
    for (const node of m.addedNodes) {
      if (!(node instanceof HTMLElement)) continue;

      if (platform === "whatsapp") {
        if (node.matches?.(".message-in, .message-out")) waExtract(node);
        node.querySelectorAll?.(".message-in, .message-out").forEach(waExtract);
      }

      if (platform === "gmail") {
        if (node.classList?.contains("a3s")) {
          setTimeout(() => gmailExtract(node), 300);
        }
        node.querySelectorAll?.(".a3s.aiL").forEach(el => {
          setTimeout(() => gmailExtract(el), 300);
        });
      }
    }
  }
});

observer.observe(document.body, { childList: true, subtree: true });

setTimeout(initialScan, 2000);

console.log("[PhishGuard] Active");