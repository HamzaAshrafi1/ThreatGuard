from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import joblib
import numpy as np
import re
import os
import json
from scipy.sparse import hstack, csr_matrix
from sentence_transformers import SentenceTransformer

# =========================
# INIT
# =========================
app = FastAPI(title="PhishGuard API", version="3.0")

# =========================
# CORS — allow chrome-extension:// origins
# =========================
@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin", "")

    allowed = (
        origin.startswith("chrome-extension://")
        or origin in ("http://127.0.0.1:5500", "http://localhost")
    )

    if request.method == "OPTIONS":
        headers = {}
        if allowed:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "Content-Type"
        return JSONResponse(status_code=200, headers=headers)

    response = await call_next(request)

    if allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    return response

# =========================
# LOAD MODELS
# =========================
print("Loading XGBoost model...")
model = joblib.load("phishguard_model.pkl")

print("Loading TF-IDF vectorizer...")
tfidf = joblib.load("phishguard_tfidf.pkl")

print("Loading keywords...")
KEYWORDS = joblib.load("phishguard_keywords.pkl")

print("Loading semantic embedder (MiniLM)...")
embedder = SentenceTransformer("phishguard_embedder")

print("Loading online correction model...")
online_model = joblib.load("phishguard_online_model.pkl")

with open("phishguard_threshold.txt", "r") as f:
    threshold = float(f.read().strip())

print(f"✅ All models loaded | Threshold: {threshold}")

FEEDBACK_FILE = "phishguard_feedback.json"

# =========================
# REQUEST MODELS
# =========================
class TextRequest(BaseModel):
    text: str

class FeedbackRequest(BaseModel):
    text: str
    label: int          # 1 = phishing, 0 = safe
    reported_prob: float

# =========================
# FEATURE ENGINEERING
# =========================
def extract_features(text: str) -> np.ndarray:
    text = str(text)
    tl   = text.lower()

    url_count          = len(re.findall(r'http[s]?://|www\.', text))
    special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', text)) / (len(text) + 1)
    digit_ratio        = len(re.findall(r'\d', text))           / (len(text) + 1)
    upper_ratio        = sum(1 for c in text if c.isupper())    / (len(text) + 1)
    exclaim_count      = text.count('!')
    word_count         = len(text.split())
    avg_word_len       = sum(len(w) for w in text.split()) / (word_count + 1)

    keyword_flags = [1 if kw in tl else 0 for kw in KEYWORDS]

    return np.array(
        [url_count, special_char_ratio, digit_ratio, upper_ratio,
         exclaim_count, word_count, avg_word_len]
        + keyword_flags
    )

def build_feature_vector(text: str):
    """Build the same combined feature matrix used during training."""
    X_tf  = tfidf.transform([text])
    X_eng = csr_matrix(extract_features(text).reshape(1, -1))
    X_sem = csr_matrix(
        embedder.encode([text], normalize_embeddings=True, show_progress_bar=False)
    )
    return hstack([X_tf, X_eng, X_sem])

# =========================
# CACHE (LRU-style, max 500)
# =========================
cache = {}
CACHE_MAX = 500

def cache_set(key, value):
    if len(cache) >= CACHE_MAX:
        oldest = next(iter(cache))
        del cache[oldest]
    cache[key] = value

# =========================
# PREDICT ENDPOINT
# =========================
@app.post("/predict")
def predict(data: TextRequest):
    text = data.text.strip()

    if text in cache:
        return cache[text]

    # Build combined feature vector
    X_in = build_feature_vector(text)

    # XGBoost base prediction
    xgb_prob = float(model.predict_proba(X_in)[0][1])

    # Online correction layer — adjusts XGBoost output based on feedback
    final_prob = float(
        online_model.predict_proba(np.array([[xgb_prob]]))[0][1]
    )

    # Blend: 70% XGBoost, 30% online correction
    # Online model starts neutral and gradually gains influence as feedback grows
    blended_prob = 0.7 * xgb_prob + 0.3 * final_prob

    prediction = 1 if blended_prob >= threshold else 0

    result = {
        "prediction":           "phishing" if prediction == 1 else "safe",
        "phishing_probability": round(blended_prob, 4),
        "xgb_probability":      round(xgb_prob, 4),
        "threshold":            threshold,
        "risk_level": (
            "HIGH"   if blended_prob > 0.7 else
            "MEDIUM" if blended_prob > 0.4 else
            "LOW"
        )
    }

    cache_set(text, result)
    return result

# =========================
# FEEDBACK ENDPOINT
# POST /feedback
# Body: { "text": "...", "label": 1, "reported_prob": 0.85 }
# =========================
@app.post("/feedback")
def receive_feedback(data: FeedbackRequest):
    """
    Accept confirmed labels from the extension or admin panel.
    Immediately updates the online correction model (partial_fit).
    Also persists the sample to disk for periodic full retraining.
    """
    text  = data.text.strip()
    label = int(data.label)

    if label not in (0, 1):
        return JSONResponse(status_code=400, content={"error": "label must be 0 or 1"})

    # Build feature vector for online model input
    X_in     = build_feature_vector(text)
    xgb_prob = float(model.predict_proba(X_in)[0][1])

    # Immediately update online model
    online_model.partial_fit(
        np.array([[xgb_prob]]),
        np.array([label]),
        classes=[0, 1]
    )

    # Persist updated model
    joblib.dump(online_model, "phishguard_online_model.pkl")

    # Invalidate cache for this text
    cache.pop(text, None)

    # Persist feedback sample for periodic full retraining
    entry = {"text": text, "label": label, "prob": data.reported_prob}

    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "r") as f:
            fb = json.load(f)
    else:
        fb = []

    fb.append(entry)

    with open(FEEDBACK_FILE, "w") as f:
        json.dump(fb, f, indent=2)

    return {
        "status":  "ok",
        "message": f"Feedback recorded. Online model updated. Total feedback samples: {len(fb)}"
    }

# =========================
# HEALTH CHECK
# =========================
@app.get("/health")
def health():
    return {
        "status":       "ok",
        "version":      "3.0",
        "feedback_count": len(json.load(open(FEEDBACK_FILE))) if os.path.exists(FEEDBACK_FILE) else 0,
        "cache_size":   len(cache)
    }