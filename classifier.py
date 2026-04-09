from typing import Tuple
from .features import url_features, text_features

# threshold between 0 and 1
HIGH_RISK_THRESHOLD = 0.7

def score_url_and_text(url: str, text: str = "") -> Tuple[float, str]:
    uf = url_features(url)
    tf = text_features(text)

    score = 0.0
    reasons = []

    if uf["suspicious_tld"]:
        score += 0.25
        reasons.append("Suspicious TLD")
    if uf["has_ip"]:
        score += 0.20
        reasons.append("URL uses raw IP address")
    if uf["has_hyphen"] and uf["count_dots"] > 2:
        score += 0.15
        reasons.append("Host has many dots and hyphens")
    if tf["keyword_hits"] > 0:
        score += 0.25
        reasons.append("Contains phishing-like urgent words")
    if not uf["https"]:
        score += 0.15
        reasons.append("Not using HTTPS")

    score = min(score, 1.0)
    explanation = ", ".join(reasons) if reasons else "No strong phishing indicators"
    return score, explanation

def classify(url: str, text: str = "") -> dict:
    score, explanation = score_url_and_text(url, text)
    label = "phishing" if score >= HIGH_RISK_THRESHOLD else "benign"
    return {
        "label": label,
        "score": round(score, 3),
        "explanation": explanation,
    }