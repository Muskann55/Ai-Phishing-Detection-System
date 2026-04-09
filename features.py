import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click"}

def url_features(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.netloc.lower()

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "count_dots": host.count("."),
        "has_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)),
        "has_hyphen": "-" in host,
        "suspicious_tld": int(any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        "https": int(parsed.scheme == "https"),
    }
    return features

def text_features(text: str) -> dict:
    text_l = text.lower()
    keywords = ["urgent", "verify", "password", "account", "login", "vote now", "suspended"]
    count_keywords = sum(kw in text_l for kw in keywords)
    return {
        "text_length": len(text),
        "keyword_hits": count_keywords,
    }