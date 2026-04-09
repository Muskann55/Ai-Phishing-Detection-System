from flask import Flask, request, jsonify, render_template
from model.classifier import classify
from services.threat_intel import check_lists

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    decision = None
    score = None
    explanation = None
    lists = None
    url = ""
    text = ""
    error = None

    if request.method == "POST":
        mode = request.form.get("mode")  # "url-only" / "text-only" / "both"
        url = request.form.get("url", "").strip()
        text = request.form.get("text", "").strip()

        if mode == "url-only" and not url:
            error = "URL is required for URL scan."
        elif mode == "text-only" and not text:
            error = "Text is required for text scan."
        elif mode == "both" and not (url and text):
            error = "Both URL and text are required for advanced scan."
        else:
            # Threat intel only when URL present
            if url:
                intel = check_lists(url)
            else:
                intel = {"blacklisted": False, "whitelisted": False, "sources": []}

            # Run model (you can later customize behavior based on mode if needed)
            result = classify(url, text)

            # Priority: blacklist > model
            if intel.get("blacklisted"):
                result["label"] = "phishing"
                result["score"] = 1.0
                result["explanation"] = (
                    result.get("explanation", "")
                    + " | Host is in static blacklist"
                )

            if intel.get("whitelisted") and result.get("label") == "phishing":
                result["explanation"] = result.get("explanation", "") + \
                    " | WARNING: model flagged whitelisted host"

            decision = result.get("label")
            score = result.get("score")
            explanation = result.get("explanation")
            lists = intel

    return render_template(
        "index.html",
        decision=decision,
        score=score,
        explanation=explanation,
        url=url,
        text=text,
        lists=lists,
        error=error,
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/scan-url", methods=["POST"])
def scan_url():
    """
    JSON API endpoint:
    {
      "url": "https://example.com",
      "text": "optional page/email text"
    }
    """
    data = request.get_json(force=True) or {}
    url = data.get("url", "")
    text = data.get("text", "")

    if not url:
        return jsonify({"error": "url is required"}), 400

    intel = check_lists(url)
    result = classify(url, text)

    # Priority: blacklist > model
    if intel.get("blacklisted"):
        result["label"] = "phishing"
        result["score"] = 1.0
        result["explanation"] = (
            result.get("explanation", "")
            + " | Host is in static blacklist"
        )

    if intel.get("whitelisted") and result.get("label") == "phishing":
        result["explanation"] = result.get("explanation", "") + \
            " | WARNING: model flagged whitelisted host"

    return jsonify({
        "url": url,
        "text_preview": text[:120],
        "decision": result.get("label"),
        "score": result.get("score"),
        "explanation": result.get("explanation"),
        "lists": intel,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)