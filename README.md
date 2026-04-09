# AI Phishing Detection System

A simple Flask web app that scans suspicious URLs and message text for phishing indicators using rule-based heuristics and static threat intelligence.

## Features

- URL scan with suspicious TLD, IP address, HTTPS, hyphens, and dot checks
- Text scan for phishing keywords like `urgent`, `verify`, and `password`
- Advanced scan mode combining URL and message analysis
- Static blacklist and whitelist threat intelligence
- Clean Bootstrap-based UI for presentations

## Run locally

1. Install dependencies:

```sh
python -m pip install -r requirements.txt
```

2. Start the app:

```sh
python app.py
```

3. Open in browser:

```
http://127.0.0.1:8000
```

## Run tests

```sh
python -m unittest tests.test_api -v
```

## Project structure

- `app.py` — Flask web server and API
- `templates/index.html` — UI template
- `model/classifier.py` — scoring and classification logic
- `model/features.py` — URL and text feature extraction
- `services/threat_intel.py` — blacklist/whitelist host checks
- `tests/test_api.py` — Unit tests for app and model
