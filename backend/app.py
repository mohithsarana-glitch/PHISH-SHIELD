import os
import re
import ssl
import socket
import datetime
import hashlib
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import tldextract
import whois

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

model = None
scaler = None

def load_ml_assets():
    global model, scaler
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            print("[OK] ML Model & Scaler loaded successfully.")
        except Exception as e:
            print(f"[WARN] Error loading ML models: {e}")

load_ml_assets()

HIGH_RISK_KEYWORDS = [
    "otp", "cvv", "verify", "login", "bank", "account", "secure",
    "update", "signin", "auth", "paypal", "free", "gift", "billing",
    "credential", "passcode", "security", "wallet", "crypto"
]

TOP_TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "wikipedia.org", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "linkedin.com", "reddit.com", "cloudflare.com", "stackoverflow.com",
    "bing.com", "openai.com", "yahoo.com", "duckduckgo.com"
]

def check_ip_hostname(hostname):
    """Check if the hostname is a raw IPv4 or IPv6 address."""
    if not hostname:
        return 0
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    if re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname):
        return 1
    return 0

def get_domain_age(domain_name):
    """Perform fast WHOIS query to determine domain age in days with strict timeout."""
    if not domain_name or check_ip_hostname(domain_name) or domain_name in ["localhost", "127.0.0.1", "local"]:
        return 3650
    dom_lower = domain_name.lower()
    if dom_lower in TOP_TRUSTED_DOMAINS:
        return 5000
    try:
        socket.setdefaulttimeout(1.5)
        w = whois.whois(domain_name)
        creation_date = getattr(w, "creation_date", None)
        if isinstance(creation_date, list) and len(creation_date) > 0:
            creation_date = creation_date[0]
        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.datetime.strptime(creation_date.split("T")[0], "%Y-%m-%d")
                except ValueError:
                    return 365
            now = datetime.datetime.now()
            age_days = (now - creation_date).days
            return max(0, age_days)
    except Exception:
        # Default fallback for unknown/unreachable domains (1 year)
        return 365
    return 365


def audit_ssl_certificate(hostname, scheme):
    """Audit SSL/TLS certificate validity using standard library ssl with 1.5s timeout."""
    if scheme != "https" or not hostname or check_ip_hostname(hostname) or hostname in ["localhost", "127.0.0.1"]:
        return 1 if scheme == "http" and hostname in ["localhost", "127.0.0.1"] else 0
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, 443), timeout=1.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return 0
                not_after = cert.get("notAfter")
                if not_after:
                    exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if exp_date < datetime.datetime.utcnow():
                        return 0 # Expired
                return 1
    except Exception:
        return 0

def extract_features(url):
    """Extract lexical, WHOIS, SSL, and keyword features from URL string."""
    raw = url.strip()
    if not raw.startswith("http://") and not raw.startswith("https://") and not raw.startswith("file://"):
        raw_url = "http://" + raw
    else:
        raw_url = raw

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.netloc.split(":")[0] if parsed.netloc else "").lower()
    
    # Handle file:// or local paths
    if scheme == "file":
        hostname = "local-file"
        path_and_query = parsed.path.lower()
    else:
        path_and_query = (parsed.path + "?" + parsed.query).lower()
    
    ext = tldextract.extract(raw_url)
    subdomains = ext.subdomain.split(".") if ext.subdomain else []
    registered_domain = ext.registered_domain or hostname or "local"
    
    url_length = len(raw_url)
    num_subdomains = len(subdomains) if subdomains != [""] else 0
    has_at_symbol = 1 if "@" in raw_url else 0
    num_hyphens = raw_url.count("-")
    is_ip = check_ip_hostname(hostname)
    
    keyword_count = sum(1 for kw in HIGH_RISK_KEYWORDS if kw in path_and_query or kw in hostname)
    num_digits = sum(c.isdigit() for c in raw_url)
    
    domain_age_days = get_domain_age(registered_domain)
    ssl_valid = audit_ssl_certificate(hostname, scheme)
    
    features_vector = [
        url_length,
        num_subdomains,
        has_at_symbol,
        num_hyphens,
        is_ip,
        keyword_count,
        domain_age_days,
        ssl_valid,
        num_digits
    ]
    
    details = {
        "url_length": url_length,
        "num_subdomains": num_subdomains,
        "has_at_symbol": bool(has_at_symbol),
        "num_hyphens": num_hyphens,
        "is_ip_address": bool(is_ip),
        "keyword_count": keyword_count,
        "domain_age_days": domain_age_days,
        "ssl_valid": bool(ssl_valid),
        "num_digits": num_digits,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "scheme": scheme
    }
    
    return features_vector, details

def calculate_heuristic_fallback(features_vector, details):
    """Fallback scoring system when ML model is reloading or offline."""
    if details["scheme"] == "file" or details["hostname"] in ["localhost", "127.0.0.1"]:
        return 0.0

    score = 5.0
    if details["is_ip_address"]:
        score += 45.0
    if details["has_at_symbol"]:
        score += 25.0
    if details["num_subdomains"] > 3:
        score += 20.0
    if details["num_hyphens"] > 3:
        score += 15.0
    if details["keyword_count"] > 0:
        score += min(details["keyword_count"] * 12.0, 35.0)
    if details["domain_age_days"] < 30 and details["domain_age_days"] >= 0:
        score += 20.0
    if not details["ssl_valid"] and details["scheme"] == "https":
        score += 25.0
    if details["url_length"] > 75:
        score += 15.0
    return min(100.0, max(0.0, score))

@app.route("/", methods=["GET"])
def home_dashboard():
    model_status = "ONLINE (RandomForestClassifier)" if model is not None else "OFFLINE"
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>CYBERPUNK PHISH-SHIELD BACKEND GRID</title>
      <style>
        body {{ background: #080811; color: #00f3ff; font-family: 'Courier New', monospace; padding: 40px; text-align: center; }}
        .box {{ border: 2px solid #00f3ff; padding: 30px; max-width: 650px; margin: 0 auto; box-shadow: 0 0 20px rgba(0,243,255,0.4); background: rgba(10,10,20,0.9); }}
        h1 {{ color: #ff0055; text-shadow: 0 0 10px #ff0055; margin-bottom: 5px; }}
        p {{ color: #a0c0d0; margin-bottom: 20px; }}
        .status {{ display: inline-block; padding: 8px 16px; background: rgba(0,255,136,0.15); border: 1px solid #00ff88; color: #00ff88; font-weight: bold; margin-bottom: 20px; }}
        .endpoint {{ background: #101424; border-left: 3px solid #00f3ff; text-align: left; padding: 10px 15px; margin: 10px 0; color: #fff; }}
        a {{ color: #00f3ff; text-decoration: none; font-weight: bold; }}
        a:hover {{ text-shadow: 0 0 8px #00f3ff; }}
      </style>
    </head>
    <body>
      <div class="box">
        <h1>⚡ CYBERPUNK PHISH-SHIELD</h1>
        <p>AI Phishing URL Detector — Microservice REST API Backend</p>
        <div class="status">GRID STATUS: ONLINE | ML MODEL: {model_status}</div>
        
        <div class="endpoint">
          <strong>GET /api/health</strong> - System diagnostic status<br>
          <a href="/api/health" target="_blank">> Test /api/health</a>
        </div>

        <div class="endpoint">
          <strong>POST /api/analyze</strong> - URL Feature Extraction & Risk Scoring<br>
          <code>Payload: {{"url": "https://example.com"}}</code>
        </div>

        <div class="endpoint">
          <strong>POST /api/report</strong> - Crowdsourced Threat Logger<br>
          <code>Payload: {{"url": "https://example.com", "reason": "Phishing"}}</code>
        </div>
      </div>
    </body>
    </html>
    """

@app.route("/api/health", methods=["GET"])
def health_check():

    return jsonify({
        "status": "online",
        "service": "CYBERPUNK PHISH-SHIELD REST API",
        "model_loaded": model is not None and scaler is not None,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/analyze", methods=["POST"])
def analyze_url():
    data = request.get_json() or {}
    raw_url = data.get("url", "").strip()
    
    if not raw_url:
        return jsonify({"error": "Missing URL parameter"}), 400

    # Whitelist system/internal/file pages
    if raw_url.startswith("chrome://") or raw_url.startswith("chrome-extension://") or raw_url.startswith("edge://") or raw_url.startswith("about:"):
        return jsonify({
            "url": raw_url,
            "risk_score": 0.0,
            "status": "SAFE",
            "verdict": "SYSTEM_PAGE_PROTECTED",
            "checklist": [
                {"name": "Browser Core", "status": "PASS", "value": "Internal Protected Component"}
            ],
            "details": {"hostname": "browser-internal"}
        })

    domain_hash = hashlib.sha256(raw_url.encode("utf-8")).hexdigest()
    features_vector, details = extract_features(raw_url)
    
    global model, scaler
    if model is None or scaler is None:
        load_ml_assets()
        
    if model is not None and scaler is not None:
        try:
            scaled_vec = scaler.transform([features_vector])
            probabilities = model.predict_proba(scaled_vec)[0]
            risk_score = round(float(probabilities[1]) * 100, 2)
        except Exception as e:
            print(f"[WARN] Inference error: {e}")
            risk_score = calculate_heuristic_fallback(features_vector, details)
    else:
        risk_score = calculate_heuristic_fallback(features_vector, details)

    # Override for localhost / internal file
    if details["hostname"] in ["localhost", "127.0.0.1", "local-file"]:
        risk_score = 0.0

    if risk_score >= 75.0:
        status = "DANGER"
        verdict = "PHISHING_THREAT_DETECTED"
    elif risk_score >= 40.0:
        status = "WARN"
        verdict = "SUSPICIOUS_ANOMALY"
    else:
        status = "SAFE"
        verdict = "VERIFIED_SECURE"

    checklist = [
        {"name": "Lexical Analysis", "status": "FAIL" if (details["url_length"] > 70 or details["num_subdomains"] > 3 or details["has_at_symbol"]) else "PASS", "value": f"Length: {details['url_length']}, Subdomains: {details['num_subdomains']}"},
        {"name": "IP Address Host", "status": "FAIL" if details["is_ip_address"] else "PASS", "value": "IP Host Detected" if details["is_ip_address"] else "Standard Domain"},
        {"name": "SSL/TLS Security", "status": "PASS" if details["ssl_valid"] else "FAIL", "value": "Valid TLS Certificate" if details["ssl_valid"] else "Invalid / Missing Certificate"},
        {"name": "Domain Metadata", "status": "WARN" if (details["domain_age_days"] < 30) else "PASS", "value": f"{details['domain_age_days']} Days Old"},
        {"name": "Urgency Tokens", "status": "FAIL" if details["keyword_count"] > 0 else "PASS", "value": f"{details['keyword_count']} Flagged Keywords"}
    ]

    return jsonify({
        "url": raw_url,
        "domain_hash": domain_hash[:16],
        "risk_score": risk_score,
        "status": status,
        "verdict": verdict,
        "checklist": checklist,
        "details": details,
        "analysis_timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/report", methods=["POST"])
def report_phish():
    data = request.get_json() or {}
    url = data.get("url", "")
    reason = data.get("reason", "User submitted threat report")
    client_score = data.get("client_score", 0)
    
    if not url:
        return jsonify({"error": "Missing URL parameter"}), 400
        
    print(f"[REPORT] URL: {url} | Reason: {reason} | Score: {client_score}")
    
    return jsonify({
        "status": "success",
        "message": "Crowdsourced threat submission recorded in security log.",
        "url": url,
        "report_id": hashlib.md5((url + str(datetime.datetime.utcnow())).encode("utf-8")).hexdigest()[:10]
    })

if __name__ == "__main__":
    print("[START] [CYBERPUNK PHISH-SHIELD] Starting Flask REST API Backend on port 5000...")
    app.run(host="127.0.0.1", port=5000, debug=True)
