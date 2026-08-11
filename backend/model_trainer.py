import os
import random
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

FEATURE_NAMES = [
    "url_length",
    "num_subdomains",
    "has_at_symbol",
    "num_hyphens",
    "is_ip",
    "keyword_count",
    "domain_age_days",
    "ssl_valid",
    "num_digits"
]

HIGH_RISK_KEYWORDS = ["otp", "cvv", "verify", "login", "bank", "account", "secure", "update", "signin", "auth", "paypal", "free", "gift"]

def generate_legitimate_sample():
    """Generate synthetic features representing a legitimate URL."""
    url_length = random.randint(12, 45)
    num_subdomains = random.choice([0, 1, 1, 2])
    has_at_symbol = 0
    num_hyphens = random.choice([0, 0, 1, 1, 2])
    is_ip = 0
    keyword_count = random.choice([0, 0, 0, 1])
    domain_age_days = random.randint(365, 5000)
    ssl_valid = random.choice([1, 1, 1, 1, 1, 0])
    num_digits = random.randint(0, 5)
    return [url_length, num_subdomains, has_at_symbol, num_hyphens, is_ip, keyword_count, domain_age_days, ssl_valid, num_digits], 0

def generate_phishing_sample():
    """Generate synthetic features representing a phishing URL."""
    url_length = random.randint(40, 140)
    num_subdomains = random.choice([2, 3, 4, 5, 6])
    has_at_symbol = random.choice([0, 1, 1])
    num_hyphens = random.randint(2, 8)
    is_ip = random.choice([0, 0, 1, 1])
    keyword_count = random.randint(1, 5)
    domain_age_days = random.choice([1, 5, 12, 25, 45, -1])
    ssl_valid = random.choice([0, 0, 0, 1])
    num_digits = random.randint(4, 25)
    return [url_length, num_subdomains, has_at_symbol, num_hyphens, is_ip, keyword_count, domain_age_days, ssl_valid, num_digits], 1

def main():
    print("[INFO] [CYBERPUNK PHISH-SHIELD] Training ML Classifier...")
    np.random.seed(42)
    random.seed(42)
    
    X = []
    y = []
    
    # 1500 Legitimate + 1500 Phishing
    for _ in range(1500):
        feat, label = generate_legitimate_sample()
        X.append(feat)
        y.append(label)
        
    for _ in range(1500):
        feat, label = generate_phishing_sample()
        X.append(feat)
        y.append(label)
        
    X = np.array(X)
    y = np.array(y)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    model = RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"[OK] Model Training Complete. Test Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(backend_dir, "phishing_model.pkl")
    scaler_path = os.path.join(backend_dir, "scaler.pkl")
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"[SAVE] Model saved to: {model_path}")
    print(f"[SAVE] Scaler saved to: {scaler_path}")

if __name__ == "__main__":
    main()

