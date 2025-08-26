import json, time, joblib, datetime, csv, os
from pathlib import Path

# --- Paths ---
BASE = Path.home() / "mlips_project"
MODELS_DIR = BASE / "models"
OUT_DIR = BASE / "output"
OUT_DIR.mkdir(parents=True, exist_ok=True)
EVE = "/var/log/suricata/eve.json"

MODEL_PATH = MODELS_DIR / "LinearSVC.joblib"
VEC_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"

model = joblib.load(MODEL_PATH)
vec = joblib.load(VEC_PATH)

ALERTS_CSV = OUT_DIR / "alerts.csv"
if not ALERTS_CSV.exists():
    ALERTS_CSV.write_text("timestamp,event_type,src_ip,dst_ip,url_or_signature,prediction,blocked\n")

# Keep track of already blocked IPs
blocked_ips = set()

# Event types to process
RELEVANT_TYPES = ["http", "alert"]

with open(EVE, 'r') as f:
    f.seek(0, 2)  # go to end
    while True:
        line = f.readline()
        if not line:
            time.sleep(0)
            continue
        try:
            e = json.loads(line)
        except:
            continue

        event_type = e.get("event_type")
        if event_type not in RELEVANT_TYPES:
            continue

        ts = e.get("timestamp", datetime.datetime.utcnow().isoformat())

        # --- HTTP Event ---
        if event_type == "http":
            http = e.get("http", {})
            url = http.get("url") or http.get("request_uri") or ""
            src = e.get("src_ip") or ""
            dst = e.get("dest_ip") or ""
            if not url or not src:
                continue

            # ML prediction
            X = vec.transform([url])
            pred = model.predict(X)[0]

            # Keyword-based XSS detection
            xss_keywords = ["<script>", "xss_r", "onerror", "onload"]
            if any(k.lower() in url.lower() for k in xss_keywords):
                pred = "XSS"

        # --- Suricata Alert Event ---
        elif event_type == "alert":
            alert = e.get("alert", {})
            signature = alert.get("signature") or ""
            src = e.get("src_ip") or e.get("src_ip") or ""
            dst = e.get("dest_ip") or ""
            if not signature or not src:
                continue
            if "xss_r" in signature.lower():
                pred = "XSS"
            else:
                pred = "SURICATA"

        # --- Blocking Logic ---
        blocked = "NO"
        if pred != "BENIGN" and src not in blocked_ips:
            os.system(f"sudo iptables -I INPUT -s {src} -j DROP")
            blocked_ips.add(src)
            blocked = "YES"
            print(f"{ts} [BLOCKED] {pred} from {src} -> {dst}")

        # --- Write to CSV ---
        with open(ALERTS_CSV, "a", newline="") as out:
            writer = csv.writer(out)
            writer.writerow([ts, event_type, src, dst, url if event_type=="http" else signature, pred, blocked]) 
