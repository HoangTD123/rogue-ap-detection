# config.py

MODE  = "detection"    # "learning" hoac "detection"
IFACE = "wlan1"

# --- Prevention (Ngan chan) ---
PREVENTION_ENABLED    = True
DEAUTH_COUNT          = 64
DEAUTH_INTERVAL       = 0.0
DEAUTH_COOLDOWN       = 20
DEAUTH_TARGET_CLIENTS = True

# --- Risk Scoring Engine ---
RISK_THRESHOLD = 80  # Tong diem >= 80 se bi xac dinh la ROGUE va ban Deauth

# --- File ---
DB_FILE  = "known_fingerprints.json"
CSV_FILE = "rogue_dataset.csv"
LOG_FILE = "rogue_alerts.log"
OUI_FILE = "oui.txt"

AUTO_SAVE_INTERVAL        = 15
BEACON_INTERVAL_TOLERANCE = 15