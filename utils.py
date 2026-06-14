# utils.py

import os
import json
import pandas as pd
import config
import state

OUI_VENDOR = {}

class SafeEncoder(json.JSONEncoder):
    def default(self, obj):
        try: return int(obj)
        except: pass
        try: return str(obj)
        except: return None

def load_oui_file():
    global OUI_VENDOR
    if not os.path.exists(config.OUI_FILE):
        print(f"[OUI] Khong tim thay file database tai: {config.OUI_FILE}")
        return
    try:
        count = 0
        with open(config.OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        oui_key = parts[0].strip().replace("-", "").replace(":", "").upper()
                        vendor_name = parts[1].strip()
                        if len(oui_key) == 6 and vendor_name:
                            OUI_VENDOR[oui_key] = vendor_name
                            count += 1
        print(f"[OUI] Da nap thanh cong {count} thong tin OUI tu file database.")
    except Exception:
        pass

def get_vendor(bssid):
    oui = bssid.replace(":", "")[:6].upper()
    return OUI_VENDOR.get(oui, "Unknown")

def load_db():
    if os.path.exists(config.DB_FILE):
        with open(config.DB_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content:
                state.known_fingerprints = json.loads(content)
                print(f"[DB] Da load {len(state.known_fingerprints)} fingerprint.")

def save_db():
    tmp = config.DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state.known_fingerprints, f, indent=2, ensure_ascii=False, cls=SafeEncoder)
    os.replace(tmp, config.DB_FILE)

def save_csv():
    with state.lock: 
        snapshot = dict(state.seen)
    
    if not snapshot: return
    rows = []
    
    for bssid, d in snapshot.items():
        # Lấy status đã được lưu từ lúc phân tích, tránh import ngược classify()
        status = d.get("status", "LEARNING") if config.MODE == "detection" else "LEARNING"
        rows.append({
            "timestamp":       d.get("last_seen", ""),
            "bssid":           bssid,
            "ssid":            d.get("ssid", ""),
            "vendor":          d.get("vendor", ""),
            "channel":         d.get("channel", ""),
            "rssi":            d.get("rssi", ""),
            "beacon_interval": d.get("beacon_interval", ""),
            "cap_str":         d.get("cap_str", ""),
            "cap_raw":         d.get("cap_raw", ""),
            "ht_cap":          d.get("ht_cap", False),
            "ie_hash":         d.get("ie_hash", ""),
            "risk_score":      d.get("risk_score", 0),
            "is_hidden":       d.get("is_hidden", False),
            "frame_count":     d.get("frame_count", 0),
            "status":          status,
            "deauth_count":    d.get("deauth_count", 0),
        })
    try:
        pd.DataFrame(rows).to_csv(config.CSV_FILE, index=False, encoding="utf-8-sig")
    except: pass

def append_alert(entry):
    try:
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, cls=SafeEncoder) + "\n")
    except: pass