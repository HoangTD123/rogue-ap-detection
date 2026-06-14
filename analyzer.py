# analyzer.py

import hashlib
from datetime import datetime
from scapy.all import Dot11, Dot11Beacon, Dot11Elt
import config
import state
from utils import get_vendor

def extract_features(pkt):
    try:
        bssid = pkt[Dot11].addr2
        if not bssid: return None
        bssid = bssid.upper()

        ssid_raw  = pkt[Dot11Elt].info if pkt.haslayer(Dot11Elt) else b""
        ssid      = ssid_raw.decode("utf-8", errors="ignore").strip()
        is_hidden = (ssid == "")

        beacon_interval = int(getattr(pkt[Dot11Beacon], "beacon_interval", 0))
        cap_raw         = int(getattr(pkt[Dot11Beacon], "cap", 0))
        cap_str         = pkt.sprintf("%Dot11Beacon.cap%")

        rssi = int(pkt.dBm_AntSignal) if hasattr(pkt, "dBm_AntSignal") else -100

        channel = 0
        ht_cap = False
        ie_tags = []
        
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            ie_tags.append(str(elt.ID))
            if elt.ID == 3 and len(elt.info) >= 1:
                channel = int(elt.info[0])
            elif elt.ID == 45:
                ht_cap = True
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        ie_hash = hashlib.md5("-".join(ie_tags).encode()).hexdigest()[:10]

        return {
            "bssid":           bssid,
            "ssid":            ssid,
            "is_hidden":       is_hidden,
            "channel":         channel,
            "rssi":            rssi,
            "beacon_interval": beacon_interval,
            "cap_raw":         cap_raw,
            "cap_str":         cap_str,
            "ht_cap":          ht_cap,
            "ie_hash":         ie_hash,
            "vendor":          get_vendor(bssid),
            "last_seen":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception:
        return None

def build_fingerprint(feat):
    return {
        "ssid":            feat["ssid"],
        "oui":             feat["bssid"].replace(":", "")[:6].upper(),
        "channel":         feat["channel"],
        "beacon_interval": feat["beacon_interval"],
        "cap_raw":         feat["cap_raw"],
        "ht_cap":          feat["ht_cap"],
        "ie_hash":         feat["ie_hash"],
        "vendor":          feat["vendor"],
        "is_hidden":       feat["is_hidden"],
        "timestamp":       feat["last_seen"],
    }

def classify(bssid, feat):
    ssid = feat.get("ssid", "")
    risk_score = 0
    anomalies = []

    if bssid in state.known_fingerprints:
        k = state.known_fingerprints[bssid]

        if k.get("channel") and feat["channel"] and feat["channel"] != k["channel"]:
            risk_score += 10
            anomalies.append("CHANNEL_HOPPING")

        if k.get("beacon_interval") and feat["beacon_interval"]:
            if abs(feat["beacon_interval"] - k["beacon_interval"]) > config.BEACON_INTERVAL_TOLERANCE:
                risk_score += 20
                anomalies.append("INTERVAL_ANOMALY")

        PRIVACY_BIT = 0x0010
        curr_priv = feat.get("cap_raw", 0) & PRIVACY_BIT
        known_priv = k.get("cap_raw", 0) & PRIVACY_BIT
        if curr_priv != known_priv:
            risk_score += 80
            anomalies.append("SECURITY_FLAG_ALTERED")

        if k.get("ie_hash") and feat.get("ie_hash") != k["ie_hash"]:
            risk_score += 100
            anomalies.append("OS_FINGERPRINT_MISMATCH")

    elif ssid and ssid in [ap.get("ssid") for ap in state.known_fingerprints.values()]:
        corp_ouis = set()
        corp_prefixes = set()
        for kbssid, kap in state.known_fingerprints.items():
            if kap.get("ssid") == ssid:
                corp_ouis.add(kap.get("oui", ""))
                corp_prefixes.add(kbssid[:14])

        curr_oui_hex = bssid.replace(":", "")[:6].upper()
        curr_prefix = bssid[:14]

        if curr_prefix in corp_prefixes:
            pass
        elif curr_oui_hex not in corp_ouis:
            risk_score += 100
            anomalies.append("EVIL_TWIN_VENDOR_MISMATCH")
        else:
            risk_score += 40
            anomalies.append("UNVERIFIED_AP_SAME_SSID")

    feat["risk_score"] = risk_score
    
    if risk_score >= config.RISK_THRESHOLD:
        return f"ROGUE: {','.join(anomalies)}"
    elif risk_score > 0:
        return f"WARNING: {','.join(anomalies)}"
    else:
        return "LEGIT" if bssid in state.known_fingerprints else "UNKNOWN"