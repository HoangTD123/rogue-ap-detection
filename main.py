#!/usr/bin/env python3
# main.py

import os
import sys
import time
import threading
from datetime import datetime
from scapy.all import sniff, Dot11Beacon

import config
import state
from utils import load_oui_file, load_db, save_db, save_csv, append_alert
from analyzer import extract_features, build_fingerprint, classify
from deauth import DeauthEngine

# Đảm bảo bạn đã có file telegram_alert.py cùng thư mục
from telegram_alert import send_telegram_alert 

deauth_engine = None

def packet_handler(pkt):
    if not pkt.haslayer(Dot11Beacon): return

    feat = extract_features(pkt)
    if not feat: return
    bssid = feat["bssid"]

    with state.lock:
        feat["frame_count"] = state.seen[bssid].get("frame_count", 0) + 1
        state.seen[bssid].update(feat)

    if config.MODE == "learning":
        if bssid not in state.known_fingerprints:
            state.known_fingerprints[bssid] = build_fingerprint(feat)
            save_db()
            print(f"  [HOC] {(feat['ssid'] or '<Hidden>'):<25} | {bssid} | Ch:{feat['channel']:>2} | {feat['vendor']}")

        elif config.MODE == "detection":
        result = classify(bssid, feat)
        with state.lock:
            prev_status = state.seen[bssid].get("status", "")
            prev_alert_time = state.seen[bssid].get("alert_time", 0)
            state.seen[bssid]["status"] = result

        if result.startswith("ROGUE"):
            now = time.time()
            if not prev_status.startswith("ROGUE") or (now - prev_alert_time) > 30:
                entry = {
                    "time": feat["last_seen"], 
                    "bssid": bssid, 
                    "ssid": feat["ssid"], 
                    "channel": feat["channel"], 
                    "rssi": feat["rssi"], 
                    "reason": result, 
                    "risk_score": feat.get("risk_score")
                }
                state.alert_log.append(entry)
                append_alert(entry)
                
                # TELEGRAM ALERT
                send_telegram_alert(
                    ssid=feat["ssid"],
                    bssid=bssid,
                    vendor=feat["vendor"],
                    reason=result,
                    signal=feat["rssi"]
                )
                
                with state.lock: 
                    state.seen[bssid]["alert_time"] = now

            if config.PREVENTION_ENABLED and deauth_engine:
                state.deauth_queue.put({"bssid": bssid, "channel": feat.get("channel", 0), "ssid": feat.get("ssid", ""), "reason": result})

    if time.time() - state.last_save_time > config.AUTO_SAVE_INTERVAL:
        save_csv()
        state.last_save_time = time.time()

def hop_channel():
    channels = list(range(1, 14))
    while not state.stop_event.is_set():
        for ch in channels:
            if state.stop_event.is_set(): break
            if deauth_engine:
                with deauth_engine.channel_lock:
                    os.system(f"iwconfig {config.IFACE} channel {ch} > /dev/null 2>&1")
                    if deauth_engine.current_ch == 0: deauth_engine.current_ch = ch
            else: 
                os.system(f"iwconfig {config.IFACE} channel {ch} > /dev/null 2>&1")
            time.sleep(0.8)

def print_table():
    W = {"st": 28, "ssid": 20, "bssid": 19, "ch": 4, "rs": 5, "rssi": 5, "vendor": 12, "da": 6}
    header = f"{'Status':<{W['st']}} {'SSID':<{W['ssid']}} {'BSSID':<{W['bssid']}} {'Ch':>{W['ch']}} {'Rsk':>{W['rs']}} {'dBm':>{W['rssi']}} {'Vendor':<{W['vendor']}} {'Deauth':>{W['da']}}"
    
    while not state.stop_event.is_set():
        os.system("clear")
        now = datetime.now().strftime("%H:%M:%S")
        with state.lock: 
            snap = dict(state.seen)
        
        rogue_n = sum(1 for v in snap.values() if str(v.get("status", "")).startswith("ROGUE"))
        
        print("=" * 110)
        print(f"  ENTERPRISE WIPS ENGINE  |  Mode: {config.MODE.upper()}  |  {now}  |  Threshold: {config.RISK_THRESHOLD} pts")
        print("=" * 110)
        print(header)
        print("-" * len(header))

        items = sorted(snap.items(), key=lambda x: (
            0 if str(x[1].get("status", "")).startswith("ROGUE") else 1,
            -(x[1].get("risk_score") or 0),
            -(x[1].get("rssi") or -200)
        ))

        for bssid, d in items:
            st = d.get("status", "UNKNOWN")
            r_score = d.get("risk_score", 0)
            
            if config.MODE == "learning": label = "[DANG HOC]"
            elif st == "LEGIT": label = "[HOP PHAP]"
            elif st.startswith("ROGUE"): label = f"[ROGUE:{r_score}pt] [X]" if d.get("deauth_count", 0) > 0 else f"[ROGUE:{r_score}pt]"
            elif st.startswith("WARNING"): label = f"[WARN:{r_score}pt]"
            else: label = "[UNKNOWN]"

            print(
                f"{label:<{W['st']}} {(d.get('ssid') or '<Hidden>')[:W['ssid']]:<{W['ssid']}} "
                f"{bssid:<{W['bssid']}} {str(d.get('channel', '?')):>{W['ch']}} "
                f"{str(r_score):>{W['rs']}} {str(d.get('rssi', '?')):>{W['rssi']}} "
                f"{str(d.get('vendor', ''))[:W['vendor']]:<{W['vendor']}} "
                f"{str(d.get('deauth_count', 0)):>{W['da']}}"
            )
        
        time.sleep(2)

def main():
    global deauth_engine
    if os.geteuid() != 0: 
        print("[!] Vui long chay script voi quyen root (sudo).")
        sys.exit(1)
    
    load_oui_file()
    load_db()

    if config.MODE == "detection" and not state.known_fingerprints:
        print("\n[CANH BAO] Database trong! Doi MODE = 'learning' roi chay lai.\n")
        sys.exit(1)

    deauth_engine = DeauthEngine(config.IFACE)
    deauth_engine.start()

    threading.Thread(target=hop_channel, daemon=True).start()
    threading.Thread(target=print_table, daemon=True).start()

    try: 
        sniff(iface=config.IFACE, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        state.stop_event.set()
        save_db()
        save_csv()
        print("\n[INFO] Da dung chuong trinh va luu du lieu.")

if __name__ == "__main__":
    main()