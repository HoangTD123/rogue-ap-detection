# deauth.py

import os
import time
import queue
import threading
from datetime import datetime
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import config
import state
from utils import append_alert

class DeauthEngine:
    def __init__(self, iface: str):
        self.iface        = iface
        self.cooldown_map = {}
        self.channel_lock = threading.Lock()
        self.current_ch   = 0
        self._thread      = threading.Thread(target=self._worker, daemon=True)

    def start(self):
        self._thread.start()

    def _set_channel(self, ch: int):
        if ch == self.current_ch or ch == 0: return
        os.system(f"iwconfig {self.iface} channel {ch} > /dev/null 2>&1")
        time.sleep(0.15)
        self.current_ch = ch

    @staticmethod
    def _make_deauth(src: str, dst: str, bssid: str, reason: int = 7) -> bytes:
        return RadioTap()/Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=bssid)/Dot11Deauth(reason=reason)

    def _do_deauth(self, bssid: str, channel: int, ssid: str):
        BROADCAST = "FF:FF:FF:FF:FF:FF"
        packets = [
            self._make_deauth(src=bssid, dst=BROADCAST, bssid=bssid),
            self._make_deauth(src=BROADCAST, dst=bssid, bssid=bssid)
        ]
        with self.channel_lock:
            self._set_channel(channel)
            try:
                for _ in range(config.DEAUTH_COUNT):
                    if state.stop_event.is_set(): break
                    for pkt in packets: 
                        sendp(pkt, iface=self.iface, verbose=False, inter=config.DEAUTH_INTERVAL)
            except: pass

        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
            "action": "DEAUTH", 
            "bssid": bssid, 
            "ssid": ssid, 
            "channel": channel, 
            "packets": config.DEAUTH_COUNT * 2
        }
        state.prevention_log.append(entry)
        append_alert({**entry, "type": "PREVENTION"})
        
        with state.lock:
            if bssid in state.seen: 
                state.seen[bssid]["deauth_count"] = state.seen[bssid].get("deauth_count", 0) + config.DEAUTH_COUNT * 2

    def _worker(self):
        while not state.stop_event.is_set():
            try: 
                item = state.deauth_queue.get(timeout=1.0)
            except queue.Empty: 
                continue
            
            if not config.PREVENTION_ENABLED:
                state.deauth_queue.task_done()
                continue
                
            bssid, channel, ssid = item["bssid"], item.get("channel", 0), item.get("ssid", "")
            now = time.time()
            if now - self.cooldown_map.get(bssid, 0) >= config.DEAUTH_COOLDOWN:
                self.cooldown_map[bssid] = now
                self._do_deauth(bssid, channel, ssid)
            state.deauth_queue.task_done()