import requests
import time
from datetime import datetime

# ===== TELEGRAM CONFIG =====
BOT_TOKEN = "8504282656:AAEDenT3_dJSiL3zUJAVG3K4o7jggDgI5jE"
CHAT_ID = "5898979798"

# ===== ALERT CONTROL =====
ALERT_COOLDOWN = 60  # giây

# Lưu thời gian alert cuối theo BSSID
last_alert_time = {}

def send_telegram_alert(ssid, bssid, vendor, reason, signal=None):
    """
    Gửi cảnh báo Rogue AP về Telegram
    Có chống spam theo BSSID
    """

    now = time.time()

    # =========================
    # Anti Spam Cooldown
    # =========================
    if bssid in last_alert_time:
        elapsed = now - last_alert_time[bssid]

        if elapsed < ALERT_COOLDOWN:
            print(f"[SKIP] Cooldown active for {bssid}")
            return

    # cập nhật thời gian alert
    last_alert_time[bssid] = now

    # =========================
    # Build Message
    # =========================
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = f"""
🚨 *ROGUE ACCESS POINT DETECTED* 🚨

📶 SSID: `{ssid}`
🔗 BSSID: `{bssid}`
🏢 Vendor: `{vendor}`
📡 Signal: `{signal} dBm`
⚠️ Reason: `{reason}`

🕒 Time: `{time_now}`
"""

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, data=payload, timeout=5)

        if response.status_code == 200:
            print(f"[+] Telegram alert sent for {bssid}")
        else:
            print("[-] Telegram error:", response.text)

    except Exception as e:
        print("[-] Failed to send Telegram alert:", e)