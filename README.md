# 🚨 Rogue AP Detector - Beacon Frame Fingerprinting

**Hệ thống phát hiện và ngăn chặn Rogue Access Point dựa trên Beacon Frame Fingerprinting + Risk Scoring**

Phiên bản: **2.4**  
Ngôn ngữ: Python + Scapy + Streamlit

---

## ✨ Giới thiệu

Hệ thống sử dụng kỹ thuật **Beacon Frame Fingerprinting** để học đặc trưng của Access Point hợp pháp và phát hiện Rogue AP (Evil Twin). Hệ thống có khả năng tự động ngăn chặn bằng Deauth Attack và gửi cảnh báo qua **Telegram**.

**Phù hợp cho đồ án tốt nghiệp** với đề tài:  s
**"Nghiên cứu và xây dựng mô hình phát hiện Rogue Access Point dựa trên phân tích Beacon Frame và Fingerprinting"**

---

## 🚀 Tính năng nổi bật

- Học fingerprint AP hợp pháp (Learning Mode)
- Tính **Risk Score** (0-100) cho từng AP
- Tự động phát hiện Rogue AP (SSID thay đổi, Channel hopping, Evil Twin...)
- Ngăn chặn bằng **Deauth Attack**
- Gửi cảnh báo realtime qua **Telegram**
- Giao diện web đẹp bằng **Streamlit Dashboard**
- Export dữ liệu CSV / JSON

---

## 📁 Cấu trúc dự án
rogue-detection/
├── app.py                  # Dashboard Streamlit
├── main.py                 # Beacon Sniffer chính
├── config.py               # Cấu hình chế độ chạy
├── analyzer.py             # Phân tích & tính Risk Score
├── deauth.py               # Module Deauth Attack
├── utils.py
├── state.py
├── telegram_alert.py       # Gửi cảnh báo Telegram
├── known_fingerprints.json # Database fingerprint đã học
├── rogue_dataset.csv       # Dữ liệu AP thu thập
├── rogue_alerts.log        # Log cảnh báo
├── oui.txt
└── README.md
text---

## 🛠️ Cài đặt môi trường

### 1. Clone dự án
```bash
cd ~
git clone <link-repo-cua-ban>
cd rogue-detection
2. Tạo Virtual Environment (chỉ làm 1 lần)
Bashpython3 -m venv ~/rogue-detection-env
3. Activate môi trường (PHẢI LÀM MỖI LẦN MỞ TERMINAL)
Bashcd ~/rogue-detection
source ~/rogue-detection-env/bin/activate
4. Cài thư viện
Bashpip install --upgrade pip
pip install streamlit pandas scapy numpy requests

⚙️ Cấu hình Telegram Alert
Bước 1: Tạo Bot Telegram

Mở Telegram tìm @BotFather
Gõ /newbot
Đặt tên bot và username
Sao chép Token (ví dụ: 8504282656:AAEDenT3_dJSiL3zUJAVG3K4o7jggDgI5jE)

Bước 2: Lấy Chat ID

Gửi tin nhắn bất kỳ cho bot vừa tạo
Truy cập link sau (thay TOKEN bằng token của bạn):texthttps://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
Tìm "chat":{"id":...} → sao chép số đó làm CHAT_ID

Bước 3: Cấu hình trong code
Mở file telegram_alert.py và sửa:
PythonBOT_TOKEN = "8504282656:AAEDenT3_dJSiL3zUJAVG3K4o7jggDgI5jE"   # Token của bạn
CHAT_ID   = "5898979798"                                       # Chat ID của bạn

📖 Hướng dẫn sử dụng
🔄 Quy trình chạy chuẩn (Khuyến nghị)
Mỗi lần mở Terminal mới:
Bashcd ~/rogue-detection
source ~/rogue-detection-env/bin/activate
Chuyển đổi chế độ WiFi
1. Chế độ Dashboard (có mạng internet):
Bashsudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
2. Chế độ Monitor (quét Rogue AP):
Bashsudo airmon-ng check kill
sudo airmon-ng start wlan0
iwconfig

Các bước chạy hệ thống
Bước 1: Learning Mode (Học AP hợp pháp)
Bash# Sửa config.py: MODE = "learning"
sudo python main.py
→ Để tool quét và học các AP xung quanh một lúc.
Bước 2: Detection + Prevention
Bash# Sửa config.py:
# MODE = "detection"
# PREVENTION_ENABLED = True
sudo python main.py
Bước 3: Mở Dashboard (Terminal khác)
Bashstreamlit run app.py

📊 Giao diện Streamlit
Các tab chính:

Tổng quan → Metrics + Cảnh báo gần nhất
Danh sách AP → Bảng lọc + Risk Score
Phân tích điểm rủi ro → Biểu đồ, Top Rogue AP
Cảnh báo Rogue
Log Ngăn chặn
Database đã học


🧪 Cách Test Rogue AP

Bật Monitor Mode
Chạy sudo python main.py
Dùng điện thoại tạo Hotspot với SSID giống hệt một AP hợp pháp
Quan sát:
Terminal hiển thị [ROGUE]
Dashboard highlight màu đỏ
Nhận thông báo Telegram
Hệ thống tự gửi Deauth



🔍 Xem log & dữ liệu
Bash# Xem database fingerprint
python -m json.tool known_fingerprints.json

# Xem log cảnh báo
cat rogue_alerts.log

# Xem dữ liệu AP đẹp
python -c "
import pandas as pd
df = pd.read_csv('rogue_dataset.csv')
print(df.to_string())
"

⚠️ Lưu ý quan trọng

Phải chạy với quyền root (sudo)
Card WiFi phải hỗ trợ Monitor Mode
Telegram chỉ gửi khi phát hiện Rogue AP mới
Khi chạy Prevention nên dùng card WiFi mạnh
Tắt Monitor Mode trước khi chạy Streamlit để có mạng


🛠️ Troubleshooting

Không thấy wlan0mon: Chạy lại lệnh bật Monitor Mode
Telegram không nhận tin: Kiểm tra BOT_TOKEN và CHAT_ID
Venv lỗi: Xóa thư mục ~/rogue-detection-env và tạo lại
Scapy không sniff: Đảm bảo interface đang ở mode Monitor


📈 Hướng phát triển

Tích hợp Machine Learning (Isolation Forest)
Hỗ trợ băng tần 5GHz
Báo cáo PDF tự động
Docker hóa ứng dụng
