"""
=============================================================================
GIAO DIỆN WEB - HỆ THỐNG PHÁT HIỆN & NGĂN CHẶN ROGUE ACCESS POINT
Beacon Frame Fingerprinting Dashboard v2.4 (Added Learning Time Column)
=============================================================================
Cách chạy:
  1. Tắt Monitor Mode:  sudo airmon-ng stop wlan0mon
  2. Kết nối WiFi bình thường
  3. Activate venv:     source ~/rogue-detection-env/bin/activate
  4. Chạy app:          streamlit run app.py
=============================================================================
"""

import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
import time

# ─────────────────────────────────────────────
#  CẤU HÌNH TRANG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Rogue AP Detector",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .rogue-badge {
        background-color: #FCEBEB;
        color: #A32D2D;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
    }
    .legit-badge {
        background-color: #EAF3DE;
        color: #3B6D11;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
    }
    .unknown-badge {
        background-color: #F1EFE8;
        color: #5F5E5A;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
    }
    .blocked-badge {
        background-color: #FAEEDA;
        color: #633806;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 500;
    }
    .alert-box {
        background-color: #FCEBEB;
        border-left: 3px solid #A32D2D;
        padding: 10px 14px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 8px;
        font-size: 13px;
    }
    .prevention-box {
        background-color: #FAEEDA;
        border-left: 3px solid #BA7517;
        padding: 10px 14px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 8px;
        font-size: 13px;
    }
    div[data-testid="metric-container"] {
        background-color: var(--background-secondary);
        border: 0.5px solid rgba(0,0,0,0.08);
        border-radius: 10px;
        padding: 14px 18px;
    }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  CẤU HÌNH FILE
# ─────────────────────────────────────────────
DB_FILE  = "known_fingerprints.json"
CSV_FILE = "rogue_dataset.csv"
LOG_FILE = "rogue_alerts.log"


# ─────────────────────────────────────────────
#  LOAD / SAVE DỮ LIỆU
# ─────────────────────────────────────────────
@st.cache_data(ttl=5)
def load_known() -> dict:
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_known(data: dict) -> bool:
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        st.error(f"Lỗi khi lưu cấu hình database: {e}")
        return False


@st.cache_data(ttl=5)
def load_dataset() -> pd.DataFrame | None:
    if not os.path.exists(CSV_FILE):
        return None
    df = pd.read_csv(CSV_FILE)
    df.columns = [c.strip().lower() for c in df.columns]
    if "deauth_count" not in df.columns:
        df["deauth_count"] = 0
    return df


@st.cache_data(ttl=5)
def load_alerts() -> tuple[list, list]:
    detection  = []
    prevention = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "PREVENTION":
                        prevention.append(entry)
                    else:
                        detection.append(entry)
                except Exception: pass
    return detection, prevention


# ─────────────────────────────────────────────
#  PHÂN LOẠI AP
# ─────────────────────────────────────────────
def classify_row(row: pd.Series, known: dict) -> str:
    bssid   = str(row.get("bssid", "")).upper()
    ssid    = str(row.get("ssid", ""))
    channel = row.get("channel", 0)
    bi      = row.get("beacon_interval", 0)
    cap_raw = row.get("cap_raw", None)
    ht_cap  = row.get("ht_cap", None)

    if bssid in known:
        k = known[bssid]
        anomalies = []
        if k.get("ssid") and ssid != k["ssid"]: anomalies.append("SSID thay đổi")
        if k.get("channel") and channel and int(channel) != int(k["channel"]): anomalies.append("Channel thay đổi")
        if k.get("beacon_interval") and bi:
            if abs(int(bi) - int(k["beacon_interval"])) > 15: anomalies.append("Interval lệch")
        if cap_raw is not None and k.get("cap_raw") is not None:
            if str(cap_raw) != str(k["cap_raw"]): anomalies.append("Cap thay đổi")
        if ht_cap is not None and k.get("ht_cap") is not None:
            if str(ht_cap) != str(k["ht_cap"]): anomalies.append("HT Cap thay đổi")
        return ("ROGUE: " + ", ".join(anomalies)) if anomalies else "LEGIT"

    for _, kfp in known.items():
        if kfp.get("ssid") == ssid and ssid != "": return "ROGUE: Evil Twin"
    return "UNKNOWN"


def status_label(status: str) -> str:
    if status == "LEGIT": return "✅ Hợp pháp"
    elif status.startswith("ROGUE"):
        reason = status.split(":", 1)[-1].strip() if ":" in status else ""
        return f"🔴 Rogue — {reason}" if reason else "🔴 Rogue AP"
    return "⚪ Chưa xác định"


# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🚨 Rogue AP Detector")
    st.caption("Beacon Frame Fingerprinting v2.0")
    st.divider()

    view = st.radio(
        "Chế độ xem:",
        ["Tổng quan", "Danh sách AP", "Cảnh báo Rogue", "Log Ngăn chặn", "Database đã học"],
        label_visibility="collapsed",
    )

    st.divider()
    auto_refresh = st.toggle("Tự động làm mới (5s)", value=False)
    if st.button("🔄 Làm mới ngay", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# ─────────────────────────────────────────────
#  LOAD DỮ LIỆU CHÍNH
# ─────────────────────────────────────────────
known                    = load_known()
df_raw                   = load_dataset()
alerts, prevention_logs  = load_alerts()

if auto_refresh:
    time.sleep(5)
    st.cache_data.clear()
    st.rerun()


# ─────────────────────────────────────────────
#  XỬ LÝ DATAFRAME
# ─────────────────────────────────────────────
if df_raw is not None and not df_raw.empty:
    df = df_raw.copy()
    df["status_calc"] = df.apply(lambda r: classify_row(r, known), axis=1)
    df["Trạng thái"]  = df["status_calc"].apply(status_label)
    df["Đã ngăn chặn"] = df["deauth_count"].apply(lambda x: f"🛡️ {int(x)} gói" if pd.notna(x) and int(x) > 0 else "—")

    col_rename = {
        "bssid": "BSSID", "ssid": "SSID", "channel": "Kênh", "rssi": "RSSI (dBm)",
        "beacon_interval": "Beacon Interval", "vendor": "Hãng sản xuất",
        "frame_count": "Số frame", "timestamp": "Thời gian", "deauth_count": "Deauth gửi",
    }
    df_display = df.rename(columns={k: v for k, v in col_rename.items() if k in df.columns})

    n_total    = len(df)
    n_rogue    = len(df[df["status_calc"].str.startswith("ROGUE")])
    n_legit    = len(df[df["status_calc"] == "LEGIT"])
    n_unknown  = len(df[df["status_calc"] == "UNKNOWN"])
    n_blocked  = len(df[df["deauth_count"] > 0])
    total_pkts = int(df["deauth_count"].sum())
else:
    df = df_display = None
    n_total = n_rogue = n_legit = n_unknown = n_blocked = total_pkts = 0


# ─────────────────────────────────────────────
#  VIEW: TỔNG QUAN
# ─────────────────────────────────────────────
if view == "Tổng quan":
    st.markdown("## Tổng quan hệ thống")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("AP đã học",         len(known))
    c2.metric("Tổng AP quét được", n_total)
    c3.metric("🔴 Rogue AP",       n_rogue, delta=f"+{n_rogue}" if n_rogue > 0 else None, delta_color="inverse")
    c4.metric("✅ Hợp pháp",       n_legit)

    st.divider()
    p1, p2, p3, p4 = st.columns(4)
    p1.metric("🛡️ Rogue bị ngăn chặn", n_blocked)
    p2.metric("📦 Tổng gói deauth gửi", total_pkts)
    p3.metric("📋 Tổng cảnh báo",       len(alerts))
    p4.metric("🔒 Log ngăn chặn",       len(prevention_logs))

    st.divider()
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("### Cảnh báo Rogue AP gần nhất")
        if alerts:
            for a in reversed(alerts[-6:]):
                ssid_disp = a.get("ssid") or "<SSID ẩn>"
                reason    = a.get("reason", "").replace("ROGUE:", "").strip()
                st.markdown(f'<div class="alert-box"><strong>{ssid_disp}</strong> — {a.get("bssid","")}<br><span style="color:#A32D2D;">Lý do: {reason}</span> &nbsp;|&nbsp; {a.get("time","")} &nbsp;|&nbsp; Ch:{a.get("channel","?")} &nbsp;|&nbsp; RSSI:{a.get("rssi","?")} dBm</div>', unsafe_allow_html=True)
        else:
            st.info("Chưa có cảnh báo.")

        if prevention_logs:
            st.markdown("### Hành động ngăn chặn gần nhất")
            for p in reversed(prevention_logs[-4:]):
                ssid_p = p.get("ssid") or "<SSID ẩn>"
                st.markdown(f'<div class="prevention-box">🛡️ <strong>{ssid_p}</strong> — {p.get("bssid","")}<br>Đã gửi <strong>{p.get("packets","?")} gói deauth</strong> &nbsp;|&nbsp; Ch:{p.get("channel","?")} &nbsp;|&nbsp; {p.get("time","")}</div>', unsafe_allow_html=True)

    with col_right:
        st.markdown("### Phân bố theo trạng thái")
        if n_total > 0:
            pie_data = pd.DataFrame({"Trạng thái": ["Hợp pháp", "Rogue AP", "Chưa xác định"], "Số lượng": [n_legit, n_rogue, n_unknown]})
            st.bar_chart(pie_data.set_index("Trạng thái"), use_container_width=True)
        
        st.markdown("### Phân bố kênh WiFi")
        if df is not None and "channel" in df.columns:
            ch_counts = df["channel"].value_counts().sort_index().reset_index()
            ch_counts.columns = ["Kênh", "Số AP"]
            ch_counts["Kênh"] = "Ch " + ch_counts["Kênh"].astype(str)
            st.bar_chart(ch_counts.set_index("Kênh"), use_container_width=True)


# ─────────────────────────────────────────────
#  VIEW: DANH SÁCH AP
# ─────────────────────────────────────────────
elif view == "Danh sách AP":
    st.markdown("## Danh sách Access Point đã quét")
    if df_display is None or df_display.empty:
        st.warning("⚠️ Chưa có dữ liệu mạng.")
    else:
        filt_col1, filt_col2, filt_col3, filt_col4 = st.columns(4)
        with filt_col1: 
            filter_status = st.selectbox("Lọc theo trạng thái:", ["Tất cả", "Rogue AP", "Hợp pháp", "Chưa xác định", "Đã ngăn chặn"])
        with filt_col2: 
            search_ssid = st.text_input("Tìm SSID:", placeholder="Nhập tên WiFi...")
        with filt_col3:
            unique_channels = ["Tất cả"] + sorted([int(x) for x in df_display["Kênh"].dropna().unique() if str(x).isdigit()])
            filter_ch = st.selectbox("Lọc kênh:", unique_channels)
        with filt_col4:
            unique_vendors = ["Tất cả"] + sorted([str(x) for x in df_display["Hãng sản xuất"].dropna().unique() if pd.notna(x)])
            filter_vendor = st.selectbox("Lọc hãng sản xuất:", unique_vendors)

        df_filtered = df_display.copy()
        df_status   = df["status_calc"].copy()

        if filter_status == "Rogue AP": df_filtered = df_filtered[df_status.str.startswith("ROGUE")]
        elif filter_status == "Hợp pháp": df_filtered = df_filtered[df_status == "LEGIT"]
        elif filter_status == "Chưa xác định": df_filtered = df_filtered[df_status == "UNKNOWN"]
        elif filter_status == "Đã ngăn chặn": df_filtered = df_filtered[df["deauth_count"] > 0]

        if search_ssid and "SSID" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["SSID"].str.contains(search_ssid, case=False, na=False)]
        if filter_ch != "Tất cả" and "Kênh" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["Kênh"] == filter_ch]
        if filter_vendor != "Tất cả" and "Hãng sản xuất" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["Hãng sản xuất"] == filter_vendor]

        if not df_filtered.empty:
            df_filtered = df_filtered.sort_values(by=["Kênh", "Hãng sản xuất"], ascending=[True, True])

        st.caption(f"Hiển thị {len(df_filtered)} / {len(df_display)} AP")

        show_cols = [c for c in ["Trạng thái", "Đã ngăn chặn", "SSID", "BSSID", "Kênh", "RSSI (dBm)", "Hãng sản xuất", "Số frame", "Thời gian"] if c in df_filtered.columns]
        st.dataframe(df_filtered[show_cols], use_container_width=True, height=520, hide_index=True)


# ─────────────────────────────────────────────
#  VIEW: CẢNH BÁO ROGUE / LOG NGĂN CHẶN
# ─────────────────────────────────────────────
elif view == "Cảnh báo Rogue":
    st.markdown("## Lịch sử cảnh báo Rogue AP")
    if not alerts: st.info("Chưa có cảnh báo.")
    else:
        df_alerts = pd.DataFrame(alerts).rename(columns={"time": "Thời gian", "bssid": "BSSID", "ssid": "SSID", "channel": "Kênh", "rssi": "RSSI (dBm)", "reason": "Lý do"})
        st.dataframe(df_alerts, use_container_width=True, height=500, hide_index=True)

elif view == "Log Ngăn chặn":
    st.markdown("## Lịch sử hành động ngăn chặn (Deauth)")
    if not prevention_logs: st.info("Chưa có hành động ngăn chặn.")
    else:
        df_prev = pd.DataFrame(prevention_logs).rename(columns={"time": "Thời gian", "action": "Hành động", "bssid": "BSSID", "ssid": "SSID", "channel": "Kênh", "packets": "Gói deauth"})
        st.dataframe(df_prev[[c for c in df_prev.columns if c != "type"]], use_container_width=True, height=480, hide_index=True)


# ─────────────────────────────────────────────
#  VIEW: DATABASE ĐÃ HỌC 
# ─────────────────────────────────────────────
elif view == "Database đã học":
    st.markdown("## Danh sách Access Point hợp pháp (Whitelist)")

    if not known:
        st.warning("⚠️ Chưa có AP nào được học. Chạy lệnh sniffing ở chế độ Learning.")
    else:
        rows = []
        for bssid, fp in known.items():
            rows.append({
                "BSSID": bssid, "SSID": fp.get("ssid", ""), "OUI": fp.get("oui", ""),
                "Hãng sản xuất": fp.get("vendor", "Unknown"), "Kênh": fp.get("channel", 0),
                "Thời gian học": fp.get("timestamp") or fp.get("time") or "—"
            })
        df_known = pd.DataFrame(rows)

        st.markdown("### 📊 Thống kê Cơ sở dữ liệu Whitelist")
        stat_col1, stat_col2 = st.columns(2)
        with stat_col1:
            st.markdown("##### Phân bố theo Kênh (Channel)")
            ch_stats = df_known["Kênh"].value_counts().sort_index().reset_index()
            ch_stats.columns = ["Kênh WiFi", "Số lượng AP"]
            ch_stats["Kênh WiFi"] = "Ch " + ch_stats["Kênh WiFi"].astype(str)
            st.bar_chart(ch_stats.set_index("Kênh WiFi"), use_container_width=True)
        with stat_col2:
            st.markdown("##### Phân bố theo Hãng sản xuất")
            vendor_stats = df_known["Hãng sản xuất"].value_counts().reset_index()
            vendor_stats.columns = ["Hãng sản xuất", "Số lượng AP"]
            st.bar_chart(vendor_stats.set_index("Hãng sản xuất"), use_container_width=True)

        st.divider()

        # ─── BẢNG INTERACTIVE CẬP NHẬT: CHIA LẠI 6 CỘT ĐỀU NHAU TÍCH HỢP THỜI GIAN HỌC ───
        st.markdown("### 📋 Bảng quản lý thông tin Whitelist")
        st.caption("Danh sách chi tiết các Access Point đáng tin cậy. Giao diện tích hợp vùng trượt độc lập.")

        # Định nghĩa thanh tiêu đề ngoài khung cuộn với cấu trúc 6 cột [2, 2, 2, 1, 2, 1]
        h_col1, h_col2, h_col3, h_col4, h_col5, h_col6 = st.columns([2, 2, 2, 1, 2, 1])
        h_col1.markdown("**SSID (Tên mạng)**")
        h_col2.markdown("**BSSID (Địa chỉ MAC)**")
        h_col3.markdown("**Hãng sản xuất**")
        h_col4.markdown("**Kênh phát**")
        h_col5.markdown("**Thời gian học**")  
        h_col6.markdown("**Hành động**")
        st.markdown("<hr style='margin: 4px 0px 12px 0px; border-color: rgba(49, 51, 63, 0.2);'>", unsafe_allow_html=True)

        # Vùng container cuộn độc lập với chiều cao kéo dài lên 550
        with st.container(height=550):
            for bssid, fp in list(known.items()):
                col1, col2, col3, col4, col5, col6 = st.columns([2, 2, 2, 1, 2, 1])
                
                ssid_name = fp.get("ssid", "").strip()
                col1.write(ssid_name if ssid_name else "<SSID ẩn>")
                col2.code(bssid)
                col3.write(fp.get("vendor", "Unknown"))
                col4.write(f"Kênh {fp.get('channel', '?')}")
                
                # Hiển thị chuỗi thời gian lấy từ database
                learned_time = fp.get("timestamp") or fp.get("time") or fp.get("last_seen") or "—"
                col5.write(learned_time)
                
                # Nút hành động xóa trực tiếp cuối hàng dữ liệu mạng
                if col6.button("🗑️ Xóa", key=f"btn_del_{bssid}", use_container_width=True, help=f"Gỡ {bssid}"):
                    del known[bssid]
                    if save_known(known):
                        st.cache_data.clear()
                        st.success(f"Đã gỡ bỏ AP: {bssid}")
                        time.sleep(0.6)
                        st.rerun()

        st.divider()

        mgmt_col1, mgmt_col2 = st.columns(2)
        with mgmt_col1:
            st.markdown("**Bản lưu trữ hệ thống:**")
            json_export = json.dumps(known, indent=2, ensure_ascii=False).encode("utf-8")
            st.download_button("⬇️ Xuất file sao lưu JSON", data=json_export, file_name="known_fingerprints_export.json", mime="application/json", use_container_width=True)
        with mgmt_col2:
            st.markdown("**Làm sạch tài nguyên:**")
            if st.button("🚨 Xóa TOÀN BỘ database whitelist", type="secondary", key="btn_clear_all_db", use_container_width=True):
                st.session_state["confirm_delete"] = True
            if st.session_state.get("confirm_delete"):
                st.error("⚠️ Bạn có chắc muốn xóa sạch toàn bộ database whitelist không?")
                cx1, cx2 = st.columns(2)
                if cx1.button("✅ Xác nhận xóa hết", type="primary"):
                    if os.path.exists(DB_FILE): os.remove(DB_FILE)
                    st.cache_data.clear()
                    st.session_state["confirm_delete"] = False
                    st.success("Đã xóa. Đang tải lại dữ liệu...")
                    time.sleep(1)
                    st.rerun()
                if cx2.button("❌ Hủy bỏ"):
                    st.session_state["confirm_delete"] = False
                    st.rerun()
