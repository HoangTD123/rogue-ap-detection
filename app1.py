"""
=============================================================================
GIAO DIỆN WEB - HỆ THỐNG PHÁT HIỆN & NGĂN CHẶN ROGUE ACCESS POINT
Beacon Frame Fingerprinting Dashboard v2.0
=============================================================================
Cách chạy:
  1. Tắt Monitor Mode:  sudo airmon-ng stop wlan0mon
  2. Kết nối WiFi bình thường
  3. Activate venv:     source ~/rogue-detection-env/bin/activate
  4. Chạy app:          streamlit run app.py

File này đọc dữ liệu từ:
  - known_fingerprints.json  → Database AP hợp pháp đã học
  - rogue_dataset.csv        → Toàn bộ AP đã quét (có cột deauth_count)
  - rogue_alerts.log         → Log cảnh báo + hành động ngăn chặn
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
    /* Risk score bar */
    .risk-bar-wrap {
        background: #e9ecef;
        border-radius: 4px;
        height: 8px;
        width: 100%;
        display: inline-block;
    }
    .risk-bar-fill {
        height: 8px;
        border-radius: 4px;
        display: inline-block;
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
#  LOAD DỮ LIỆU  (cache 5s)
# ─────────────────────────────────────────────
@st.cache_data(ttl=5)
def load_known() -> dict:
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


@st.cache_data(ttl=5)
def load_dataset() -> pd.DataFrame | None:
    if not os.path.exists(CSV_FILE):
        return None
    df = pd.read_csv(CSV_FILE)
    df.columns = [c.strip().lower() for c in df.columns]
    # Đảm bảo cột deauth_count tồn tại (tương thích ngược với v1)
    if "deauth_count" not in df.columns:
        df["deauth_count"] = 0
    return df


@st.cache_data(ttl=5)
def load_alerts() -> tuple[list, list]:
    """
    Trả về (detection_alerts, prevention_logs).
    Phân biệt qua trường 'type': 'PREVENTION' hoặc không có.
    """
    detection  = []
    prevention = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "PREVENTION":
                        prevention.append(entry)
                    else:
                        detection.append(entry)
                except Exception:
                    pass
    return detection, prevention


# ─────────────────────────────────────────────
#  PHÂN LOẠI AP + TÍNH ĐIỂM RỦI RO
# ─────────────────────────────────────────────
def classify_row(row: pd.Series, known: dict) -> tuple[str, int]:
    """
    Trả về (status_string, risk_score).

    Bảng điểm:
      - SSID thay đổi      : +60
      - Cap thay đổi       : +40
      - HT Cap thay đổi    : +35
      - Channel thay đổi   : +30
      - Interval lệch      : +25
      - Evil Twin (BSSID lạ): 100 (cố định)
      - UNKNOWN             :  10 (cố định)
      - LEGIT               :   0
    """
    bssid   = str(row.get("bssid", "")).upper()
    ssid    = str(row.get("ssid", ""))
    channel = row.get("channel", 0)
    bi      = row.get("beacon_interval", 0)
    cap_raw = row.get("cap_raw", None)
    ht_cap  = row.get("ht_cap", None)

    risk_score = 0
    anomalies  = []

    if bssid in known:
        k = known[bssid]
        if k.get("ssid") and ssid != k["ssid"]:
            anomalies.append("SSID thay đổi")
            risk_score += 60
        if k.get("channel") and channel and int(channel) != int(k["channel"]):
            anomalies.append("Channel thay đổi")
            risk_score += 30
        if k.get("beacon_interval") and bi:
            if abs(int(bi) - int(k["beacon_interval"])) > 15:
                anomalies.append("Interval lệch")
                risk_score += 25
        if cap_raw is not None and k.get("cap_raw") is not None:
            if str(cap_raw) != str(k["cap_raw"]):
                anomalies.append("Cap thay đổi")
                risk_score += 40
        if ht_cap is not None and k.get("ht_cap") is not None:
            if str(ht_cap) != str(k["ht_cap"]):
                anomalies.append("HT Cap thay đổi")
                risk_score += 35
        status = ("ROGUE: " + ", ".join(anomalies)) if anomalies else "LEGIT"
        return status, min(risk_score, 100)

    for _, kfp in known.items():
        if kfp.get("ssid") == ssid and ssid != "":
            return "ROGUE: Evil Twin", 100

    return "UNKNOWN", 10


def risk_color(score: int) -> str:
    """Trả về mã màu hex tương ứng điểm rủi ro."""
    if score >= 80:
        return "#A32D2D"   # đỏ đậm
    elif score >= 50:
        return "#D4691E"   # cam
    elif score >= 20:
        return "#BA7517"   # vàng
    else:
        return "#3B6D11"   # xanh lá


def status_label(status: str, risk_score: int) -> str:
    if status == "LEGIT":
        return "✅ Hợp pháp"
    elif status.startswith("ROGUE"):
        reason    = status.split(":", 1)[-1].strip() if ":" in status else ""
        score_str = f" [{risk_score}đ]"
        return f"🔴 Rogue{score_str} — {reason}" if reason else f"🔴 Rogue AP{score_str}"
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
        ["Tổng quan", "Danh sách AP", "Phân tích điểm rủi ro",
         "Cảnh báo Rogue", "Log Ngăn chặn", "Database đã học"],
        label_visibility="collapsed",
    )

    st.divider()
    auto_refresh = st.toggle("Tự động làm mới (5s)", value=False)
    if st.button("🔄 Làm mới ngay", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("**Hướng dẫn:**")
    st.caption("1. Chạy `beacon_sniff_v2.py` với `MODE = learning`.")
    st.caption("2. Đổi `MODE = detection` để phát hiện.")
    st.caption("3. Bật `PREVENTION_ENABLED = True` để ngăn chặn.")
    st.divider()
    st.caption(f"Cập nhật lúc: {datetime.now().strftime('%H:%M:%S')}")


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

    # Phân loại + tính điểm rủi ro
    results            = df.apply(lambda r: classify_row(r, known), axis=1)
    df["status_calc"]  = results.apply(lambda x: x[0])
    df["risk_score"]   = results.apply(lambda x: x[1])

    df["Trạng thái"]   = df.apply(
        lambda r: status_label(r["status_calc"], r["risk_score"]), axis=1
    )

    # Cột "Đã ngăn chặn" dựa trên deauth_count
    df["Đã ngăn chặn"] = df["deauth_count"].apply(
        lambda x: f"🛡️ {int(x)} gói" if pd.notna(x) and int(x) > 0 else "—"
    )

    col_rename = {
        "bssid":            "BSSID",
        "ssid":             "SSID",
        "channel":          "Kênh",
        "rssi":             "RSSI (dBm)",
        "beacon_interval":  "Beacon Interval",
        "vendor":           "Hãng sản xuất",
        "frame_count":      "Số frame",
        "timestamp":        "Thời gian",
        "is_hidden":        "Ẩn SSID",
        "ht_cap":           "HT Cap",
        "deauth_count":     "Deauth gửi",
        "risk_score":       "Điểm rủi ro",
    }
    df_display = df.rename(columns={k: v for k, v in col_rename.items() if k in df.columns})

    n_total    = len(df)
    n_rogue    = len(df[df["status_calc"].str.startswith("ROGUE")])
    n_legit    = len(df[df["status_calc"] == "LEGIT"])
    n_unknown  = len(df[df["status_calc"] == "UNKNOWN"])
    n_blocked  = len(df[df["deauth_count"] > 0])
    total_pkts = int(df["deauth_count"].sum())
    avg_risk   = int(df[df["status_calc"].str.startswith("ROGUE")]["risk_score"].mean()) \
                 if n_rogue > 0 else 0
else:
    df = df_display = None
    n_total = n_rogue = n_legit = n_unknown = n_blocked = total_pkts = avg_risk = 0


# ─────────────────────────────────────────────
#  VIEW: TỔNG QUAN
# ─────────────────────────────────────────────
if view == "Tổng quan":
    st.markdown("## Tổng quan hệ thống")

    # Hàng metric 1: số lượng AP
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("AP đã học",         len(known),  help="Số AP hợp pháp trong database")
    c2.metric("Tổng AP quét được", n_total)
    c3.metric("🔴 Rogue AP",       n_rogue,
              delta=f"+{n_rogue}" if n_rogue > 0 else None,
              delta_color="inverse")
    c4.metric("✅ Hợp pháp",       n_legit)
    c5.metric("⚠️ Điểm rủi ro TB (Rogue)", f"{avg_risk}/100",
              help="Trung bình điểm rủi ro của các Rogue AP")

    # Hàng metric 2: prevention
    st.divider()
    p1, p2, p3, p4 = st.columns(4)
    p1.metric("🛡️ Rogue bị ngăn chặn", n_blocked,
              help="Số Rogue AP đã bị deauth ít nhất 1 lần")
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
                st.markdown(
                    f'<div class="alert-box">'
                    f'<strong>{ssid_disp}</strong> — {a.get("bssid","")}<br>'
                    f'<span style="color:#A32D2D;">Lý do: {reason}</span> &nbsp;|&nbsp; '
                    f'{a.get("time","")} &nbsp;|&nbsp; '
                    f'Ch:{a.get("channel","?")} &nbsp;|&nbsp; '
                    f'RSSI:{a.get("rssi","?")} dBm'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("Chưa có cảnh báo. Chạy beacon_sniff_v2.py ở Detection Mode.")

        # Prevention log gần nhất (nếu có)
        if prevention_logs:
            st.markdown("### Hành động ngăn chặn gần nhất")
            for p in reversed(prevention_logs[-4:]):
                ssid_p = p.get("ssid") or "<SSID ẩn>"
                st.markdown(
                    f'<div class="prevention-box">'
                    f'🛡️ <strong>{ssid_p}</strong> — {p.get("bssid","")}<br>'
                    f'Đã gửi <strong>{p.get("packets","?")} gói deauth</strong>'
                    f' &nbsp;|&nbsp; Ch:{p.get("channel","?")}'
                    f' &nbsp;|&nbsp; {p.get("time","")}'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    with col_right:
        st.markdown("### Phân bố theo trạng thái")
        if n_total > 0:
            pie_data = pd.DataFrame({
                "Trạng thái": ["Hợp pháp", "Rogue AP", "Chưa xác định"],
                "Số lượng":   [n_legit, n_rogue, n_unknown],
            })
            pie_data = pie_data[pie_data["Số lượng"] > 0]
            st.bar_chart(pie_data.set_index("Trạng thái"), use_container_width=True)
        else:
            st.caption("Chưa có dữ liệu.")

        st.markdown("### Phân bố kênh WiFi")
        if df is not None and "channel" in df.columns:
            ch_counts = (
                df["channel"]
                .value_counts()
                .sort_index()
                .reset_index()
            )
            ch_counts.columns = ["Kênh", "Số AP"]
            ch_counts["Kênh"] = "Ch " + ch_counts["Kênh"].astype(str)
            st.bar_chart(ch_counts.set_index("Kênh"), use_container_width=True)
        else:
            st.caption("Chưa có dữ liệu kênh.")

    if df_raw is None:
        st.warning("⚠️ Chưa có file `rogue_dataset.csv`. Hãy chạy `beacon_sniff_v2.py` trước.")


# ─────────────────────────────────────────────
#  VIEW: DANH SÁCH AP
# ─────────────────────────────────────────────
elif view == "Danh sách AP":
    st.markdown("## Danh sách Access Point đã quét")

    if df_display is None or df_display.empty:
        st.warning("⚠️ Chưa có dữ liệu. Hãy chạy `beacon_sniff_v2.py` trước.")
    else:
        filt_col1, filt_col2, filt_col3 = st.columns(3)
        with filt_col1:
            filter_status = st.selectbox(
                "Lọc theo trạng thái:",
                ["Tất cả", "Rogue AP", "Hợp pháp", "Chưa xác định", "Đã ngăn chặn"],
            )
        with filt_col2:
            search_ssid = st.text_input("Tìm SSID:", placeholder="Nhập tên WiFi...")
        with filt_col3:
            if "Kênh" in df_display.columns:
                all_channels = sorted(df["channel"].dropna().unique().tolist())
                selected_ch  = st.multiselect("Lọc kênh:", all_channels, default=[])

        df_filtered = df_display.copy()
        df_status   = df["status_calc"].copy()

        if filter_status == "Rogue AP":
            df_filtered = df_filtered[df_status.str.startswith("ROGUE")]
        elif filter_status == "Hợp pháp":
            df_filtered = df_filtered[df_status == "LEGIT"]
        elif filter_status == "Chưa xác định":
            df_filtered = df_filtered[df_status == "UNKNOWN"]
        elif filter_status == "Đã ngăn chặn":
            mask = df["deauth_count"] > 0
            df_filtered = df_filtered[mask]

        if search_ssid:
            col = "SSID" if "SSID" in df_filtered.columns else "ssid"
            if col in df_filtered.columns:
                df_filtered = df_filtered[
                    df_filtered[col].str.contains(search_ssid, case=False, na=False)
                ]

        if selected_ch and "Kênh" in df_filtered.columns:
            df_filtered = df_filtered[df_filtered["Kênh"].isin(selected_ch)]

        st.caption(f"Hiển thị {len(df_filtered)} / {len(df_display)} AP")

        show_cols = [c for c in [
            "Trạng thái", "Điểm rủi ro", "Đã ngăn chặn", "SSID", "BSSID", "Kênh",
            "RSSI (dBm)", "Beacon Interval", "Hãng sản xuất",
            "Số frame", "Deauth gửi", "Thời gian",
        ] if c in df_filtered.columns]

        st.dataframe(
            df_filtered[show_cols],
            use_container_width=True,
            height=520,
            hide_index=True,
            column_config={
                "Điểm rủi ro": st.column_config.ProgressColumn(
                    "Điểm rủi ro",
                    help="0 = an toàn, 100 = nguy hiểm tối đa",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
        )

        csv_export = df_filtered.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "⬇️ Xuất CSV",
            data=csv_export,
            file_name=f"rogue_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )


# ─────────────────────────────────────────────
#  VIEW: PHÂN TÍCH ĐIỂM RỦI RO  ← MỚI THÊM
# ─────────────────────────────────────────────
elif view == "Phân tích điểm rủi ro":
    st.markdown("## Phân tích điểm rủi ro")

    if df is None or df.empty:
        st.warning("⚠️ Chưa có dữ liệu. Hãy chạy `beacon_sniff_v2.py` trước.")
    else:
        # ── Bảng điểm ──────────────────────────────────────────────────────
        st.markdown("### Bảng quy đổi điểm rủi ro")
        score_table = pd.DataFrame([
            {"Dấu hiệu bất thường": "Evil Twin (BSSID chưa học, trùng SSID)", "Điểm cộng": 100, "Ghi chú": "Cố định, không tích lũy thêm"},
            {"Dấu hiệu bất thường": "SSID thay đổi",                            "Điểm cộng": 60,  "Ghi chú": ""},
            {"Dấu hiệu bất thường": "Capabilities (cap_raw) thay đổi",          "Điểm cộng": 40,  "Ghi chú": ""},
            {"Dấu hiệu bất thường": "HT Capabilities thay đổi",                 "Điểm cộng": 35,  "Ghi chú": ""},
            {"Dấu hiệu bất thường": "Channel thay đổi",                         "Điểm cộng": 30,  "Ghi chú": ""},
            {"Dấu hiệu bất thường": "Beacon Interval lệch > 15ms",              "Điểm cộng": 25,  "Ghi chú": ""},
            {"Dấu hiệu bất thường": "UNKNOWN (chưa có trong database)",         "Điểm cộng": 10,  "Ghi chú": "Cố định"},
            {"Dấu hiệu bất thường": "Hợp pháp (LEGIT)",                         "Điểm cộng": 0,   "Ghi chú": ""},
        ])
        st.dataframe(score_table, use_container_width=True, hide_index=True)

        st.divider()

        # ── Ngưỡng phân loại ──────────────────────────────────────────────
        st.markdown("### Ngưỡng đánh giá mức nguy hiểm")
        th1, th2, th3, th4 = st.columns(4)
        th1.markdown(
            '<div style="background:#EAF3DE;border-radius:8px;padding:12px 16px;">'
            '<b style="color:#3B6D11">🟢 An toàn</b><br>'
            '<span style="font-size:22px;font-weight:700;color:#3B6D11">0 – 19</span><br>'
            '<span style="font-size:12px;color:#555">LEGIT hoặc UNKNOWN mới</span>'
            '</div>', unsafe_allow_html=True
        )
        th2.markdown(
            '<div style="background:#FFF9E6;border-radius:8px;padding:12px 16px;">'
            '<b style="color:#BA7517">🟡 Nghi ngờ</b><br>'
            '<span style="font-size:22px;font-weight:700;color:#BA7517">20 – 49</span><br>'
            '<span style="font-size:12px;color:#555">Beacon Interval lệch</span>'
            '</div>', unsafe_allow_html=True
        )
        th3.markdown(
            '<div style="background:#FEF0E0;border-radius:8px;padding:12px 16px;">'
            '<b style="color:#D4691E">🟠 Nguy hiểm</b><br>'
            '<span style="font-size:22px;font-weight:700;color:#D4691E">50 – 79</span><br>'
            '<span style="font-size:12px;color:#555">Cap/Channel thay đổi</span>'
            '</div>', unsafe_allow_html=True
        )
        th4.markdown(
            '<div style="background:#FCEBEB;border-radius:8px;padding:12px 16px;">'
            '<b style="color:#A32D2D">🔴 Cực kỳ nguy hiểm</b><br>'
            '<span style="font-size:22px;font-weight:700;color:#A32D2D">80 – 100</span><br>'
            '<span style="font-size:12px;color:#555">SSID thay đổi / Evil Twin</span>'
            '</div>', unsafe_allow_html=True
        )

        st.divider()

        # ── Thống kê nhanh ────────────────────────────────────────────────
        s1, s2, s3, s4 = st.columns(4)
        rogue_df = df[df["status_calc"].str.startswith("ROGUE")]
        s1.metric("Điểm rủi ro cao nhất",  int(df["risk_score"].max()) if n_total > 0 else 0)
        s2.metric("Điểm rủi ro TB (Rogue)", avg_risk)
        s3.metric("AP nguy hiểm (≥80đ)",
                  len(df[df["risk_score"] >= 80]))
        s4.metric("AP nghi ngờ (20–79đ)",
                  len(df[(df["risk_score"] >= 20) & (df["risk_score"] < 80)]))

        st.divider()

        # ── Bảng chi tiết điểm rủi ro ─────────────────────────────────────
        st.markdown("### Chi tiết điểm rủi ro từng AP")

        # Slider lọc theo ngưỡng điểm
        min_score = st.slider(
            "Chỉ hiện AP có điểm rủi ro ≥:",
            min_value=0, max_value=100, value=0, step=5,
            help="Kéo sang phải để lọc AP nguy hiểm hơn"
        )

        df_risk = df[df["risk_score"] >= min_score].copy()
        df_risk = df_risk.sort_values("risk_score", ascending=False)

        # Chuẩn bị cột hiển thị
        show_risk_cols_raw = ["ssid", "bssid", "channel", "rssi", "status_calc", "risk_score"]
        show_risk_cols_raw = [c for c in show_risk_cols_raw if c in df_risk.columns]
        df_risk_disp = df_risk[show_risk_cols_raw].rename(columns={
            "ssid":        "SSID",
            "bssid":       "BSSID",
            "channel":     "Kênh",
            "rssi":        "RSSI (dBm)",
            "status_calc": "Phân loại",
            "risk_score":  "Điểm rủi ro",
        })

        st.caption(f"Hiển thị {len(df_risk_disp)} AP (điểm ≥ {min_score})")
        st.dataframe(
            df_risk_disp,
            use_container_width=True,
            height=420,
            hide_index=True,
            column_config={
                "Điểm rủi ro": st.column_config.ProgressColumn(
                    "Điểm rủi ro",
                    help="0 = an toàn · 100 = nguy hiểm tối đa",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
        )

        st.divider()

        # ── Biểu đồ phân bố điểm rủi ro ───────────────────────────────────
        st.markdown("### Phân bố điểm rủi ro")
        bins      = [0, 20, 50, 80, 101]
        labels    = ["An toàn (0–19)", "Nghi ngờ (20–49)", "Nguy hiểm (50–79)", "Cực kỳ nguy hiểm (80–100)"]
        df["risk_level"] = pd.cut(df["risk_score"], bins=bins, labels=labels, right=False)
        risk_dist = df["risk_level"].value_counts().reindex(labels).fillna(0).reset_index()
        risk_dist.columns = ["Mức độ", "Số AP"]
        st.bar_chart(risk_dist.set_index("Mức độ"), use_container_width=True)

        # ── Top Rogue AP nguy hiểm nhất ────────────────────────────────────
        if n_rogue > 0:
            st.divider()
            st.markdown("### 🔴 Top Rogue AP nguy hiểm nhất")
            top_rogue = (
                rogue_df
                .sort_values("risk_score", ascending=False)
                .head(10)
            )
            for _, row in top_rogue.iterrows():
                score  = int(row["risk_score"])
                color  = risk_color(score)
                ssid_d = row.get("ssid", "") or "<SSID ẩn>"
                bssid_d= row.get("bssid", "")
                reason = row["status_calc"].split(":", 1)[-1].strip() if ":" in row["status_calc"] else ""
                bar_w  = score  # width % capped at 100

                st.markdown(
                    f'<div style="border:1px solid {color}33;border-radius:8px;'
                    f'padding:10px 14px;margin-bottom:8px;">'
                    f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                    f'  <span><strong>{ssid_d}</strong> &nbsp; '
                    f'  <span style="color:#888;font-size:12px;">{bssid_d}</span></span>'
                    f'  <span style="font-size:20px;font-weight:700;color:{color}">{score}</span>'
                    f'</div>'
                    f'<div style="background:#e9ecef;border-radius:4px;height:7px;margin:6px 0;">'
                    f'  <div style="width:{bar_w}%;background:{color};height:7px;border-radius:4px;"></div>'
                    f'</div>'
                    f'<span style="font-size:12px;color:#666;">{reason}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )


# ─────────────────────────────────────────────
#  VIEW: CẢNH BÁO ROGUE
# ─────────────────────────────────────────────
elif view == "Cảnh báo Rogue":
    st.markdown("## Lịch sử cảnh báo Rogue AP")

    if not alerts:
        st.info("Chưa có cảnh báo. Chạy beacon_sniff_v2.py ở Detection Mode.")
    else:
        st.caption(f"Tổng cộng {len(alerts)} cảnh báo đã ghi nhận.")

        df_alerts = pd.DataFrame(alerts)
        col_map = {
            "time":    "Thời gian",
            "bssid":   "BSSID",
            "ssid":    "SSID",
            "channel": "Kênh",
            "rssi":    "RSSI (dBm)",
            "reason":  "Lý do phát hiện",
        }
        df_alerts = df_alerts.rename(
            columns={k: v for k, v in col_map.items() if k in df_alerts.columns}
        )
        if "Lý do phát hiện" in df_alerts.columns:
            df_alerts["Lý do phát hiện"] = (
                df_alerts["Lý do phát hiện"]
                .str.replace("ROGUE:", "", regex=False)
                .str.strip()
            )

        # Ẩn cột "type" nếu có
        show_cols = [c for c in df_alerts.columns if c != "type"]
        st.dataframe(df_alerts[show_cols], use_container_width=True,
                     height=500, hide_index=True)

        csv_alerts = df_alerts.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "⬇️ Xuất log cảnh báo",
            data=csv_alerts,
            file_name=f"rogue_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )


# ─────────────────────────────────────────────
#  VIEW: LOG NGĂN CHẶN
# ─────────────────────────────────────────────
elif view == "Log Ngăn chặn":
    st.markdown("## Lịch sử hành động ngăn chặn (Deauth)")

    if not prevention_logs:
        st.info(
            "Chưa có hành động ngăn chặn nào được ghi lại.\n\n"
            "Để kích hoạt: đặt `PREVENTION_ENABLED = True` trong `beacon_sniff_v2.py`."
        )
    else:
        total_deauth_pkts = sum(p.get("packets", 0) for p in prevention_logs)
        unique_targets    = len({p.get("bssid") for p in prevention_logs})

        m1, m2, m3 = st.columns(3)
        m1.metric("Tổng lần ngăn chặn",    len(prevention_logs))
        m2.metric("Số Rogue AP bị xử lý",  unique_targets)
        m3.metric("Tổng gói deauth đã gửi", total_deauth_pkts)

        st.divider()

        df_prev = pd.DataFrame(prevention_logs)
        col_map = {
            "time":    "Thời gian",
            "action":  "Hành động",
            "bssid":   "BSSID",
            "ssid":    "SSID",
            "channel": "Kênh",
            "packets": "Gói deauth gửi",
        }
        df_prev = df_prev.rename(
            columns={k: v for k, v in col_map.items() if k in df_prev.columns}
        )

        # Ẩn cột "type"
        show_cols = [c for c in df_prev.columns if c != "type"]
        st.dataframe(df_prev[show_cols], use_container_width=True,
                     height=480, hide_index=True)

        # Biểu đồ: số gói deauth theo BSSID
        if "BSSID" in df_prev.columns and "Gói deauth gửi" in df_prev.columns:
            st.markdown("### Số gói deauth theo Rogue AP")
            chart_data = (
                df_prev.groupby("BSSID")["Gói deauth gửi"]
                .sum()
                .reset_index()
                .sort_values("Gói deauth gửi", ascending=False)
            )
            st.bar_chart(chart_data.set_index("BSSID"), use_container_width=True)

        # Export
        csv_prev = df_prev.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "⬇️ Xuất log ngăn chặn",
            data=csv_prev,
            file_name=f"prevention_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

        st.divider()
        st.caption(
            "Lưu ý: Mỗi dòng là một lần burst deauth. "
            "Cùng một BSSID có thể xuất hiện nhiều lần do cooldown timer tự kích hoạt lại."
        )


# ─────────────────────────────────────────────
#  VIEW: DATABASE ĐÃ HỌC
# ─────────────────────────────────────────────
elif view == "Database đã học":
    st.markdown("## Database fingerprint AP hợp pháp")

    if not known:
        st.warning("⚠️ Chưa có AP nào được học. Chạy beacon_sniff_v2.py với `MODE = 'learning'`.")
    else:
        st.info(f"Database có **{len(known)}** AP hợp pháp đã được học vào `{DB_FILE}`.")

        rows = []
        for bssid, fp in known.items():
            rows.append({
                "BSSID":           bssid,
                "SSID":            fp.get("ssid", ""),
                "OUI":             fp.get("oui", ""),
                "Hãng sản xuất":   fp.get("vendor", ""),
                "Kênh":            fp.get("channel", ""),
                "Beacon Interval": fp.get("beacon_interval", ""),
                "Capabilities":    fp.get("cap_raw", ""),
                "HT Capable":      fp.get("ht_cap", ""),
                "Ẩn SSID":         fp.get("is_hidden", ""),
            })

        df_known = pd.DataFrame(rows)
        st.dataframe(df_known, use_container_width=True, height=500, hide_index=True)

        # Export JSON
        json_export = json.dumps(known, indent=2, ensure_ascii=False).encode("utf-8")
        st.download_button(
            "⬇️ Xuất database JSON",
            data=json_export,
            file_name="known_fingerprints_export.json",
            mime="application/json",
        )

        st.divider()

        # Xoá database
        st.markdown("**Xoá database:**")
        st.caption("Xoá toàn bộ AP đã học. Cần chạy Learning Mode lại từ đầu.")
        if st.button("🗑️ Xoá toàn bộ database", type="secondary"):
            st.session_state["confirm_delete"] = True

        if st.session_state.get("confirm_delete"):
            st.error("Bạn có chắc muốn xoá toàn bộ database không? Thao tác này không thể hoàn tác.")
            c1, c2 = st.columns(2)
            if c1.button("✅ Xác nhận xoá", type="primary"):
                if os.path.exists(DB_FILE):
                    os.remove(DB_FILE)
                st.cache_data.clear()
                st.session_state["confirm_delete"] = False
                st.success("Đã xoá database. Hãy chạy Learning Mode lại.")
                st.rerun()
            if c2.button("❌ Huỷ"):
                st.session_state["confirm_delete"] = False
                st.rerun()