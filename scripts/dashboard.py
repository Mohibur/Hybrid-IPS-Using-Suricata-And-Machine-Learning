# dashboard.py
import streamlit as st
import pandas as pd
from pathlib import Path
import altair as alt

ALERTS_CSV = Path.home() / "mlips_project" / "output" / "alerts.csv"

st.set_page_config(page_title="Security Dashboard", page_icon="🛡️", layout="wide")

# ----- Simple dark styling -----
ACCENT = "#1DB954"   # headings + chart
ALERT_RED = "#B22222"
st.markdown(f"""
<style>
  .stApp {{ background-color: #121212; color: #EAEAEA; }}
  h1,h2,h3 {{ color: {ACCENT}; }}
  .alert-card {{
    background: #1A1A1A; border: 1px solid #2A2A2A; border-radius: 10px;
    padding: 10px 14px; margin: 8px 0; font-size: 15px; line-height: 1.35;
  }}
  .attack {{ border-left: 6px solid {ALERT_RED}; }}
  .benign {{ border-left: 6px solid #3A3A3A; }}
  .badge {{
    display:inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; margin-left: 8px; color: #fff; background: {ALERT_RED};
  }}
  .muted {{ color: #B8B8B8; font-size: 12px; }}
  .mono  {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Real-Time Security Dashboard")
st.caption("Monitoring ML predictions + Suricata alerts")

if not ALERTS_CSV.exists():
    st.error(f"alerts.csv not found at {ALERTS_CSV}")
    st.stop()

df = pd.read_csv(ALERTS_CSV)

if df.empty:
    st.info("No alerts yet.")
    st.stop()

# ---- Controls ----
left, right = st.columns([3,1])
with right:
    last_n = st.slider("Show last N alerts", 5, 100, 20)

# ---- Alerts feed ----
st.subheader("🔔 Recent Alerts")
subset = df.tail(last_n)

for _, r in subset.iterrows():
    pred = str(r.get("prediction", "UNKNOWN")).upper()
    css = "attack" if pred in {"SQLI","XSS","SURICATA"} else "benign"
    blocked = str(r.get("blocked","NO")).upper() == "YES"

    timestamp = r.get("timestamp","N/A")
    src = r.get("src_ip","N/A")
    dst = r.get("dst_ip","N/A")
    text = str(r.get("url_or_signature","")).strip()

    badge = f'<span class="badge">BLOCKED</span>' if blocked else ""
    st.markdown(
        f"""
        <div class="alert-card {css}">
          <div class="mono"><b>{pred}</b> {badge}</div>
          <div class="muted">{timestamp}</div>
          <div class="mono">{src} → {dst}</div>
          <div class="muted">{text}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

# ---- Minimal chart ----
st.subheader("📊 Attack Type Counts")
counts = df["prediction"].value_counts().rename_axis("type").reset_index(name="count")
chart = (
    alt.Chart(counts)
      .mark_bar(color=ACCENT)
      .encode(x=alt.X("type:N", sort="-y", title="Type"),
              y=alt.Y("count:Q", title="Count"))
      .properties(height=220)
)
st.altair_chart(chart, use_container_width=True)
