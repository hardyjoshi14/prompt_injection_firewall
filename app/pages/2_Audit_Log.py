import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
import pandas as pd
from firewall.observability.logger import read_audit_log, clear_audit_log

st.set_page_config(page_title="Audit Log")
st.title("Audit Log")

entries = read_audit_log()

if not entries:
    st.info("No audit entries yet. Run some inputs through the Live Demo tab.")
    st.stop()

# Summary metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total decisions", len(entries))
col2.metric("Blocked", sum(1 for e in entries if e.get("decision") == "block"))
col3.metric("Sanitized", sum(1 for e in entries if e.get("decision") == "sanitize"))
col4.metric("Allowed", sum(1 for e in entries if e.get("decision") == "allow"))

# Filters
st.subheader("Filter")
c1, c2 = st.columns(2)
with c1:
    decisions = ["all"] + sorted({e.get("decision", "?") for e in entries})
    sel_decision = st.selectbox("Decision", decisions)
with c2:
    sources = ["all"] + sorted({e.get("source", "?") for e in entries})
    sel_source = st.selectbox("Source", sources)

filtered = entries
if sel_decision != "all":
    filtered = [e for e in filtered if e.get("decision") == sel_decision]
if sel_source != "all":
    filtered = [e for e in filtered if e.get("source") == sel_source]

# Table
st.subheader(f"Entries ({len(filtered)})")

df = pd.DataFrame([
    {
        "time": e.get("timestamp", "")[:19].replace("T", " "),
        "source": e.get("source", ""),
        "decision": e.get("decision", ""),
        "attack_type": e.get("attack_type") or "—",
        "confidence": e.get("confidence", 0.0),
        "latency_ms": e.get("latency_ms", 0.0),
        "hash": e.get("content_hash", ""),
        "preview": (e.get("content_preview") or "")[:60],
    }
    for e in filtered
])

st.dataframe(df, width='stretch', hide_index=True)

# Detail viewer
st.subheader("Inspect Entry")
if filtered:
    selected_hash = st.selectbox(
        "Select by content hash",
        [e.get("content_hash") for e in filtered],
    )
    entry = next(e for e in filtered if e.get("content_hash") == selected_hash)
    st.json(entry)

# Danger zone
st.divider()
with st.expander("Danger zone"):
    if st.button("Clear audit log"):
        clear_audit_log()
        st.success("Audit log cleared.")
        st.rerun()