import json
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="Metrics")
st.title("Evaluation Metrics")

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "evaluation" / "reports"

reports = sorted(REPORTS_DIR.glob("*.json")) if REPORTS_DIR.exists() else []

if not reports:
    st.warning("No evaluation reports found. Run:")
    st.code("python evaluation/evaluate.py --tag baseline")
    st.stop()

# Report selector
report_names = [r.stem for r in reports]
selected = st.selectbox("Select report", report_names, index=len(report_names) - 1)
report = json.loads((REPORTS_DIR / f"{selected}.json").read_text())

st.caption(
    f"Test file: {report['config']['test_file']} ."
    f"Samples: {report['config']['sample_count']} ."
    f"LLM: {'on' if report['config']['use_llm'] else 'off'}"
)

# Overal metrics
st.subheader("Overall")
o = report["overall"]

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Precision", f"{o['precision']:.3f}")
c2.metric("Recall", f"{o['recall']:.3f}")
c3.metric("F1", f"{o['f1']:.3f}")
c4.metric("Accuracy", f"{o['accuracy']:.3f}")
c5.metric("Avg latency", f"{report['timing']['avg_latency_ms']:.0f} ms")

# Confusion matrix
st.subheader("Confusion Matrix")

cm = [[o["tn"], o["fp"], o["fn"], o["tp"]]]
fig = go.Figure(data=go.Heatmap(
    z=cm,
    x=["Predicted Benign", "Predicted Malicious"],
    y=["Actually Benign", "Actually Malicious"],
    text=cm,
    texttemplate="%text",
    colorscale="Blues"
))
fig.update_layout(height=350)
st.plotly_chart(fig, width='stretch')

# Per-attack detection rate
st.subheader("Per-Attack Detection Rate")

per_attack = report["per_attack"]
df = pd.DataFrame([
    {"Attack": k, "Detected": v["detected"], "Total": v["total"], "Rate": v["detection_rate"]}
    for k, v in per_attack.items()
]).sort_values("Rate", ascending=False)

fig = px.bar(df, x="Rate", y="Attack", orientation="h",
             color="Rate", color_continuous_scale="RdYlGn",
             range_x=[0,1], text="Rate")
fig.update_traces(texttemplate="%{text:.2f}", textposition="outside")
fig.update_layout(height=450, coloraxis_showscale=False)
st.plotly_chart(fig, width='stretch')

st.dataframe(df, width='stretch', hide_index=True)

# Per-source accuracy
st.subheader("Per-Source Accuracy")

per_source = report["per_source"]
df_src = pd.DataFrame([
    {"Source": k, "Correct": v["correct"], "Total": v["total"], "Accuracy": v["accuracy"]}
    for k, v in per_source.items()
]).sort_values("Accuracy", ascending=False)

fig = px.bar(df_src, x="Source", y="Accuracy", color="Accuracy",
             color_continuous_scale="RdYlGn", range_y=[0,1], text="Accuracy")
fig.update_traces(texttemplate="%{text:.2f}", textposition="outside")
fig.update_layout(height=350, coloraxis_showscale=False)
st.plotly_chart(fig, width='stretch')

# False positives / negatives
st.subheader("Errors")

tab1, tab2 = st.tabs([
    f"False Positives ({len(report['false_positives'])})",
    f"False Negatives ({len(report['false_negatives'])})"
])

with tab1:
    if report["false_positives"]:
        st.dataframe(pd.DataFrame(report["false_positives"])[
            ["id", "source", "content_preview", "confidence"]
        ], width='stretch', hide_index=True)
    else:
        st.success("No false positives")

with tab2:
    if report["false_negatives"]:
        st.dataframe(pd.DataFrame(report["false_negatives"])[
            ["id","source", "true_attack", "content_preview"]
        ], width='stretch', hide_index=True)
    else:
        st.success("No false negatives")
