"""Read-only Streamlit monitor. Refreshes never start capture or rewrite reports."""

import json
import os
from pathlib import Path
import time

import pandas as pd
import streamlit as st

from netsentinel.dashboard.data import (
    DashboardDataError, SEVERITIES, alert_rows, read_recent_alerts, read_snapshot,
)


def default_snapshot() -> str:
    configured = os.environ.get("NETSENTINEL_REPORT")
    if configured:
        return configured
    for path in ("logs/threat_summary.json", "logs/summary.json", "logs/live_summary.json"):
        if Path(path).is_file():
            return path
    return "logs/live_summary.json"


def main():
    st.set_page_config(page_title="NetSentinel | Security Monitor", page_icon="🛡️", layout="wide")
    st.title("NetSentinel")
    st.caption("NETWORK SECURITY MONITOR · Packet visibility, detection evidence, and risk")
    with st.sidebar:
        st.header("Monitoring source")
        report_path = st.text_input("Snapshot file", value=default_snapshot())
        log_path = st.text_input("Alert log override (optional)", value="")
        auto_refresh = st.toggle("Refresh every 2 seconds", value=True)
        severities = st.multiselect("Severity", list(SEVERITIES), default=list(SEVERITIES))
        source_filter = st.text_input("Filter source or destination", value="")
        st.caption("Capture runs in a separate terminal. This dashboard only reads files.")
        st.button("Refresh now")

    @st.fragment(run_every=2.0 if auto_refresh else None)
    def render():
        try:
            report = read_snapshot(report_path)
        except DashboardDataError as exc:
            st.warning(str(exc))
            st.info("Generate a report with the NetSentinel CLI, or select an existing snapshot in the sidebar.")
            return
        monitor = report.get("monitor")
        if monitor:
            status = monitor["status"]
            st.caption(f"Live interface: {monitor['interface']} · Status: {status.upper()}")
            if status == "failed":
                st.error(monitor.get("error") or "Capture failed; inspect the capture terminal.")
            elif status in ("starting", "running") and time.time() - monitor["updated_at"] > 10:
                st.warning("The live snapshot is stale. Check whether the capture process is still running.")
            elif status == "stopped":
                st.info("Capture stopped. The last collected results remain available.")
        else:
            st.caption("Completed offline analysis")
        stats = report["statistics"]
        detection = report.get("detection", {})
        columns = st.columns(4)
        for column, label, value in zip(columns,
                ("Packets observed", "Packets analyzed", "Packets skipped", "Alerts emitted"),
                (stats["total_packets"], stats["analyzed_packets"], stats["skipped_packets"], detection.get("alerts_emitted", 0))):
            column.metric(label, f"{value:,}")
        left, right = st.columns(2)
        with left:
            st.subheader("Protocol distribution")
            protocols = pd.DataFrame([{"Protocol": key, "Packets": value}
                                      for key, value in stats["protocol_counts"].items()])
            st.bar_chart(protocols, x="Protocol", y="Packets", color="#38bdf8")
        with right:
            st.subheader("Tracked source activity")
            sources = sorted(stats.get("source_counts", {}).items(), key=lambda item: item[1], reverse=True)[:10]
            if sources:
                st.bar_chart(pd.DataFrame(sources, columns=["Source", "Packets"]), x="Source", y="Packets", color="#a78bfa")
            else:
                st.info("No analyzed sources yet.")
            st.caption("Up to 10 of the tracked sources; source tracking is bounded.")
        alerts = report.get("recent_alerts", [])
        if log_path.strip():
            alerts, messages = read_recent_alerts(log_path, run_id=detection.get("run_id"))
            for message in messages:
                st.warning(message)
        st.subheader("Recent security alerts")
        rows = alert_rows(alerts, severities, source_filter)
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            with st.expander("Detection evidence"):
                for alert in reversed(alerts):
                    if alert_rows([alert], severities, source_filter):
                        st.json(alert)
        else:
            st.info("No alerts match the selected filters.")
        with st.expander("Packet statistics and sample"):
            st.json(stats)
            st.json(report.get("sample_packets", []))
        st.download_button("Download snapshot", data=json.dumps(report, indent=2),
                           file_name="netsentinel-summary.json", mime="application/json")
        st.caption(f"Source: {report.get('source', 'Unknown')} · Snapshot: {report_path}")

    render()


if __name__ == "__main__":
    main()
