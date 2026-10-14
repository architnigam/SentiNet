# NetSentinel

Intelligent Network Intrusion Detection & Threat Analysis System

NetSentinel is a Python-based mini intrusion detection system (IDS) designed to
analyze network traffic, detect suspicious behavior, assign risk scores, and show
security alerts in a dashboard. The repository folder is currently named `SentiNet`.

**Current status:** Project documentation and starter folder structure are ready.
The Python files are placeholders; packet capture, detection, logging, and the
dashboard still need to be implemented.

## Project scope

The project will include six features:

1. **Packet analysis:** Extract source/destination IP addresses, TCP/UDP protocol,
   source/destination ports, and TCP flags.
2. **Port-scan detection:** Detect one source contacting many destination ports
   within a short time window.
3. **SYN-flood detection:** Flag unusually high SYN activity and, where observable,
   incomplete TCP connection patterns.
4. **Traffic anomaly detection:** Flag unusually high packet rates from a source.
5. **Risk scoring:** Combine suspicious indicators into Low, Medium, High, or
   Critical severity.
6. **Dashboard and logs:** Display packet statistics, protocol distribution, and
   recent alerts; save alerts locally.

This is an IDS: it detects and alerts; it does not automatically block traffic.
The initial version uses rules, without machine learning, a database, a login
system, or a separate web frontend.

## Technology

| Tool | Purpose |
| --- | --- |
| Python | Core application and detection logic |
| Scapy | Read saved PCAP files and capture/analyze packets |
| Streamlit | Monitoring dashboard |
| JSON / JSON Lines | Configuration and local alert storage |
| Python unittest | Automated tests during implementation |

## How the system will work

```text
Live traffic or saved PCAP
            |
      Packet capture
            |
  Packet analysis and TCP/UDP classification
            |
      Detection engine
      |       |       |
 Port scan   SYN    Traffic anomaly
            flood
      |       |       |
        Risk scoring
            |
      Security alerts
            |
       Logs + dashboard
```

The three detection rules evaluate the same analyzed traffic independently.
Risk scoring then combines their findings for a source within a time window.

## Basic folder structure

```text
SentiNet/
|-- README.md
|-- requirements.txt
|-- .gitignore
|-- config/
|   `-- settings.example.json     # Starting thresholds and scoring values
|-- data/
|   `-- pcaps/                   # Authorized packet captures for testing
|-- logs/                        # Generated alert logs
|-- src/
|   `-- netsentinel/
|       |-- __init__.py
|       |-- pipeline.py          # Connect capture, analysis, detection, and alerts
|       |-- capture.py           # Live capture and offline PCAP reading
|       |-- analyzer.py          # Extract and normalize packet fields
|       |-- risk.py              # Calculate scores and severity
|       |-- alerts.py            # Format alerts and write JSON Lines logs
|       |-- detection/
|       |   |-- __init__.py
|       |   |-- port_scan.py
|       |   |-- syn_flood.py
|       |   `-- traffic_anomaly.py
|       `-- dashboard/
|           |-- __init__.py
|           `-- app.py           # Streamlit dashboard
`-- tests/
    `-- README.md                # Test cases to implement
```

Empty data and log folders contain `.gitkeep` files so Git preserves them.

## Setup procedure

Run these commands from the project folder using PowerShell, with Python 3
installed:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config\settings.example.json config\settings.json
```

The virtual environment keeps dependencies separate from other projects.
`config/settings.json` is the local configuration to load once the application
is implemented. No application startup command is available yet.

## Development steps

Follow these steps in order:

1. **Prepare the project.** Create the virtual environment, install dependencies,
   and copy the example configuration. This repository provides the structure
   for this step.
2. **Start with offline packet input.** Implement PCAP reading in `capture.py`
   and use an authorized sample in `data/pcaps/`. Add live capture after the
   offline workflow works; confirm capture permissions and platform prerequisites.
3. **Analyze packets.** In `analyzer.py`, extract timestamp, IP addresses,
   protocol, ports, TCP flags, and packet length. Skip unsupported packets safely
   and maintain packet/protocol counters.
4. **Detect port scans.** Track unique destination ports per source and target
   within the configured time window. Flag a source when the count reaches the
   threshold, and expire old observations.
5. **Detect abnormal SYN activity.** Count SYN packets without ACK per source
   and target within the window. Track connection progress where possible.
   Treat high SYN rates as suspicious indicators, not proof of an attack.
6. **Detect traffic anomalies.** Count packets per source within the same window
   and compare their rate with the configured threshold. Tune thresholds using
   normal lab traffic.
7. **Add risk scoring.** Combine active rule indicators per source within the
   window. Count each rule once per assessment so repeated packets do not
   repeatedly add the same score. Map the score to a severity level.
8. **Create security alerts.** Include timestamp, source/target, triggered rules,
   score, severity, and supporting counts. Append one JSON object per line to
   `logs/alerts.jsonl` and suppress duplicate alerts during the cooldown period.
9. **Connect the pipeline.** In `pipeline.py`, load configuration and connect
   packet input, analysis, detection, scoring, and logging. Keep capture separate
   from dashboard refreshes so refreshing the page does not start another capture.
10. **Build the dashboard.** Show total packets, TCP/UDP distribution, suspicious
    sources, and recent alerts. Read the pipeline's saved statistics and alerts.
11. **Test and tune.** Test normal traffic, scan patterns, high SYN rates, traffic
    bursts, window expiry, and duplicate suppression. Check that scores, logs,
    and displayed statistics agree, then adjust thresholds to reduce false alerts.
12. **Document and demonstrate.** Add startup commands once implemented. Prepare
    an authorized PCAP demonstration and record the observed detections and
    limitations.

## Initial detection settings

`config/settings.example.json` supplies proposed starting values:

| Setting | Initial value |
| --- | --- |
| Observation window | 10 seconds |
| Port-scan threshold | 20 unique destination ports per source/target/window |
| SYN threshold | 100 SYN packets without ACK per source/target/window |
| Traffic threshold | 200 packets per second per source over the window |
| Duplicate alert cooldown | 30 seconds per source/target/rule combination |
| Indicator weights | Port scan: 30; SYN flood: 40; traffic anomaly: 30 |
| Severity ranges | Low: 1–24; Medium: 25–49; High: 50–74; Critical: 75–100 |

A score of zero produces no alert. These values are lab defaults to implement
and tune, not validated production detection settings.

## Planned usage procedure

Once the implementation is ready:

1. Select an authorized PCAP or a lab network interface.
2. Load the local configuration and start the monitoring pipeline.
3. Open the Streamlit dashboard to inspect traffic statistics and alerts.
4. Review `logs/alerts.jsonl` for the evidence behind each alert.
5. Stop capture cleanly and preserve any results needed for the demonstration.

Use only your own/local lab traffic or saved captures you are authorized to
analyze. Keep packet captures and generated logs out of version control.
