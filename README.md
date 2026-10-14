# NetSentinel

**Intelligent Network Intrusion Detection & Threat Analysis System**

NetSentinel is a Python project for analyzing network traffic, detecting
suspicious behavior, assigning risk scores, and displaying security alerts.
It is an IDS: it detects and alerts; it does not automatically block traffic.

**Status: Parts 1 and 2 are implemented and tested. Part 3 is planned.**
The repository folder is named `SentiNet`; the Python package is `netsentinel`.

## The three project parts

| Part | Work included | Status |
| --- | --- | --- |
| **1. Packet-analysis foundation** | Configuration validation, offline PCAP/PCAPNG input, IPv4/IPv6 TCP/UDP analysis, statistics, CLI, JSON reports, synthetic demo, tests | Complete |
| **2. Detection and security alerts** | Port scans, abnormal SYN activity, traffic-rate anomalies, window management, risk scoring, JSON Lines alerts, duplicate suppression, tests | Complete |
| **3. Live monitoring and dashboard** | Live capture, interface selection, clean shutdown, Streamlit statistics and alerts, integration tests, demonstration | Planned |

Each part has test requirements in [tests/README.md](tests/README.md).
The initial project uses **Python + Scapy + Streamlit**, without machine learning,
a database, a login system, or a separate web frontend.

## System procedure

```text
Part 1: Saved PCAP/PCAPNG -> Validate capture -> Parse packets -> Statistics
                                                 |
Part 2:                         Detection rules -> Risk score -> Alert logs
                                                                    |
Part 3: Live capture feeds the same pipeline -> Streamlit dashboard <-+
```

The three detection rules evaluate the same analyzed traffic independently.
The default command performs Part 1 analysis; add `--detect` for Part 2 rules and alerts.

## Setup

Use **Python 3.10 or newer**. From the project folder in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

This installs the local package and Scapy. Streamlit will be needed in Part 3.
The commands use the virtual environment directly, so activation is unnecessary.

Configuration is optional. To customize it, copy the example once:

```powershell
Copy-Item config\settings.example.json config\settings.json
```

If `--config` is omitted, built-in defaults are used. If supplied, that file
must exist and be valid JSON. Missing fields use defaults; unknown/duplicate keys,
wrong types, invalid thresholds, and invalid score ranges are rejected.
Paths are relative to the working directory. Detection settings are validated and
included in the report; rules use them when `--detect` is enabled. Window length is
limited to 1–86,400 seconds, cooldown to 0–604,800 seconds, and count/rate thresholds
to 1–1,000,000,000. Rule weights are positive integers totaling at most 100; severity
thresholds start at 1 and strictly increase to at most 100.

## Run Part 1

Create a synthetic demo capture, then analyze it:

```powershell
.\.venv\Scripts\python.exe examples\create_demo_capture.py
.\.venv\Scripts\python.exe -m netsentinel --pcap data\pcaps\demo.pcap --output logs\summary.json
```

The demo writes packets to a file and **does not transmit traffic**. Running it
again replaces the generated demo file. Expected results:

| Result | Expected value |
| --- | --- |
| Total packets | 8 |
| Analyzed packets | 5: 3 TCP + 2 UDP |
| Skipped packets | 3: ARP, ICMP, and one fragment |
| Capture duration | 1.75 seconds |

To analyze another authorized capture with custom options:

```powershell
.\.venv\Scripts\python.exe -m netsentinel --pcap data\pcaps\sample.pcapng --config config\settings.json --limit 1000 --sample-limit 10 --output logs\summary.json
```

Replace `sample.pcapng` with your own file. An installed console command is also
available at `.\.venv\Scripts\netsentinel.exe` on Windows.

| Option | Meaning |
| --- | --- |
| `--pcap` | Required uncompressed PCAP/PCAPNG input |
| `--config` | Optional JSON configuration file |
| `--limit` | Positive maximum raw frames to process, including skipped frames |
| `--sample-limit` | Keep the first 0–1000 analyzed records; default 10 |
| `--output` | Also save the JSON report to a file |
| `--help` | Show command help |
| `--detect` | Enable detection and JSON Lines alert logging |
| `--alert-log` | Override the configured log path; requires `--detect` |

JSON is printed to standard output. Errors go to standard error. Exit codes:
`0` success, `1` capture/configuration/output error, `2` invalid CLI arguments,
`130` interruption. A corrupt capture produces no completed report. Output is
replaced atomically after successful analysis; `--output` cannot overwrite the
capture or explicit configuration, including through a hard link.

## Run Part 2

Generate synthetic suspicious traffic and analyze it with detection enabled:

```powershell
.\.venv\Scripts\python.exe examples\create_detection_demo.py
.\.venv\Scripts\python.exe -m netsentinel --pcap data\pcaps\threat_demo.pcap --detect --alert-log logs\threat_alerts.jsonl --output logs\threat_summary.json
```

The generator writes **2,000 synthetic SYN packets** to a file and never transmits
them. Using default settings, the report contains three escalating alerts:

| Trigger | Active rules | Score | Severity |
| --- | --- | --- | --- |
| Packet 20 | Port scan | 30 | Medium |
| Packet 100 | Port scan + SYN flood | 70 | High |
| Packet 2,000 | Port scan + SYN flood + traffic anomaly | 100 | Critical |

To use your own capture and configuration:

```powershell
.\.venv\Scripts\python.exe -m netsentinel --pcap data\pcaps\sample.pcap --config config\settings.json --detect --output logs\summary.json
```

Without `--alert-log`, alerts are appended to `alert_log_path` in the configuration
(default `logs/alerts.jsonl`). Logs preserve previous runs; each run/alert has a
unique ID. Replaying a capture adds new alerts rather than deduplicating across runs.
The summary contains the current run's counters and its latest 100 alerts. Detection
reports use schema version 2; analysis-only reports retain schema version 1. Alert
records have their own schema version 1.

## Detection and scoring procedure

1. Process normalized TCP/UDP records in capture order. All thresholds include
   equality. The rolling window is **(current time − window length, current time]**;
   an event exactly one window old expires.
2. For each source/target IP pair, count unique **(protocol, destination port)**
   pairs. Repeated packets/source-port changes do not increase this count. TCP 80
   and UDP 80 count separately. Default port-scan threshold: **20**.
3. For each source/target, count TCP packets with SYN set and ACK clear. Default
   threshold: **100**. Retransmissions count as packets but occupy one pending
   connection. SYN-ACK followed by an originating ACK marks observed completion;
   RST from either direction clears pending state. SYN+FIN/RST packets contribute
   to the SYN count but are not tracked as pending connections.
4. Count all analyzed TCP/UDP packets per source across destinations. Divide by
   the **full configured window**, including during startup. Default threshold:
   **200 packets/second over 10 seconds**, requiring 2,000 packets in the window.
5. Evaluate the current source/target's scan/SYN rules and the source-wide rate.
   Add each active rule's weight **once**: port scan 30, SYN flood 40, traffic 30.
   Recalculate from currently active indicators; expired indicators add nothing.
6. Map score to **Low 1–24 / Medium 25–49 / High 50–74 / Critical 75–100**.
   Zero produces no alert. Pure rate alerts have a null destination; when combined
   with pair-level rules, rate evidence still explicitly covers all destinations.
7. Suppress identical **source + target + active-rule-set** signatures for **30
   seconds** by default, measured from the last emitted alert. A changed rule set
   can alert immediately; the exact cooldown boundary permits another alert.
   Cooldown zero disables suppression.
8. Append the alert with timestamp, run/alert IDs, source/target, window, rules,
   score, severity, and supporting counts. Update emission/cooldown counters only
   after the log write succeeds.

Detection uses the latest accepted TCP/UDP timestamp as its watermark. Records
older than that watermark remain in packet statistics but are skipped by detection
and counted in `late_packets_skipped`. Equal timestamps are accepted. Cleanup
occurs as accepted packet time advances; offline analysis has no wall-clock timer.
Rules are evaluated for the current packet's source/target, rather than retroactively
reissuing alerts for every previously observed target when a source-wide rate changes.

## Detection limits and log handling

- Window state is incremental and bounded: **100,000 active events**, **16,384
  pending connections**, and **16,384 active alert cooldowns**. Exhaustion stops the
  run with a clear error rather than silently evicting observations. Library
  constructors expose these limits for tuning; larger configured detection thresholds
  still require enough state capacity to be reached.
- At most 20 destination ports are sampled in scan evidence. Aggregate counts
  remain complete within the window. The report retains only the latest 100 alerts;
  the JSON Lines file contains every successfully emitted alert.
- Handshake tracking uses IPs/ports and observed flags, without sequence validation
  or stream reassembly. SYN rate is a suspicious indicator, not proof of an attack;
  legitimate bursts, asymmetric capture, and incomplete capture can affect results.
  Rules operate per source (and per source/target), not aggregate distributed attacks
  from many unrelated sources.
- Logging supports **one writer per log file**. Records are limited to **1 MiB**,
  flushed and synced after each append. An existing log's final line must be complete,
  valid JSON with a recognized alert envelope; older lines are not rescanned.
  For a damaged tail, repair the file or choose a new `--alert-log` path.
- A write failure attempts to truncate the incomplete append and aborts detection.
  Rollback is best effort when the filesystem itself fails. Previously completed
  alerts remain if later detection, output, or interruption fails; summary output is
  replaced only after successful analysis. Logs are not a transactional database.
- The CLI rejects log aliases of its capture, configuration, or summary, including
  hard links. Detection and cooldown state reset for each run.

## What Part 1 implements

1. **Validate configuration** before analysis.
2. **Check the full capture container** for truncated headers/data, impossible
   lengths, unsupported versions, bad PCAPNG blocks/options, and invalid interfaces.
   The entire file is checked even with `--limit`.
3. **Read packets with Scapy**, one at a time, without retaining the whole capture.
4. **Extract fields:** timestamp, source/destination IP, IP version, TCP/UDP
   protocol, ports, TCP flag bits, captured/wire length, and truncation status.
5. **Skip unsupported or malformed packets safely**, record the reason, and
   continue. A damaged capture container fails the whole run.
6. **Aggregate statistics:** raw/analyzed/skipped counts, captured/wire bytes,
   protocol/source counts, time range, and timestamp ordering.
7. **Produce a bounded sample and JSON report** for inspection and future dashboard use.

## Supported behavior and limits

- PCAP 2.4: either byte order; microsecond or nanosecond timestamps.
- PCAPNG 1.0: one section, multiple interfaces, enhanced/obsolete/simple packet
  blocks, decimal/binary timestamp resolution. Unknown metadata blocks are ignored.
- Common Scapy link decoders include Ethernet, VLAN, raw IP, Linux cooked capture,
  and loopback. Unknown link types are counted as skipped.
- Outer IPv4/IPv6 TCP/UDP headers are analyzed, including common IPv6 extensions.
  Packet payload content is not inspected or saved in the report.
- Fragments, including atomic IPv6 fragments, are skipped: no reassembly yet.
  ARP/ICMP, tunnels, IPv6 jumbograms, and other unsupported protocols are skipped.
- Truncated payloads are accepted if network/transport headers are complete and
  declared lengths fit the original wire length. Truncated headers are skipped.
- Simple PCAPNG blocks lack timestamps and are skipped without inventing one.
  Nonzero PCAPNG timestamp offsets, multiple sections, and compressed captures are
  rejected explicitly. Checksums are not validated.
- Limit: **65,535 captured bytes per packet**, **16 MiB per PCAPNG block**.
  At most **4,096 distinct sources** are tracked in first-seen order; excess source
  packets are counted separately. Source counts are not top-source rankings.
- Time range uses minimum/maximum valid capture timestamps, including skipped
  packets. Timestamp descents are counted; packets are not sorted or replayed.
  JSON timestamps are floating-point seconds; nanosecond precision is not guaranteed.

On Windows, Scapy may print `No libpcap provider available`. Offline reading still
works; live capture prerequisites will be addressed in Part 3.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

For coverage:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m coverage run -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m coverage report -m
```

Parts 1 and 2 validation: **147 tests passed, no skips; 99% combined statement/branch
coverage** on Windows with Python 3.12.5 and Scapy 2.8.0. The detection engine,
three rule modules, risk scoring, and alert logging each have **100% statement and
branch coverage**. See
[tests/README.md](tests/README.md) for the test matrix and scope. Tests use synthetic
traffic and need no live capture privileges. The hard-link test can skip when a
filesystem or sandbox denies link creation; it passed in the validation run.
Coverage measures exercised code, not a guarantee that every possible edge case is absent.

## Folder structure

```text
SentiNet/
|-- README.md
|-- pyproject.toml               # Package, entry point, optional dependencies
|-- requirements.txt
|-- config/settings.example.json
|-- examples/create_demo_capture.py
|-- examples/create_detection_demo.py
|-- data/pcaps/                  # Authorized inputs (ignored by Git)
|-- logs/                       # Generated reports and future alerts (ignored)
|-- src/netsentinel/
|   |-- __init__.py
|   |-- __main__.py              # python -m netsentinel
|   |-- cli.py
|   |-- config.py
|   |-- errors.py
|   |-- models.py
|   |-- capture.py
|   |-- analyzer.py
|   |-- statistics.py
|   |-- pipeline.py
|   |-- risk.py                  # Part 2 scoring
|   |-- alerts.py                # Part 2 cooldowns and JSON Lines persistence
|   |-- detection/
|   |   |-- engine.py            # Rolling windows and observed handshakes
|   |   |-- port_scan.py
|   |   |-- syn_flood.py
|   |   `-- traffic_anomaly.py
|   `-- dashboard/app.py         # Part 3 placeholder
`-- tests/                       # Tests and acceptance matrix
```

## Next implementation steps

**Parts 1 and 2 are complete.** The example configuration supplies initial lab
thresholds to tune, not validated production detection settings.

**Part 3:** Feed live traffic through the same pipeline, publish statistics safely,
and build Streamlit independently of capture. Test lifecycle, permissions,
unavailable interfaces, missing/corrupt logs, refresh behavior, and the complete
packet-to-alert-to-dashboard workflow before demonstrating it.

Use only your own/local lab traffic or saved captures you are authorized to analyze.
