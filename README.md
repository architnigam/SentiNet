# NetSentinel

**Intelligent Network Intrusion Detection & Threat Analysis System**

NetSentinel is a Python project for analyzing network traffic, detecting
suspicious behavior, assigning risk scores, and displaying security alerts.
It is an IDS: it detects and alerts; it does not automatically block traffic.

**Status: Part 1 is implemented and tested. Parts 2 and 3 are planned.**
The repository folder is named `SentiNet`; the Python package is `netsentinel`.

## The three project parts

| Part | Work included | Status |
| --- | --- | --- |
| **1. Packet-analysis foundation** | Configuration validation, offline PCAP/PCAPNG input, IPv4/IPv6 TCP/UDP analysis, statistics, CLI, JSON reports, synthetic demo, tests | Complete |
| **2. Detection and security alerts** | Port scans, abnormal SYN activity, traffic-rate anomalies, window management, risk scoring, JSON Lines alerts, duplicate suppression, tests | Planned |
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

The three planned detection rules evaluate the same analyzed traffic independently.
Part 1 performs packet analysis only; it does not yet identify attacks or emit alerts.

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
included in the report now; their rules will be implemented in Part 2.

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

JSON is printed to standard output. Errors go to standard error. Exit codes:
`0` success, `1` capture/configuration/output error, `2` invalid CLI arguments,
`130` interruption. A corrupt capture produces no completed report. Output is
replaced atomically after successful analysis; `--output` cannot overwrite the
capture or explicit configuration, including through a hard link.

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

Part 1 validation: **73 tests passed, no skips; 99% combined statement/branch
coverage** on Windows with Python 3.12.5 and Scapy 2.8.0. See
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
|   |-- risk.py                  # Part 2 placeholder
|   |-- alerts.py                # Part 2 placeholder
|   |-- detection/               # Part 2 placeholders
|   |   |-- port_scan.py
|   |   |-- syn_flood.py
|   |   `-- traffic_anomaly.py
|   `-- dashboard/app.py         # Part 3 placeholder
`-- tests/                       # Tests and acceptance matrix
```

## Next implementation steps

**Part 2:** Implement time-windowed port/SYN/rate rules, correlate active indicators
without repeatedly adding a rule's weight, assign Low/Medium/High/Critical severity,
and write evidence-rich alerts with cooldowns. Test thresholds, expiry, timestamp
ordering, source/target isolation, connection progress, state limits, scoring
boundaries, and log failures. The example configuration supplies initial lab
thresholds to tune, not validated production detection settings.

**Part 3:** Feed live traffic through the same pipeline, publish statistics safely,
and build Streamlit independently of capture. Test lifecycle, permissions,
unavailable interfaces, missing/corrupt logs, refresh behavior, and the complete
packet-to-alert-to-dashboard workflow before demonstrating it.

Use only your own/local lab traffic or saved captures you are authorized to analyze.
