# Testing and acceptance criteria

## Part 1: implemented

Run from the repository root after installing the package:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests create temporary synthetic captures under `tests/.tmp/`, clean them up,
and never transmit packets. The suite includes table-driven subtests and a
deterministic sample of 225 random byte frames in addition to its named tests.

| Area | Covered cases | Test file |
| --- | --- | --- |
| Configuration | Defaults/example agreement; partial/nested overrides; immutable mappings; UTF-8 BOM; zero cooldown; unknown/duplicate keys; invalid types, numeric bounds, score ranges, paths, JSON/encoding, absent/unreadable files | `test_config.py` |
| PCAP input | Byte orders; micro/nanosecond timestamps; valid empty captures; zero-byte frames; snapshot truncation; unknown links; limits; bad versions/magic; partial headers/data; impossible lengths/fractions; permissions; resource cleanup | `test_capture.py` |
| PCAPNG input | Byte orders; multiple interfaces; enhanced/obsolete blocks; decimal/binary timestamps; zero offset; metadata; unlimited enhanced snapshot; timestamp-free simple packets; malformed sections/blocks/options; missing interfaces; unsupported cases | `test_capture.py` |
| Network parsing | IPv4/IPv6 TCP/UDP; zero/maximum ports; SYN/SYN-ACK/ACK/FIN/RST; VLAN/double VLAN; raw/cooked/loopback links; IP/TCP options; IPv6 extensions; fragments; unsupported protocols and tunnels | `test_analyzer.py` |
| Malformed packets | Missing/invalid timestamps/metadata; random data; partial link/IP/TCP/UDP headers; invalid lengths; excessive IPv6 extensions; Ethernet padding; complete headers with truncated payload | `test_analyzer.py` |
| Pipeline and statistics | Full synthetic workflow; exact counters; empty/bad captures; valid packet after bad packet; bounded samples; raw-frame limits; unordered/duplicate/zero timestamps; byte totals; truncation; timestamp-free packets; settings; stream cleanup; bounded sources | `test_pipeline.py` |
| CLI/output | Actual launchers; JSON stdout/file agreement; options; nested output; usage/help/exit codes; bad input; output failure; input/config alias protection; hard links; atomic replacement/cleanup; old-report preservation; interruption | `test_cli.py` |

Recorded validation on **2026-10-14**:

- Windows, Python **3.12.5**, Scapy **2.8.0**, coverage.py **7.16.2**.
- **73 tests passed with no failures or skips** in the unrestricted validation run.
- **99% combined statement/branch coverage** of implemented Part 1 modules.
- Manual demo: 8 raw packets, 5 analyzed records (3 TCP/2 UDP), 3 documented skips;
  the CLI saved a valid JSON summary.
- `pip check` passed; `git diff --check` passed.

For that initial Part 1 run, coverage included capture, analysis, configuration,
statistics, pipeline, models, errors, and CLI. Detection/dashboard placeholders
and the tiny package launcher were excluded. Actual launchers are tested in subprocesses, which are
not included in the parent process's coverage measurement.

The hard-link test may skip where link creation is denied; the final validation
allowed it. Other Python versions/operating systems and real NIC traffic have not
been validated. Detection and dashboard results are recorded below. High coverage and fuzz
samples do not prove that every malformed input is covered. Supported format
limits are explicit in the main README.

## Part 2: implemented

The complete suite now runs **147 tests with no failures or skips** in the
unrestricted Windows validation run. Overall combined statement/branch coverage is
**99%**. New engine, rule, risk, and alert-log modules have **100% statement and
branch coverage**. That Part 2 run included these modules and excluded the then-future
dashboard and tiny package launcher. Python/Scapy versions are unchanged from
the Part 1 validation above.

| Test file | Verified behavior |
| --- | --- |
| `test_detection.py` | Exact/below/above thresholds; unique TCP/UDP port policy; source/target isolation; fixed-denominator rate; window equality; expiry/cleanup; late/equal/large timestamps; SYN retransmissions; observed handshake progression; reverse resets; invalid inputs; bounded event/connection state; bounded evidence; 500-record independent brute-force window oracle |
| `test_alerts.py` | All eight rule combinations; duplicate-rule scoring; severity boundaries; custom scores; IDs/evidence; cooldown equality/zero/escalation/isolation; bounded cooldown state; fresh runs; persistence before cooldown updates; valid/reopened JSON Lines; corrupt/partial/nonstandard tails; exact/oversized records; large logs; permissions; short writes; sync/seek/rollback errors |
| `test_detection_pipeline.py` | Normal traffic baseline; scan/SYN/rate/combined indicators; empty/bad capture/log; late-packet counters; bounded recent alerts with complete persistence; configured/default log behavior; analysis-only compatibility; aliases including hard links; CLI flags/errors; retained completed alerts on later failure; synthetic threat escalation |
| `test_config.py` | Operational upper bounds for windows, cooldowns, and packet/port/rate thresholds |

The manual Part 2 demo verified 2,000 analyzed packets, scores **30 / 70 / 100**,
and **Medium / High / Critical** alerts. JSON stdout and summary output agree;
each alert is persisted in the JSON Lines log. `pip check` and `git diff --check`
pass. The two hard-link tests may skip inside the Windows sandbox; both passed
in the unrestricted final suite.

Implemented acceptance cases:

- Port scans: below/at/above unique-port threshold; repeated ports; separate
  sources/targets; TCP/UDP policy; exact window boundaries.
- SYN activity: SYN versus SYN-ACK/ACK; normal handshakes; retransmissions,
  resets, incomplete connections, separate flows.
- Traffic anomalies: rate calculation, threshold equality, idle intervals,
  bursts, separate sources.
- State: expiry, cleanup, timestamp ordering, clock policy, bounded tracking,
  sustained/high-cardinality input.
- Risk: all indicator combinations, no repeated rule contribution per assessment,
  zero score, severity boundaries, expired indicators.
- Alerts: required evidence, valid JSON Lines, cooldown boundaries, rule/source/target
  isolation, re-alerts, output creation, write failures.
- Integration: synthetic normal/scan/SYN/burst captures produce expected alerts
  and consistent statistics without false alerts for the normal baseline.

The README documents the policies and deliberate limits: accepted-packet capture
time, late-record exclusion, no sequence-number validation, source-wide rate scope,
per-pair correlation, single-writer logs with tail-only validation, bounded state,
and best-effort rollback. These tests do not claim that all possible inputs are
bug-free or that production traffic has been validated.

## Part 3: implemented and automatically tested

The full suite now passes **201 tests with zero failures and zero skips** in the
unrestricted Windows validation run. Overall statement/branch coverage is **99%**;
`live.py`, `runtime.py`, `storage.py`, `dashboard/app.py`, and `dashboard/data.py`
each have **100% statement and branch coverage**. The dashboard dependency is
Streamlit **1.66.0**; the full application now requires Python **3.11+**. Install
`requirements.txt` before running the full suite so widget tests have Streamlit.

| Test file | Verified behavior |
| --- | --- |
| `test_live.py` | Interface catalog/provider status; exact/ambiguous selection; metadata and truncation; single socket; no packet retention; count/duration bounds; idle heartbeat; stop events; callback failure propagation; permissions/backend failure; unexpected socket close; interruption; cleanup failure; invalid options |
| `test_runtime.py` | Shared packet-to-alert flow; incremental/atomic snapshots; idle/stopped/completed/failed status; Ctrl+C state; write failures; exclusive output/log ownership; PID locks/cleanup; output aliases; CLI listing/source/duration/limit handling; default output; clean errors |
| `test_dashboard.py` | Snapshot validation/size limits; count consistency; alert envelopes; bounded tails; incomplete/malformed log lines; run/severity/source filters; default paths; actual Streamlit metrics/charts/table/evidence; refresh with no capture/write side effects; path recovery; missing logs; provider failure; stale/fresh/stopped states; empty reports |

Streamlit `AppTest` runs the actual app and widgets, not a substitute renderer.
Socket/provider tests are deterministic mocks and send no traffic. Coverage
includes the dashboard and live code; only the tiny package launcher is excluded.
The remaining uncovered branches are existing defensive/launcher paths, not a
claim that every possible input has been proven safe.

Manual checks on this machine:

- Replayed the synthetic 2,000-packet threat capture: three escalating alerts,
  scores 30/70/100, with matching log and summary records.
- Started the local dashboard at **http://127.0.0.1:8501**. Its health endpoint
  returned **200 / ok**, and its HTML page returned **200**.
- Enumerated interfaces and attempted a real bounded capture on **Wi-Fi**. The
  machine lacks Npcap: capture exited with a clear error and wrote a failed-status
  snapshot. **Successful real NIC capture has not been validated.**
- Dependency and whitespace checks passed. Sandbox limitations on Streamlit
  temporary files and hard links required the final tests to run unrestricted.

Implemented acceptance cases:

- Capture: interfaces, missing provider, permissions, start/stop/interruption,
  provider failures, resource cleanup (mocked for automation).
- Dashboard: empty/missing/corrupt files, partially appended lines, chart counts,
  severity display, bounded recent alerts, refresh consistency.
- Integration: one capture pipeline per session; refresh never starts another
  capture; safe statistics publication; visible capture failures.
- Demonstration: packet input -> rule evidence -> risk score -> alert log -> dashboard,
  using authorized local traffic and a repeatable offline fixture.

Implementation and automated validation are complete. The remaining lab check is
successful authorized NIC capture after installing the missing driver. The
dashboard and mocked live tests do not establish lossless capture, production
detection accuracy, or compatibility with untested operating systems/providers.
