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

Coverage includes capture, analysis, configuration, statistics, pipeline, models,
errors, and CLI. Future detection/dashboard placeholders and the tiny package
launcher are excluded. Actual launchers are tested in subprocesses, which are
not included in the parent process's coverage measurement.

The hard-link test may skip where link creation is denied; the final validation
allowed it. Other Python versions/operating systems, real NIC traffic, and
detection/dashboard behavior have not yet been validated. High coverage and fuzz
samples do not prove that every malformed input is covered. Supported format
limits are explicit in the main README.

## Part 2: planned acceptance tests

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

Part 2 is complete when these behaviors have defined policies, working
implementations, and passing tests; documentation must explain deliberate limits.

## Part 3: planned acceptance tests

- Capture: interfaces, missing provider, permissions, start/stop/interruption,
  provider failures, resource cleanup (mocked for automation).
- Dashboard: empty/missing/corrupt files, partially appended lines, chart counts,
  severity display, bounded recent alerts, refresh consistency.
- Integration: one capture pipeline per session; refresh never starts another
  capture; safe statistics publication; visible capture failures.
- Demonstration: packet input -> rule evidence -> risk score -> alert log -> dashboard,
  using authorized local traffic and a repeatable offline fixture.

Real interface/provider checks need a suitable lab and are separate from mocked
tests. Record automated and actual lab results before calling Part 3 complete.
