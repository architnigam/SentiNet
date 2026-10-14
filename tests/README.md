# Planned tests

Add Python `unittest` test cases as each module is implemented:

- Packet parsing: TCP, UDP, unsupported packets, and missing fields.
- Port scans: repeated ports, distinct ports, threshold boundaries, and separate targets.
- SYN activity: SYN versus SYN-ACK, normal handshakes, and high SYN counts.
- Traffic anomalies: packet rates below, at, and above the configured threshold.
- Time windows: expired observations, PCAP timestamps, and state cleanup.
- Risk scoring: each indicator combination, severity boundaries, and zero-score behavior.
- Alerts: required fields, valid JSON Lines, cooldown behavior, and log creation.
- Pipeline: an authorized sample PCAP produces consistent counters and expected alerts.

Use synthetic packet objects for rule tests so they do not require live capture.
No automated tests or working application modules are included yet.
