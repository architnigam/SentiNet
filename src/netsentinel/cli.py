"""Offline analysis CLI. Capture and configuration errors never print tracebacks."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from .config import load_settings
from .errors import NetSentinelError
from .pipeline import MAX_SAMPLE_PACKETS, analyze_capture


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _sample_count(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 0 <= number <= MAX_SAMPLE_PACKETS:
        raise argparse.ArgumentTypeError(f"must be between 0 and {MAX_SAMPLE_PACKETS}")
    return number


def _same_file(first: Path, second: Path) -> bool:
    return first.resolve() == second.resolve() or (
        first.exists() and second.exists() and first.samefile(second)
    )


def write_report(path: Path, text: str) -> None:
    """Replace a report atomically, leaving an old report intact on write failure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".netsentinel-", suffix=".tmp",
                                         delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetSentinel: analyze an authorized offline PCAP/PCAPNG.")
    parser.add_argument("--pcap", type=Path, required=True, help="Uncompressed PCAP or PCAPNG input")
    parser.add_argument("--config", type=Path, help="JSON configuration; omitted fields use defaults")
    parser.add_argument("--output", type=Path, help="Also save the JSON summary atomically to this file")
    parser.add_argument("--limit", type=_positive, help="Maximum frames to analyze (including skipped frames)")
    parser.add_argument("--sample-limit", type=_sample_count, default=10, help="Sample records to retain (0–1000; default 10)")
    parser.add_argument("--detect", action="store_true", help="Enable Part 2 detection and JSON Lines alert logging")
    parser.add_argument("--alert-log", type=Path, help="Override configured alert log (requires --detect)")
    args = parser.parse_args(argv)
    if args.alert_log is not None and not args.detect:
        parser.error("--alert-log requires --detect")
    try:
        if args.output is not None:
            inputs = [args.pcap] + ([args.config] if args.config is not None else [])
            if any(_same_file(args.output, source) for source in inputs):
                raise NetSentinelError("Output must not overwrite the capture or configuration file.")
        settings = load_settings(args.config)
        alert_log = args.alert_log if args.alert_log is not None else Path(settings.alert_log_path)
        if args.detect:
            protected = [args.pcap] + ([args.config] if args.config is not None else [])
            if args.output is not None:
                protected.append(args.output)
            if any(_same_file(alert_log, other) for other in protected):
                raise NetSentinelError("Alert log must not overwrite the capture, configuration, or summary output.")
        report = analyze_capture(args.pcap, settings=settings, packet_limit=args.limit, sample_limit=args.sample_limit,
                                 detect=args.detect, alert_log_path=alert_log if args.detect else None)
        text = json.dumps(report, indent=2, allow_nan=False)
        if args.output is not None:
            write_report(args.output, text)
        print(text)
        return 0
    except (NetSentinelError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted; no completed report was produced.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
