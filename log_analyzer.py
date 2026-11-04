#!/usr/bin/env python3
"""Analyze SSH authentication logs for repeated failed password attempts."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?.*? from "
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?:\s|$)"
)


def extract_source_ip(line: str) -> str | None:
    """Return a valid IPv4 source address from a failed-login log line."""
    if "Failed password" not in line:
        return None

    match = FAILED_LOGIN_PATTERN.search(line)
    if not match:
        return None

    candidate = match.group("ip")
    try:
        return str(ipaddress.IPv4Address(candidate))
    except ipaddress.AddressValueError:
        return None


def analyze_log(log_path: Path, threshold: int = 3) -> Dict[str, int]:
    """Count failed SSH logins and return sources meeting the threshold."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    counts: Counter[str] = Counter()
    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            source_ip = extract_source_ip(line)
            if source_ip:
                counts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in counts.items()
        if count >= threshold
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Identify source IPs with repeated failed SSH password attempts."
    )
    parser.add_argument("logfile", type=Path, help="Path to an SSH authentication log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum failed attempts required to trigger an alert (default: 3)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    if not args.logfile.is_file():
        print(f"Error: log file not found: {args.logfile}", file=sys.stderr)
        return 2

    try:
        findings = analyze_log(args.logfile, args.threshold)
    except OSError as exc:
        print(f"Error: unable to read log file: {exc}", file=sys.stderr)
        return 2

    print("Security Log Analysis")
    print("=====================")
    print(f"Log file: {args.logfile}")
    print(f"Alert threshold: {args.threshold} failed attempts")
    print()

    if findings:
        for source_ip, count in sorted(
            findings.items(), key=lambda item: (-item[1], item[0])
        ):
            print(f"ALERT: {source_ip} — {count} failed login attempts")
        print()
        print(f"Summary: {len(findings)} source IP address(es) met the alert threshold.")
    else:
        print("No source IP addresses met the alert threshold.")
        print("Summary: 0 alerts.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
