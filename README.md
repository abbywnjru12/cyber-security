# Security Log Analyzer

**A Python-based defensive security tool for detecting repeated SSH authentication failures in system logs.**

This project demonstrates practical foundations in security monitoring, log parsing, alert thresholds, input validation, and automated testing. It is designed as a learning portfolio project and uses synthetic sample data.

## Project overview

Repeated failed SSH logins can indicate password guessing or brute-force activity. This command-line utility parses SSH authentication log entries, counts failed attempts by source IP address, and reports addresses that meet a configurable threshold.

### Key capabilities

- Parses SSH `Failed password` log entries.
- Aggregates failed attempts by source IP address.
- Supports a configurable alert threshold.
- Handles missing files and invalid command-line arguments.
- Includes synthetic sample data and automated unit tests.
- Uses only the Python standard library.

## Quick start

**Requirements:** Python 3.9 or later. No third-party packages are required.

```bash
python log_analyzer.py sample_auth.log
```

Set a different threshold:

```bash
python log_analyzer.py sample_auth.log --threshold 2
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Example output

```text
Security Log Analysis
=====================
Log file: sample_auth.log
Alert threshold: 3 failed attempts

ALERT: 203.0.113.10 — 4 failed login attempts
ALERT: 198.51.100.22 — 3 failed login attempts

Summary: 2 source IP address(es) met the alert threshold.
```

The IP addresses in `sample_auth.log` are documentation-only example addresses; they do not identify real attack sources.

## Repository structure

```text
cybersecurity-portfolio/
├── docs/
│   └── methodology.md
├── tests/
│   └── test_log_analyzer.py
├── .gitignore
├── LICENSE
├── README.md
├── SECURITY.md
├── log_analyzer.py
└── sample_auth.log
```

## Technical approach

1. Read the supplied log file line by line.
2. Select entries containing the SSH failure marker.
3. Extract the source IPv4 address using a regular expression.
4. Count failures per source address.
5. Report addresses whose count is greater than or equal to the selected threshold.

## Scope and limitations

This is a small defensive analysis tool, not a production intrusion detection system. It does not block IP addresses, verify whether an event is malicious, correlate events across hosts, or detect every authentication attack pattern. Log formats vary, so parsing should be validated against the target system before operational use.

## Security and responsible use

Use this tool only on logs you own or are authorized to analyze. Review `SECURITY.md` before using real log data. Remove usernames, hostnames, public IP addresses, and other sensitive information before sharing logs in a public repository.

## Author

**Abigael Wanjiru**  
Cybersecurity learning portfolio project

This repository is a self-directed demonstration project. It should not be interpreted as evidence of employment, certification, or professional penetration-testing experience.
