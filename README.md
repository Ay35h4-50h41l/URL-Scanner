
# URL & Port Threat Scanner

A Python-based security tool that assesses the risk of a given URL/domain by combining network-level port scanning with reputation and metadata checks, and generates a professional PDF threat report.

## Overview

The scanner resolves a target's DNS, checks for commonly-exposed high-risk services via multi-threaded TCP port scanning, fetches the page to trace redirects, checks domain registration age, and queries the VirusTotal API for known malicious activity. All findings are weighted and combined into an overall risk score and risk level (MINIMAL / LOW / MEDIUM / HIGH), then exported as a clean PDF report.

## Features

- **DNS resolution** — resolves the target hostname to an IP address (supports IDNA/punycode hostnames)
- **Multi-threaded port scanning** — checks a configurable list of ports (default includes FTP, SSH, Telnet, SMTP, HTTP/S, SMB, MySQL, RDP, PostgreSQL, Redis, HTTP-alt ports, Elasticsearch, MongoDB) concurrently for speed
- **High-risk exposure flagging** — automatically raises findings when sensitive services (Telnet, SMB, databases, etc.) are found open and reachable from the internet
- **Developer-tunnel detection** — flags domains using transient tunnel infrastructure (ngrok, localtunnel, Cloudflare Tunnel, serveo), which are commonly abused for short-lived phishing
- **Page fetch & redirect tracing** — follows redirect chains to determine the final destination URL
- **Domain age lookup** — queries RDAP to estimate how long a domain has been registered (newer domains are a common phishing indicator)
- **VirusTotal integration** — checks the URL against VirusTotal's threat intelligence (requires a `VT_API_KEY` environment variable)
- **Weighted risk scoring** — combines all findings into a 0–100 risk score and a MINIMAL/LOW/MEDIUM/HIGH risk level
- **PDF report generation** — produces a polished PDF report (via ReportLab) with a risk badge, scan metadata, check status, and a findings table

## Tech Stack

- Python
- `socket`, `threading` — DNS resolution and concurrent port scanning
- `requests` — page fetching, RDAP domain-age lookup, VirusTotal API calls
- `reportlab` — PDF report generation

## How It Works

1. The target URL is parsed and checked for developer-tunnel indicators
2. DNS is resolved to an IP address
3. If resolution succeeds, all configured ports are scanned concurrently; any high-risk service found open is recorded as a finding
4. The page is fetched (following redirects) to determine the final URL
5. The domain's registration age is looked up via RDAP
6. The URL is checked against VirusTotal (if an API key is configured)
7. All findings are combined into a weighted risk score and risk level
8. A PDF report is generated summarizing the scan metadata, check status, and all findings

## How to Run

```
python url_scanner.py
```
You'll be prompted for a target URL and whether to save a PDF report.

To enable VirusTotal checks, set an environment variable before running:
```
export VT_API_KEY=your_api_key_here
```

## Notes

Some checks (VirusTotal, domain age) depend on external services and require network access / API keys. If a check can't be completed (e.g. no API key, RDAP lookup fails), it's reported as "Unknown"/"Failed" rather than assumed — the report always reflects the actual result of each check.

## Project Context

Built as a personal cybersecurity project exploring network reconnaissance, threat scoring, and automated report generation — inspired by tools like `nmap` combined with reputation-based threat intelligence.
