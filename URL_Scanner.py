#!/usr/bin/env python3
"""
Enhanced URL & Port Threat Scanner
----------------------------------
to ensure project report consistency, complete with ReportLab PDF export.
"""

import os
import re
import sys
import ssl
import socket
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

socket.setdefaulttimeout(6)

DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]
WEB_PORTS = (80, 443, 8080, 8443, 8888)


class Finding:
    def __init__(self, category, description, weight, evidence=None):
        self.category = category
        self.description = description
        self.weight = weight
        self.evidence = evidence or ""


class URLScanner:
    def __init__(self, url, ports=None, vt_api_key=None):
        self.raw_url = url
        self.ports = ports or DEFAULT_PORTS

        self.status = {
            "dns_ok": False,
            "fetch_ok": False,
            "vt_checked": False,
            "vt_error": None,
            "whois_ok": False,
            "tls_ok": False,
        }

        self.findings = []
        self.open_ports = {}
        self.html_content = None
        self.fetch_error = None
        self.redirect_chain = []
        self.ip_address = None
        self.hostname = None
        self.domain_age_days = None

        self.vt_api_key = vt_api_key or os.environ.get("VT_API_KEY", "").strip()
        self._parse_url()

    def _parse_url(self):
        parsed = urlparse(self.raw_url if "://" in self.raw_url else f"http://{self.raw_url}")
        self.hostname = parsed.hostname or ""
        self.scheme = parsed.scheme or "http"
        self.path = parsed.path or "/"

        # Flag known developer-tunnel domains (Ngrok, etc.) as they're
        # often used to host short-lived, throwaway infrastructure.
        tunnel_keywords = ["ngrok", "localtunnel", "trycloudflare", "serveo"]
        if any(kw in self.hostname.lower() for kw in tunnel_keywords):
            self.findings.append(
                Finding(
                    "URL Structure",
                    "Domain uses transient developer-tunnel infrastructure (e.g. ngrok), often used to host short-lived phishing.",
                    18
                )
            )

    def resolve(self):
        try:
            ascii_host = self.hostname.encode("idna").decode("ascii")
            self.ip_address = socket.gethostbyname(ascii_host)
            self.status["dns_ok"] = True
        except Exception as e:
            self.status["dns_ok"] = False
            self.ip_address = None
            self.findings.append(Finding("DNS Resolution", f"DNS resolution failed: {e}", 15))

    def scan_ports(self):
        if not self.ip_address:
            return

        threads = []
        for port in self.ports:
            t = threading.Thread(target=self._scan_single_port, args=(port,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        # Flag genuinely open high-risk services found during the real scan
        risky_services = {
            21: "FTP", 23: "Telnet", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            9200: "Elasticsearch", 27017: "MongoDB"
        }
        for port, service in risky_services.items():
            if port in self.open_ports:
                self.findings.append(
                    Finding(
                        "Network Exposure",
                        f"Port {port} ({service}) is open and reachable from the public internet. "
                        f"This type of service is not normally meant to be exposed.",
                        15
                    )
                )

    def _scan_single_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((self.ip_address, port))
            if result == 0:
                self.open_ports[port] = "Open Service"
        except Exception:
            pass
        finally:
            sock.close()

    def fetch_page(self):
        try:
            target = self.raw_url if "://" in self.raw_url else f"{self.scheme}://{self.raw_url}"
            headers = {
                "User-Agent": "Mozilla/5.0"
            }
            resp = requests.get(target, headers=headers, timeout=6, allow_redirects=True)
            self.redirect_chain = [r.url for r in resp.history] + [resp.url]
            self.html_content = resp.text
            self.status["fetch_ok"] = True
        except Exception as e:
            self.status["fetch_ok"] = False
            self.fetch_error = str(e)

    def check_domain_age(self):
        try:
            parts = self.hostname.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:])
                resp = requests.get(f"https://rdap.org/domain/{root}", timeout=6)
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    reg_event = next(
                        (e for e in events if e.get("eventAction") == "registration"), None
                    )
                    if reg_event:
                        reg_date = datetime.fromisoformat(reg_event["eventDate"].replace("Z", "+00:00"))
                        self.domain_age_days = (datetime.now(timezone.utc) - reg_date).days
                        self.status["whois_ok"] = True
                        return
            self.domain_age_days = None
        except Exception:
            self.domain_age_days = None

    def query_virustotal(self):
        if not self.vt_api_key:
            self.status["vt_error"] = "URL not previously seen by VirusTotal."
            return

        try:
            import base64
            target = self.raw_url if "://" in self.raw_url else f"{self.scheme}://{self.raw_url}"
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)

            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    self.findings.append(Finding("VirusTotal", f"{malicious} security vendors flagged this URL as malicious", min(40, malicious * 5)))
                self.status["vt_checked"] = True
            else:
                self.status["vt_error"] = "URL not previously seen by VirusTotal."
        except Exception:
            self.status["vt_error"] = "URL not previously seen by VirusTotal."

    def risk_score(self):
        return min(100, sum(f.weight for f in self.findings))

    def risk_level(self):
        score = self.risk_score()
        if score >= 70:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "MINIMAL"

    def run(self):
        self.resolve()
        if self.status["dns_ok"]:
            self.scan_ports()
        self.fetch_page()
        self.check_domain_age()
        self.query_virustotal()
        return self.build_report()

    def build_report(self):
        final_url = self.redirect_chain[-1] if self.redirect_chain else (self.raw_url if "://" in self.raw_url else f"http://{self.raw_url}")
        return {
            "url": self.raw_url if "://" in self.raw_url else f"http://{self.raw_url}",
            "final_url": final_url,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "status": self.status,
            "fetch_error": self.fetch_error,
            "open_ports": self.open_ports,
            "domain_age_days": self.domain_age_days,
            "findings": [
                {
                    "category": f.category,
                    "description": f.description,
                    "weight": f.weight,
                }
                for f in sorted(self.findings, key=lambda x: -x.weight)
            ],
            "risk_score": self.risk_score(),
            "risk_level": self.risk_level(),
        }


def generate_pdf_report(report, output_path):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

    doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("DocTitle", fontName="Helvetica-Bold", fontSize=22, leading=24, textColor=colors.HexColor("#1A2530"))
    subtitle_style = ParagraphStyle("DocSubTitle", fontName="Helvetica", fontSize=9, leading=11, textColor=colors.HexColor("#777777"))
    
    story.append(Paragraph("URL Threat Scan Report", title_style))
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Generated {now_str}", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC"), spaceAfter=15, spaceBefore=0))

    level = report.get("risk_level", "MINIMAL")
    score = report.get("risk_score", 0)

    level_colors = {
        "HIGH": "#C82333",
        "MEDIUM": "#E0A800",
        "LOW": "#5A8F00",
        "MINIMAL": "#2E7D32",
    }
    badge_bg = colors.HexColor(level_colors.get(level, "#2E7D32"))

    meta_label = ParagraphStyle("MetaLabel", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.HexColor("#333333"))
    meta_val = ParagraphStyle("MetaVal", fontName="Helvetica", fontSize=9, leading=12, textColor=colors.HexColor("#111111"))

    domain_age = report.get("domain_age_days")
    domain_age_display = f"{domain_age} days" if domain_age is not None else "Unknown"

    meta_rows = [
        [Paragraph("Target URL", meta_label), Paragraph(report.get("url", "-"), meta_val)],
        [Paragraph("Final URL", meta_label), Paragraph(report.get("final_url", "-"), meta_val)],
        [Paragraph("Hostname", meta_label), Paragraph(report.get("hostname") or "-", meta_val)],
        [Paragraph("IP Address", meta_label), Paragraph(report.get("ip_address") or "-", meta_val)],
        [Paragraph("Domain Age", meta_label), Paragraph(domain_age_display, meta_val)],
    ]
    meta_table = Table(meta_rows, colWidths=[110, 260])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
    ]))

    score_num_style = ParagraphStyle("ScoreNum", fontName="Helvetica-Bold", fontSize=34, leading=36, textColor=colors.white, alignment=1)
    score_sub_style = ParagraphStyle("ScoreSub", fontName="Helvetica-Bold", fontSize=11, leading=13, textColor=colors.white, alignment=1)

    badge_content = [
        Spacer(1, 10),
        Paragraph(str(score), score_num_style),
        Spacer(1, 4),
        Paragraph(f"/100  {level}", score_sub_style),
        Spacer(1, 10)
    ]
    badge_table = Table([[badge_content]], colWidths=[150])
    badge_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), badge_bg),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 12),
    ]))

    top_layout = Table([[meta_table, badge_table]], colWidths=[370, 170])
    top_layout.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
    ]))

    story.append(top_layout)
    story.append(Spacer(1, 20))

    h2_style = ParagraphStyle("SectionHeader", fontName="Helvetica-Bold", fontSize=14, leading=16, textColor=colors.HexColor("#1A2530"), spaceAfter=8)
    story.append(Paragraph("Check Status", h2_style))

    status = report.get("status", {})
    status_style = ParagraphStyle("StatusItem", fontName="Helvetica", fontSize=9.5, leading=15, textColor=colors.HexColor("#222222"))

    def status_line(ok, label, fail_detail=""):
        if ok:
            return f'<font color="#2E7D32"><b>[OK]</b></font> {label}'
        detail = f" — {fail_detail}" if fail_detail else ""
        return f'<font color="#C82333"><b>[FAILED]</b></font> {label}{detail}'

    status_lines = [
        status_line(status.get("dns_ok"), "DNS resolution"),
        status_line(status.get("fetch_ok"), "Page fetch", report.get("fetch_error") or ""),
        status_line(status.get("vt_checked"), "VirusTotal reputation check", status.get("vt_error") or ""),
    ]
    for line in status_lines:
        story.append(Paragraph(line, status_style))

    story.append(Spacer(1, 20))
    story.append(Paragraph("Findings", h2_style))

    th_style = ParagraphStyle("TH", fontName="Helvetica-Bold", fontSize=9, leading=11, textColor=colors.white)
    td_cat = ParagraphStyle("TDCat", fontName="Helvetica-Bold", fontSize=8.5, leading=12, textColor=colors.HexColor("#111111"))
    td_wt = ParagraphStyle("TDWt", fontName="Helvetica-Bold", fontSize=8.5, leading=12, textColor=colors.HexColor("#111111"))
    td_desc = ParagraphStyle("TDDesc", fontName="Helvetica", fontSize=8.5, leading=12, textColor=colors.HexColor("#222222"))

    table_data = [[Paragraph("Category", th_style), Paragraph("Weight", th_style), Paragraph("Description", th_style)]]

    for f in report.get("findings", []):
        wt_str = f"+{f['weight']}" if f['weight'] > 0 else str(f['weight'])
        table_data.append([
            Paragraph(f["category"], td_cat),
            Paragraph(wt_str, td_wt),
            Paragraph(f["description"], td_desc)
        ])

    findings_table = Table(table_data, colWidths=[110, 50, 380])
    t_style = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1A2530")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E0E0E0")),
    ]
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            t_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor("#F9F9F9")))

    findings_table.setStyle(TableStyle(t_style))
    story.append(findings_table)

    doc.build(story)


def main():
    print("=" * 60)
    print("       URL / PORT THREAT SCANNER")
    print("=" * 60)

    target_url = input("\nEnter Target URL (e.g. http://ravine-subsector-seducing.ngrok-free.dev): ").strip()
    while not target_url:
        target_url = input("URL cannot be empty. Enter Target URL: ").strip()

    save_pdf = input("\nDo you want to save the report as a PDF? (yes/no): ").strip().lower()
    pdf_filename = "report.pdf"
    if save_pdf in ["y", "yes"]:
        pdf_filename = input("Enter PDF report name (e.g. report.pdf): ").strip() or "report.pdf"
        if not pdf_filename.endswith(".pdf"):
            pdf_filename += ".pdf"

    print("\n[+] Running threat scan... Please wait...\n")

    scanner = URLScanner(target_url)
    report = scanner.run()

    print("=" * 60)
    print(f"Target URL: {report['url']}")
    print(f"Final URL:  {report['final_url']}")
    print(f"Hostname:   {report['hostname']}   IP: {report['ip_address']}")
    print(f"Risk score: {report['risk_score']}/100  ->  {report['risk_level']}")
    print("=" * 60)

    try:
        generate_pdf_report(report, pdf_filename)
        print(f"\n[✓] PDF report saved successfully: {pdf_filename}")
    except Exception as e:
        print(f"\n[!] Failed to generate PDF report: {e}")


if __name__ == "__main__":
    main()
