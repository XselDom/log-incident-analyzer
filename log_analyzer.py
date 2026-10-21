import re
import argparse
import json
from collections import defaultdict
from datetime import datetime

# Регулярные выражения для выявления сигнатур атак в URI и параметрах
ATTACK_SIGNATURES = {
    "SQL Injection (SQLi)": re.compile(
        r"(union.*select|select.*from|or\s+1=1|--|\'|\bexec\b|\bdrop\b|\bbenchmark\(|\bsleep\()",
        re.IGNORECASE
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(<script|%3Cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        re.IGNORECASE
    ),
    "Path Traversal / LFI": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini|windows/win\.ini)",
        re.IGNORECASE
    ),
    "Reconnaissance / Probe": re.compile(
        r"(\.env|wp-admin|phpmyadmin|\.git/config|eval-stdin\.php|actuator/health)",
        re.IGNORECASE
    )
}

# Регулярка для стандартного Common/Combined Log Format (Nginx, Apache)
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<uri>\S+) \S+" (?P<status>\d{3}) (?P<bytes>\S+)'
)

def analyze_logs(logfile_path: str, brute_threshold: int = 5) -> dict:
    suspicious_events = []
    ip_stats = defaultdict(lambda: {"total_requests": 0, "failed_requests": 0, "attacks_flagged": 0})
    attack_type_counter = defaultdict(int)

    with open(logfile_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            ip = match.group("ip")
            uri = match.group("uri")
            status = int(match.group("status"))
            method = match.group("method")

            ip_stats[ip]["total_requests"] += 1
            if status in [401, 403, 404]:
                ip_stats[ip]["failed_requests"] += 1

            # Поиск сигнатур атак
            for attack_type, pattern in ATTACK_SIGNATURES.items():
                if pattern.search(uri):
                    attack_type_counter[attack_type] += 1
                    ip_stats[ip]["attacks_flagged"] += 1
                    suspicious_events.append({
                        "line": line_num,
                        "ip": ip,
                        "method": method,
                        "attack_type": attack_type,
                        "uri": uri[:80],
                        "status": status
                    })

    # Выявление потенциального Brute-Force
    potential_bruteforce_ips = [
        ip for ip, data in ip_stats.items() if data["failed_requests"] >= brute_threshold
    ]

    return {
        "summary": {
            "total_analyzed_requests": sum(d["total_requests"] for d in ip_stats.values()),
            "unique_source_ips": len(ip_stats),
            "threat_events_detected": len(suspicious_events),
            "attacks_by_category": dict(attack_type_counter),
            "bruteforce_candidates": potential_bruteforce_ips
        },
        "suspicious_events": suspicious_events,
        "ip_breakdown": dict(ip_stats)
    }

def print_cli_report(results: dict, logfile: str):
    summary = results["summary"]

    print("=" * 75)
    print(" INCIDENT RESPONSE & WEB LOG SECURITY ANALYZER")
    print("=" * 75)
    print(f" Source File:          {logfile}")
    print(f" Processed Requests:   {summary['total_analyzed_requests']}")
    print(f" Unique Client IPs:    {summary['unique_source_ips']}")
    print(f" Threat Detections:    {summary['threat_events_detected']}")
    print("-" * 75)

    print(" [1] ATTACK BREAKDOWN BY CATEGORY")
    if summary["attacks_by_category"]:
        for attack, count in summary["attacks_by_category"].items():
            print(f"  * {attack:<30}: {count} occurrences")
    else:
        print("  [+] No web application attack signatures matched.")

    print("-" * 75)
    print(" [2] BRUTE FORCE / SCANNING ANOMALIES (High Failure Rates)")
    if summary["bruteforce_candidates"]:
        for ip in summary["bruteforce_candidates"]:
            failed = results["ip_breakdown"][ip]["failed_requests"]
            total = results["ip_breakdown"][ip]["total_requests"]
            print(f"  [!] High-Risk IP: {ip:<18} ({failed}/{total} failed HTTP requests)")
    else:
        print("  [+] No IP exceeded the brute-force failure threshold.")

    print("-" * 75)
    print(" [3] RECENT DETECTED THREAT INCIDENTS (Sample)")
    for event in results["suspicious_events"][:6]:
        print(f"  Line {event['line']:<4} | {event['ip']:<15} | [{event['attack_type']}] -> {event['method']} {event['uri']}")

    print("=" * 75)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Incident and Web Log Analyzer")
    parser.add_argument("logfile", help="Path to Nginx/Apache access log file")
    parser.add_argument("--threshold", help="Threshold for brute-force failed attempts", type=int, default=5)
    parser.add_argument("-j", "--json", help="Path to export report in JSON format", default=None)

    args = parser.parse_args()
    analysis = analyze_logs(args.logfile, args.threshold)
    print_cli_report(analysis, args.logfile)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(analysis, jf, indent=4)
        print(f"[+] Detailed forensic JSON report saved to: {args.json}")