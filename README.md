\# Security Incident \& Web Log Analyzer (Mini-SIEM)



A lightweight Blue Team triage tool designed to parse web server access logs (Nginx, Apache), uncover security threats, detect Brute-Force anomalies, and extract forensic attack artifacts.



\## Features

\- \*\*Signature Detection:\*\* Identifies SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion / Path Traversal (LFI), and sensitive file recon (`.env`, `phpmyadmin`).

\- \*\*Brute-Force \& Anomaly Identification:\*\* Tracks HTTP failure response codes (401, 403, 404) per client IP to spot credential stuffing and dictionary attacks.

\- \*\*SIEM Pipeline Export:\*\* Capable of outputting raw forensic telemetry to structured JSON for SIEM / SOC dashboard consumption.

\- \*\*Zero Dependencies:\*\* Pure Python standard library implementation.



\## Usage

```bash

\# Analyze log file with standard parameters

python log\_analyzer.py sample\_access.log



\# Custom brute-force threshold and JSON forensic report export

python log\_analyzer.py access.log --threshold 10 -j incident\_report.json



===========================================================================

&#x20;INCIDENT RESPONSE \& WEB LOG SECURITY ANALYZER

===========================================================================

&#x20;Source File:          sample\_access.log

&#x20;Processed Requests:   13

&#x20;Unique Client IPs:    4

&#x20;Threat Detections:    5

\---------------------------------------------------------------------------

&#x20;\[1] ATTACK BREAKDOWN BY CATEGORY

&#x20; \* SQL Injection (SQLi)          : 1 occurrences

&#x20; \* Path Traversal / LFI          : 1 occurrences

&#x20; \* Cross-Site Scripting (XSS)    : 1 occurrences

&#x20; \* Reconnaissance / Probe        : 2 occurrences

\---------------------------------------------------------------------------

&#x20;\[2] BRUTE FORCE / SCANNING ANOMALIES (High Failure Rates)

&#x20; \[!] High-Risk IP: 10.0.0.14          (6/6 failed HTTP requests)

\---------------------------------------------------------------------------

&#x20;\[3] RECENT DETECTED THREAT INCIDENTS (Sample)

&#x20; Line 9    | 45.12.89.10     | \[SQL Injection (SQLi)] -> GET /products.php?id=1%20UNION%20SELECT...

&#x20; Line 10   | 45.12.89.10     | \[Path Traversal / LFI] -> GET /download?file=../../../../etc/passwd

&#x20; Line 11   | 185.220.101.5   | \[Cross-Site Scripting (XSS)] -> GET /search?q=<script>alert...

===========================================================================

