# Aegis-Lite: Ethical Attack Surface Intelligence for SMEs

**Aegis-Lite** is a free, automated cybersecurity tool for small and medium enterprises (SMEs). It rapidly identifies hidden digital assets, scans for vulnerabilities, and generates actionable trust scores—all in under five minutes through both CLI and web interfaces.

## Problem

SMEs face increasing threats from unknown assets such as forgotten subdomains and misconfigured servers. Most solutions are either:

* Cost-prohibitive,
* Technically demanding (manual toolchains take days to configure), or
* Too generic, producing excessive false positives.

There is a gap in SME-focused, free, integrated security tooling.

---

## Solution Overview

Aegis-Lite offers a streamlined, modular system with four core components:

* **Discovery**: Subdomain enumeration (Subfinder) and service detection (HTTPX)
* **Scanning**: Nuclei-based vulnerability detection with ethical rate limiting
* **Intelligence**: Weighted trust scoring based on SSL, ports, and CVEs
* **Reporting**: PDF reports (ReportLab) and real-time dashboards (Streamlit)

---

## Workflow

1. Input: Domain, scan parameters, output preferences
2. Process:

   * Subdomain Discovery → Service Fingerprinting → Vulnerability Scanning → Risk Scoring
3. Output:

   * Asset inventory, prioritized vulnerabilities, interactive dashboard, and PDF reports

---

## Tech Stack

* **Languages & Tools**: Python 3.10, Click (CLI), Streamlit (UI), SQLite
* **Security**: Subfinder, HTTPX, Nuclei, psutil
* **Infrastructure**: Docker, ReportLab, pytest (>85% coverage)

---

## Key Features

* Ethical scanning with rate limits and resource monitoring
* Trust score (0–100) to prioritize actionable risks
* CLI and web interfaces for flexibility
* Compliance-ready PDF documentation
* One-command Docker deployment
* Hardware-aware resource control (50 assets max, 75% memory cap)

---

## Future Work

**Planned Enhancements**:

* AI-based vulnerability triage
* MITRE ATT\&CK integration
* Trust visualization (radial charts)
* Authenticated scanning via OWASP ZAP

**Long-Term Goals**:

* Cloud scaling (AWS/Terraform)
* Dark web credential monitoring
* Mobile app (React Native)
* External threat intel feed integration

---
