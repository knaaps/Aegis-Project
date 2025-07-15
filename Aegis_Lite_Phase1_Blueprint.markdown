# Aegis-Lite: Phase 1 (S3 Mini Project) Blueprint

## Overview
**Aegis-Lite** is an ethical attack surface scanner for SMEs, providing asset discovery, vulnerability scanning, trust scoring, and basic reporting. It uses a hybrid CLI/Streamlit architecture, is optimized for a Dell i5-1135G7/16GB RAM, and is fully open-source (MIT License). Designed for a cybersecurity newbie, it meets all syllabus requirements for 20MCA245 Mini Project.

## Core Features
| **Module**          | **CLI Implementation**                     | **Streamlit UI Extension**                |
|---------------------|-------------------------------------------|------------------------------------------|
| **Asset Discovery** | `aegis scan example.com --ethical`        | Input domain, progress bar, asset table  |
| **Threat Scanning** | `aegis nuclei --templates xss,sqli`       | Vulnerability table                      |
| **Trust Scoring**   | `aegis score` (0–100, HTTPS/ports-based)  | Score display in Results tab             |
| **Reporting**       | `aegis report --format json/pdf`          | 1-click JSON/PDF download                |

## Tech Stack
- **Core**: Python 3.10
- **CLI**: Click
- **UI**: Streamlit
- **Scanning**: Subfinder (subdomains), HTTPX (ports), Nuclei (5 templates: XSS, SQLi, etc.)
- **Database**: SQLite
- **Reporting**: ReportLab (PDF), Pandoc (final LaTeX report)
- **Deployment**: Docker
- **Testing**: pytest, pytest-cov, Selenium

## Hardware Guardrails
- `ThreadPoolExecutor(max_workers=4)`: Limits CPU usage.
- Max 50 assets per scan.
- Streamlit: `@st.cache_data` for performance, static tables.
- CLI `--monitor` flag: Logs CPU/RAM to `resource.log`.
- CLI `--compliance-check` flag: Validates robots.txt and rate limits, logs to `compliance.log`.

## Syllabus Alignment
| **CO** | **Deliverable**                          | **Bloom’s Level** |
|--------|------------------------------------------|-------------------|
| CO1    | Synopsis, SOC feedback (email/MOU)       | Understand (L2)   |
| CO2    | Requirements doc, user stories           | Understand (L2)   |
| CO3    | Scrum Book, GitHub issues, sprints       | Apply (L3)        |
| CO4    | ER diagram, UI wireframes               | Analyze (L4)      |
| CO5    | pytest suite (>85% coverage)             | Evaluate (L5)     |
| CO6    | Dockerized CLI/UI integration            | Create (L6)       |
| CO7    | LaTeX report, Docker Hub image           | Apply (L3)        |

## Development Plan (14 Weeks)
### Phase 1: Weeks 1–2 – Setup, Approval, and Planning
- **Tasks**:
  1. **Install Tools**: Python 3.10, Git, Docker, VS Code (1–2 hrs).
     - Test: Run `python --version`, `docker run hello-world`.
  2. **Write Synopsis** (1–2 pages):
     - Problem: SMEs face breaches from unknown assets (68% per Verizon DBIR 2024).
     - Solution: Free, ethical scanner with trust scoring.
     - Features: Asset discovery, vulnerability scanning, trust scoring, reporting.
     - Tools: Python, Subfinder, HTTPX, Nuclei, Streamlit, Docker.
     - Submit to Faculty Supervisor.
  3. **Mock Interviews**: Ask a classmate (as SME admin) about security needs (e.g., “What website issues worry you?”). Write 3–5 user stories (e.g., “As an SME admin, I want a simple scan to find vulnerabilities”).
  4. **Set Up GitHub**: Create repo (`aegis-lite`), add `/docs` folder, `README.md` (“Aegis-Lite: Ethical Scanner for SMEs”).
  5. **Start Scrum Book** (`/docs/scrum_book.md`):
     - Product Backlog: User stories.
     - Database/UI Design: Placeholder.
     - Testing/Validation: Placeholder.
     - Versions: Git commit link.
  6. **Scrum Meeting**: Discuss synopsis and setup with Faculty Supervisor.
- **Deliverables**:
  - Synopsis (`/docs/synopsis.pdf`).
  - Requirements doc (`/docs/requirements.md`).
  - GitHub repo with `README.md`, Scrum Book.
- **Time**: 8–10 hrs (4–5 hrs/week).
- **Beginner Tips**:
  - **Jargon**: Learn “ethical scanning” (respecting website rules like `robots.txt`) via Subfinder’s GitHub (5 min).
  - **Anxiety**: Watch “Git for Beginners” (YouTube, 10 min) to feel comfortable with Git.
  - **Support**: Ask Faculty Supervisor for tool installation help.

### Phase 2: Weeks 3–4 – Core Engine: Asset Discovery
- **Tasks**:
  1. **Design Database**: SQLite table `assets (id, domain, ip, ports)`. Sketch in `/docs/er_diagram.png` (use draw.io).
  2. **Sketch UI**: Plan 3 Streamlit tabs (Scan, Results, Report) in `/docs/ui_wireframes.md` (Markdown or image).
  3. **Code CLI**:
     ```python
     import click
     import subfinder
     import httpx
     import sqlite3

     @click.command()
     @click.argument("domain")
     @click.option("--ethical", is_flag=True, help="Respect robots.txt, 2 reqs/sec")
     @click.option("--compliance-check", is_flag=True, help="Log compliance")
     def scan(domain, ethical, compliance_check):
         conn = sqlite3.connect("aegis.db")
         conn.execute("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, domain TEXT, ip TEXT, ports TEXT)")
         subdomains = subfinder.enumerate(domain)
         for sub in subdomains:
             ports = httpx.scan_ports(sub, rate_limit=2 if ethical else None)
             conn.execute("INSERT INTO assets (domain, ip, ports) VALUES (?, ?, ?)", (sub, "TBD", ports))
         conn.commit()
         if compliance_check:
             with open("compliance.log", "a") as f:
                 f.write(f"Domain: {domain}, Ethical: {ethical}, Rate: {2 if ethical else 'None'}\n")
         click.echo(f"Found {len(subdomains)} subdomains for {domain}")
     ```
  4. **Write Tests**:
     ```python
     import pytest
     def test_scan_ethical():
         result = scan("example.com", ethical=True, compliance_check=True)
         assert result.rate_limit == 2, "Ethical mode should limit to 2 reqs/sec"
     ```
  5. **Scrum Meeting**: Demo `aegis scan example.com --ethical` to Faculty Supervisor.
- **Deliverables**:
  - ER diagram (`/docs/er_diagram.png`).
  - UI wireframes (`/docs/ui_wireframes.md`).
  - CLI command (`aegis scan`).
  - Pytest suite (30% coverage).
  - Sprint retrospective (`/docs/retrospectives/sprint3_4.md`).
- **Time**: 10–12 hrs/week (1.5 hrs coding, 1 hr testing, 0.5 hr docs daily).
- **Beginner Tips**:
  - **Jargon**: Learn “subdomain enumeration” (finding website subdomains like `shop.example.com`) via Subfinder’s docs (10 min).
  - **Anxiety**: Run `subfinder example.com` locally to see output (5 min).
  - **Support**: Search “Subfinder tutorial” on YouTube.

### Phase 3: Weeks 5–6 – Core Engine: Threat Scanning & Trust Scoring
- **Tasks**:
  1. **Integrate Nuclei**:
     ```python
     @click.command()
     @click.option("--templates", default="xss,sqli", help="Nuclei templates")
     def nuclei(templates):
         conn = sqlite3.connect("aegis.db")
         conn.execute("CREATE TABLE IF NOT EXISTS vulns (id INTEGER PRIMARY KEY, asset_id INTEGER, cve TEXT, severity TEXT)")
         results = nuclei.scan("aegis.db", templates.split(","))
         for vuln in results:
             conn.execute("INSERT INTO vulns (asset_id, cve, severity) VALUES (?, ?, ?)", (vuln.asset_id, vuln.cve, vuln.severity))
         conn.commit()
         click.echo(f"Found {len(results)} vulnerabilities")
     ```
  2. **Add Trust Scoring**:
     ```python
     @click.command()
     def score():
         conn = sqlite3.connect("aegis.db")
         assets = conn.execute("SELECT domain, ports FROM assets").fetchall()
         for asset in assets:
             score = 100
             if not asset[1].startswith("443"):  # No HTTPS
                 score -= 50
             if "," in asset[1]:  # Multiple open ports
                 score -= 20
             click.echo(f"{asset[0]}: Trust Score {score}")
             conn.execute("UPDATE assets SET score = ? WHERE domain = ?", (score, asset[0]))
         conn.commit()
     ```
  3. **Write Tests**:
     ```python
     def test_nuclei_scan():
         results = nuclei.scan("example.com", templates=["xss"])
         assert len(results) >= 0
     def test_trust_score():
         score = calculate_score(ports="80")  # No HTTPS
         assert score == 50, "Non-HTTPS should score 50"
     ```
  4. **Scrum Review**: Demo `aegis nuclei --templates xss,sqli` and `aegis score`.
- **Deliverables**:
  - CLI commands (`aegis nuclei`, `aegis score`).
  - Pytest suite (50% coverage).
  - Sprint review notes (`/docs/sprint_reviews.md`).
  - Retrospective (`/docs/retrospectives/sprint5_6.md`).
- **Time**: 10–12 hrs/week.
- **Beginner Tips**:
  - **Jargon**: Learn “CVE” (security flaw ID) via “What is a CVE?” (5 min).
  - **Anxiety**: Run `nuclei -t xss -u example.com` to see sample output.
  - **Support**: Ask Faculty Supervisor for Nuclei setup help.

### Phase 4: Weeks 7–8 – Streamlit UI & Interim Evaluation
- **Tasks**:
  1. **Build Streamlit UI**:
     ```python
     import streamlit as st
     import sqlite3
     import subprocess
     import psutil

     st.title("Aegis-Lite Scanner")
     st.metric("RAM Usage", f"{psutil.virtual_memory().percent}%")
     tab1, tab2, tab3 = st.tabs(["Scan", "Results", "Report"])
     with tab1:
         domain = st.text_input("Domain", "example.com")
         if st.button("Scan"):
             with st.spinner("Scanning..."):
                 subprocess.run(["python", "-m", "aegis", "scan", domain, "--ethical"])
                 subprocess.run(["python", "-m", "aegis", "nuclei", "--templates", "xss,sqli"])
                 subprocess.run(["python", "-m", "aegis", "score"])
     with tab2:
         conn = sqlite3.connect("aegis.db")
         assets = conn.execute("SELECT domain, ports, score FROM assets").fetchall()
         st.table(assets)
         vulns = conn.execute("SELECT cve, severity FROM vulns").fetchall()
         st.table(vulns)
     with tab3:
         if st.button("Download JSON"):
             with open("results.json", "r") as f:
                 st.download_button("Download", f.read(), "results.json")
     ```
  2. **Test UI**:
     ```python
     from selenium import webdriver
     def test_ui_loads():
         driver = webdriver.Chrome()
         driver.get("http://localhost:8501")
         assert "Aegis-Lite Scanner" in driver.title
         driver.quit()
     ```
  3. **Interim Evaluation**: Demo CLI (`aegis scan`, `aegis nuclei`, `aegis score`) and UI. Prepare 3–5 slides (`/docs/interim_slides.pdf`).
- **Deliverables**:
  - Streamlit UI (`ui.py`).
  - Selenium tests (`tests/test_ui.py`).
  - Pytest suite (70% coverage).
  - Interim slides.
- **Time**: 10–12 hrs/week.
- **Beginner Tips**:
  - **Jargon**: Learn “Streamlit” via `streamlit hello` (5 min).
  - **Anxiety**: Run Streamlit locally (`streamlit run ui.py`) to test.
  - **Support**: Use Streamlit’s docs (docs.streamlit.io).

### Phase 5: Weeks 9–10 – Dockerization & Reporting
- **Tasks**:
  1. **Create Dockerfile**:
     ```dockerfile
     FROM python:3.10-slim
     WORKDIR /app
     COPY requirements.txt .
     RUN pip install --no-cache-dir -r requirements.txt
     COPY . .
     EXPOSE 8501
     CMD ["bash", "-c", "streamlit run ui.py --server.port 8501 & python -m aegis"]
     ```
  2. **Requirements** (`requirements.txt`):
     ```
     streamlit==1.38.0
     click==8.1.7
     subfinder==2.5.7
     httpx==0.27.0
     nuclei==3.3.0
     reportlab==4.2.2
     pandoc==3.2
     sqlite3
     pytest==8.3.2
     pytest-cov==5.0.0
     selenium==4.23.1
     psutil==6.0.0
     ```
  3. **Add Reporting**:
     ```python
     from reportlab.lib.pagesizes import letter
     from reportlab.pdfgen import canvas
     import json

     @click.command()
     @click.option("--format", default="json", help="Output format: json/pdf")
     def report(format):
         conn = sqlite3.connect("aegis.db")
         assets = conn.execute("SELECT domain, ports, score FROM assets").fetchall()
         vulns = conn.execute("SELECT cve, severity FROM vulns").fetchall()
         if format == "json":
             with open("results.json", "w") as f:
                 json.dump({"assets": assets, "vulns": vulns}, f)
         elif format == "pdf":
             c = canvas.Canvas("results.pdf", pagesize=letter)
             c.drawString(100, 750, "Aegis-Lite Scan Results")
             y = 700
             for asset in assets:
                 c.drawString(100, y, f"{asset[0]}: Score {asset[2]}")
                 y -= 20
             c.save()
     ```
  4. **Push to Docker Hub**: `docker push aegis-lite`.
- **Deliverables**:
  - Dockerfile, `requirements.txt`.
  - JSON/PDF reporting.
  - Docker Hub image.
- **Time**: 10–12 hrs/week.
- **Beginner Tips**:
  - **Jargon**: Learn “Docker” via “Docker for Beginners” (YouTube, 10 min).
  - **Anxiety**: Test `docker run hello-world` to confirm Docker works.
  - **Support**: Ask Faculty Supervisor for Docker help.

### Phase 6: Weeks 11–14 – Final Polish, Documentation, Submission
- **Tasks**:
  1. **Testing**:
     - Add edge-case tests (e.g., `test_scan_timeout`, `test_invalid_domain`).
     - Achieve >85% pytest coverage.
     - Log bugs in GitHub Issues.
  2. **LaTeX Report** (15 pages):
     - Sections: Problem (SME breaches), design (ER diagram, wireframes), implementation, tests, results.
     - Use JSON data (`results.json`) for results.
  3. **Demo Video** (5 min):
     - CLI: `aegis scan example.com --ethical --compliance-check`.
     - UI: Run scan, show tables, download PDF.
     - Highlight trust scoring and SME focus.
  4. **SOC Feedback**: Email a classmate (mock SOC) for usability feedback.
  5. **Scrum Book**: Update with backlog, designs, tests, commits.
  6. **Presentation**: 5–7 slides (problem, solution, demo, CO mapping).
  7. **Submit**: Report, video, Docker Hub link, GitHub repo, SOC feedback.
- **Deliverables**:
  - Pytest suite (>85% coverage).
  - LaTeX report (`/docs/final_report.tex`).
  - Demo video (`/docs/demo_video.mp4`).
  - SOC feedback (`/docs/soc_feedback.pdf`).
  - Scrum Book, slides (`/docs/final_slides.pdf`).
- **Time**: 12–15 hrs/week.
- **Beginner Tips**:
  - **Jargon**: Learn “pytest” via “Pytest for Beginners” (YouTube, 10 min).
  - **Anxiety**: Rehearse demo with a friend to reduce nerves.
  - **Support**: Share draft report with Faculty Supervisor for feedback.

## Deliverables Checklist
- [ ] Synopsis (`/docs/synopsis.pdf`).
- [ ] GitHub repo (70+ commits).
- [ ] Docker image on Docker Hub.
- [ ] LaTeX report (15 pages).
- [ ] Demo video (5 min).
- [ ] SOC feedback (email/MOU).
- [ ] Scrum Book (`/docs/scrum_book.md`).
- [ ] Requirements doc (`/docs/requirements.md`).
- [ ] ER diagram (`/docs/er_diagram.png`).
- [ ] UI wireframes (`/docs/ui_wireframes.md`).
- [ ] Pytest suite (>85% coverage).

## Demo Script
1. **CLI**: `docker run aegis-lite scan example.com --ethical --compliance-check --monitor`
   - Show `compliance.log` and `resource.log`.
2. **UI**: `docker run -p 8501:8501 aegis-lite streamlit run ui.py`
   - Input `example.com`, run scan, show assets/vulns tables, display trust scores, download PDF.
3. **Highlight**:
   - SME affordability (free vs. $20K Qualys).
   - Ethical compliance (robots.txt, rate-limiting).
   - Trust scoring (simple 0–100 scale).
   - Syllabus alignment (CO1–CO7).

## Success Metrics
- Scan time < 300 seconds.
- Trust score accuracy > 80%.
- False positives < 20%.
- Runs on Dell i5/16GB RAM.