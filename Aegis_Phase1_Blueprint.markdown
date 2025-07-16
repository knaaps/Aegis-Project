# Project Aegis: Phase 1 (S3 Mini Project) Blueprint

## Overview
**Aegis** is an ethical attack surface scanner for SMEs, delivering asset discovery, vulnerability scanning, and basic reporting in a hybrid CLI/Streamlit architecture. Optimized for a Dell i5-1135G7/16GB RAM, it uses open-source tools (MIT License) and Docker for reproducibility. Phase 1 focuses on core scanning and a minimal UI, aligning with the syllabus for 20MCA245 Mini Project.

## Core Features
| **Module**          | **CLI Implementation**                     | **Streamlit UI Extension**                |
|---------------------|-------------------------------------------|------------------------------------------|
| **Asset Discovery** | `aegis scan example.com --ethical`        | Progress bar + asset table               |
| **Threat Scanning** | `aegis nuclei --templates xss,sqli`       | CVE severity table                       |
| **Reporting**       | `aegis report --format json`              | 1-click PDF download (basic)             |

## Tech Stack
- **Core**: Python 3.10, Click (CLI)
- **Scanning**: Subfinder (subdomains), HTTPX (ports), Nuclei (vulnerabilities)
- **Storage**: SQLite (scan results)
- **UI**: Streamlit (dashboard)
- **Reporting**: reportlab (PDF), Pandoc (final LaTeX report)
- **Deployment**: Docker
- **Testing**: pytest, pytest-cov

## Hardware Guardrails
- `ThreadPoolExecutor(max_workers=4)`: Limits CPU usage.
- Max 50 assets per scan.
- Streamlit: Static graphs, `@st.cache_data` for performance.
- Resource monitoring: CLI flag `--monitor` logs CPU/RAM to `resource.log`.

## Syllabus Alignment
| **CO** | **Deliverable**                          | **Bloom’s Level** |
|--------|------------------------------------------|-------------------|
| CO1    | Synopsis, SOC feedback (MOU)             | Understand (L2)   |
| CO2    | Requirements doc, user stories           | Understand (L2)   |
| CO3    | Scrum Book, GitHub issues, sprints       | Apply (L3)        |
| CO4    | ER diagram, UI wireframes               | Analyze (L4)      |
| CO5    | pytest suite (>85% coverage)             | Evaluate (L5)     |
| CO6    | Dockerized CLI/UI integration            | Create (L6)       |
| CO7    | LaTeX report, Docker Hub image           | Apply (L3)        |

## Sprint Plan (14 Weeks)
### Phase 1: Weeks 1–2 – Setup, Approval, and Planning
- **Tasks**:
  - Install tools: Python 3.10, Git, Docker, IDE (VS Code).
  - Draft **project synopsis** (1–2 pages): SME cybersecurity problem, proposed features (asset discovery, threat scanning, reporting), tech stack, deliverables.
  - Conduct mock interviews (2–3) with SOC analysts/SMEs to elicit requirements.
  - Create GitHub repo with `/docs` folder.
  - Initialize **Scrum Book** (`/docs/scrum_book.md`):
    - Product Backlog: User stories (e.g., “As an SME admin, I want to scan assets ethically”).
    - Database & UI Design: Placeholder.
    - Testing & Validation: Placeholder.
    - Versions: Link to Git commits.
  - Submit synopsis to Faculty Supervisor for approval.
- **Deliverables**:
  - Synopsis (`/docs/synopsis.pdf`).
  - Requirements doc (`/docs/requirements.md`).
  - Initial Scrum Book (`/docs/scrum_book.md`).
  - GitHub repo setup.

### Phase 2: Weeks 3–4 – Core Engine: Asset Discovery
- **Tasks**:
  - Design SQLite schema: `assets` table (e.g., `id`, `domain`, `ip`, `ports`).
  - Sketch Streamlit UI wireframes (3 tabs: Scan, Results, Report).
  - Integrate Subfinder and HTTPX for subdomain/port scanning.
  - Implement CLI command: `aegis scan <domain> --ethical` (respects robots.txt, 2 reqs/sec).
  - Write pytest tests (e.g., `test_subdomain_discovery`, `test_rate_limit`).
  - Document designs in Scrum Book (`Database & UI Design`).
- **Deliverables**:
  - ER diagram (`/docs/er_diagram.png`).
  - UI wireframes (`/docs/ui_wireframes.md`).
  - Initial CLI (`aegis scan`).
  - Pytest suite (20% coverage).
  - Updated Scrum Book.

### Phase 3: Weeks 5–6 – Core Engine: Threat Scanning & First Review
- **Tasks**:
  - Integrate Nuclei for vulnerability scanning (templates: XSS, SQLi).
  - Enhance CLI: `aegis nuclei --templates xss,sqli`.
  - Store scan results in SQLite.
  - Add pytest tests (e.g., `test_nuclei_scan`, `test_invalid_domain`).
  - Hold Scrum review with Faculty Supervisor: Demo CLI scanning.
  - Document meeting notes and sprint retrospective in Scrum Book.
- **Deliverables**:
  - CLI with Nuclei support.
  - Pytest suite (50% coverage).
  - Scrum review notes (`/docs/sprint_reviews.md`).
  - Sprint retrospective (`/docs/retrospectives/sprint3_4.md`).

### Phase 4: Weeks 7–8 – Streamlit UI & Interim Evaluation
- **Tasks**:
  - Build Streamlit UI (3 tabs):
    - **Scan**: Input domain, trigger scan, show progress bar.
    - **Results**: Display assets and vulnerabilities in tables.
    - **Report**: Download JSON results.
  - Add resource monitoring: Streamlit `st.metric` for CPU/RAM, CLI `--monitor` flag.
  - Test UI with `selenium` (e.g., test button clicks).
  - Prepare for interim evaluation: Demo CLI + UI, show Git commits.
- **Deliverables**:
  - Streamlit UI (`ui.py`).
  - Selenium tests (`tests/test_ui.py`).
  - Pytest suite (70% coverage).
  - Interim presentation slides (`/docs/interim_slides.pdf`).

### Phase 5: Weeks 9–10 – Dockerization & Basic Reporting
- **Tasks**:
  - Create Dockerfile and `requirements.txt` (pinned versions).
  - Implement JSON reporting: `aegis report --format json`.
  - Add basic PDF generator using `reportlab` (`aegis report --format pdf`).
  - Test Docker image on Dell i5/16GB.
  - Push image to Docker Hub.
- **Deliverables**:
  - Dockerfile (`Dockerfile`).
  - Requirements (`requirements.txt`).
  - JSON/PDF reporting (`aegis report`).
  - Docker Hub image.

### Phase 6: Weeks 11–14 – Final Polish, Documentation, Submission
- **Tasks**:
  - Increase pytest coverage (>85%) with edge-case tests (e.g., `test_scan_timeout`).
  - Write 15-page LaTeX report: Problem, design, implementation, testing, results.
  - Record demo video (5 min): CLI scan → Streamlit UI → PDF export.
  - Collect SOC feedback (MOU or email).
  - Finalize Scrum Book: Backlog, designs, tests, commit history.
  - Prepare final presentation: 5–7 slides (problem, solution, demo, CO alignment).
  - Submit deliverables to Faculty Supervisor.
- **Deliverables**:
  - Pytest suite (>85% coverage).
  - LaTeX report (`/docs/final_report.tex`).
  - Demo video (`/docs/demo_video.mp4`).
  - SOC feedback (`/docs/soc_feedback.pdf`).
  - Final Scrum Book.
  - Presentation slides (`/docs/final_slides.pdf`).

## Deliverables Checklist
- [ ] Project synopsis (`/docs/synopsis.pdf`).
- [ ] GitHub repo (70+ semantic commits).
- [ ] Docker image on Docker Hub.
- [ ] LaTeX report (15 pages, `/docs/final_report.tex`).
- [ ] Demo video (5 min, `/docs/demo_video.mp4`).
- [ ] SOC feedback (MOU/email, `/docs/soc_feedback.pdf`).
- [ ] Scrum Book (`/docs/scrum_book.md`).
- [ ] Requirements doc (`/docs/requirements.md`).
- [ ] ER diagram (`/docs/er_diagram.png`).
- [ ] UI wireframes (`/docs/ui_wireframes.md`).
- [ ] Pytest suite (>85% coverage).

## Dockerfile
```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501
CMD ["bash", "-c", "streamlit run ui.py --server.port 8501 & python -m aegis"]
```

## Requirements.txt
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
```

## Demo Script
1. **CLI Scan**: `docker run aegis scan example.com --ethical --monitor`
   - Show ethical compliance (robots.txt, rate-limiting).
   - Display JSON output.
2. **Streamlit UI**: `docker run -p 8501:8501 aegis streamlit run ui.py`
   - Input domain, trigger scan, show progress bar.
   - Display assets/vulnerabilities in tables.
   - Download PDF report.
3. **Highlight**:
   - SME affordability (vs. $20K Qualys).
   - Hardware optimization (Dell i5/16GB).
   - Syllabus alignment (CO1–CO7).