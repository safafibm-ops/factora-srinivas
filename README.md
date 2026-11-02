# FACTORA — From Victim to Defender

### Dual AI Agent Cyber Defense & Community Threat Intelligence Platform

---

## 1. Problem Statement (PS)

Students and freelancers increasingly face fraudulent internships, fake job offers, phishing websites, malicious coding assignments, and online scams.

Existing solutions often identify individual threats but fail to connect them with larger, recurring scam networks. As a result, people may encounter the same scam through different identities without knowing that the threats are related.

**FACTORA addresses this gap by combining individual threat investigation with community-driven threat intelligence.**

## 2. Proposed Solution

FACTORA is a dual AI-agent cyber defense platform that investigates suspicious digital content, explains potential risks, and identifies relationships between recurring threats.

It supports multiple input formats, including:

- Messages and emails
- Screenshots and PDFs
- Website URLs
- GitHub repositories

The platform combines machine learning, NLP, OSINT, neuro-symbolic reasoning, and community intelligence to help users make safer digital decisions.

## 3. Unique Value Proposition (UVP)

Unlike conventional scam detectors that focus mainly on individual threats, FACTORA goes a step further:

- **Investigate:** Understand why a suspicious message, website, or repository may be dangerous.
- **Correlate:** Connect related indicators across multiple incidents.
- **Protect:** Convert individual threat reports into collective cyber intelligence.

**FACTORA transforms individual threat detection into collective cyber defense.**

---

## 4. Core Features

### Agent 1 — Intelligent Threat Investigation

Agent 1 performs first-level analysis of suspicious digital content.

| Feature | Description |
|---|---|
| Multi-Input Analysis | Accepts messages, emails, screenshots, PDFs, websites, and GitHub repositories for investigation. |
| Machine Learning Detection | Uses XGBoost-based machine learning and NLP feature extraction to identify suspicious patterns. |
| Behavioral Fraud Detection | Examines indicators such as urgency, suspicious financial requests, and fraudulent recruitment behavior. |
| URL & Domain Forensics | Uses domain intelligence, WHOIS information, OpenPhish, and historical website records to investigate suspicious domains. |
| GitHub Repository Analysis | Examines coding repositories for potentially risky scripts, dependencies, and execution behavior. |
| P.R.I.M.E. Risk Engine | Evaluates six risk dimensions, including domain identity, urgency, financial requests, and code safety. |
| Explainable Risk Report | Provides a risk score, supporting forensic findings, and an actionable verification checklist. |

**Dataset:** The prototype demonstration uses selected job scam, phishing email, and SMS subsets from the DIFrauD benchmark, representing 36,141 labelled records.

### Agent 2 — Community Threat Intelligence

Agent 2 focuses on connecting individual incidents to identify potentially recurring scam campaigns.

| Feature | Description |
|---|---|
| Threat Similarity Analysis | Uses TF-IDF and semantic similarity to compare incoming indicators with historical incidents. |
| Relationship Detection | Uses Random Forest-based relationship analysis to identify potentially connected incidents. |
| Indicator Matching | Compares shared domains, phone numbers, UPI IDs, and repository indicators. |
| Campaign Identification | Helps uncover recurring scam patterns and potentially connected threat campaigns. |
| Relationship Graph | Visualizes connections between threat entities and incidents through an interactive network graph. |
| Community Intelligence | Converts individual reports into shared intelligence that can help warn other users. |

**Objective:** Identify how different suspicious incidents may be connected instead of treating every report as an isolated case.

### Community Dashboard — Victim Hub & Loss

The Community Dashboard provides a centralized view of reported incidents and community threat intelligence.

| Feature | Description |
|---|---|
| Threat Statistics | Displays reported incidents, threat campaigns, active alerts, and available loss information. |
| Monthly Reports | Presents the number of incidents reported over time. |
| Student Financial Loss | Summarizes reported financial losses based on available incident records. |
| Threat Campaigns | Highlights potentially connected incidents and recurring scam patterns. |
| Active Alerts | Displays relevant threat warnings for community awareness. |
| Relationship Graph | Shows connections between suspicious entities and incidents. |
| Threat Search | Helps users search for suspicious domains, URLs, emails, repositories, and other indicators. |
| Incident Reporting | Allows users to submit suspicious incidents and supporting information. |

*Dashboard statistics should be based on available records and verified data sources. External threat-feed entries must not be treated as student-reported incidents or financial losses.*

### Multi-Channel Protection

| Component | Description |
|---|---|
| Telegram Security Bot | Allows users to submit suspicious messages, screenshots, and supported documents. |
| Chrome Extension | Supports browser-based page scanning and risk assessment. |
| Make Them Prove It | Uses an AI stand-in to ask suspicious recruiters to verify company identity, official job listings, and recruitment processes. |

### Planned Capability

- **Sandbox-Based Safe Browsing:** A planned private sandbox layer intended to isolate potentially dangerous destinations during investigation. This is not yet implemented in the current prototype.

---

## 5. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend and AI development |
| FastAPI | Backend API framework |
| Uvicorn | API server |
| HTML, CSS, JavaScript | Frontend |
| XGBoost | Machine learning-based detection |
| NLP & TF-IDF | Text analysis and similarity detection |
| Random Forest | Relationship analysis |
| OSINT | External threat intelligence and domain investigation |
| WHOIS | Domain information lookup |

---

## 6. Installation & Setup

### Prerequisites

- Python 3.10 or above
- Git
- Visual Studio Code
- Web browser

### Step 1: Clone the Repository

```bash
git clone <repository-url>
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Start the Backend

```bash
uvicorn main:app --reload
```

### Step 5: Open API Documentation

Visit:

```text
http://127.0.0.1:8000/docs
```

### Step 6: Run the Frontend

Open the frontend `index.html` file using the **Live Server** extension in Visual Studio Code.

> **Note:** The commands assume that the terminal is opened in the directory containing `requirements.txt` and that the FastAPI application is exposed as `app` in `main.py`. Adjust the entry-point name if your project uses a different file.

---

## 7. Backend Requirements

The main Python dependencies are:

```txt
fastapi>=0.110.0
uvicorn>=0.28.0
pydantic>=2.6.0
python-multipart>=0.0.9
requests>=2.31.0
```

---

## 8. Future Scope

- Expand real-time threat intelligence collection from public sources.
- Improve threat relationship detection using larger incident datasets.
- Strengthen community-based threat verification.
- Expand browser and messaging platform protection.
- Develop the planned sandbox-based safe-browsing capability.
- Improve campaign intelligence and community alert generation.

---

## 9. Project Objective

FACTORA aims to create a collaborative cyber threat intelligence ecosystem where suspicious activities can be investigated, connected, and shared to improve digital safety.

**We are not just building a system that tells students whether something is fake or real. We are building a system that investigates why it is dangerous, discovers how threats are connected, and helps students make safer digital decisions.**
