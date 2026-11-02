# FACTORA — From Victim to Defender

**FACTORA** is a community-driven cyber threat intelligence platform designed to detect suspicious activities, identify recurring scam campaigns, and help people stay protected through shared threat information.

##  Key Features

| Component | Description |
|---|---|
| **Agent 1 – Threat Detection** | Analyzes suspicious messages, emails, URLs, screenshots, and GitHub repositories to identify potential threats and explain risks. |
| **Agent 2 – Threat Correlation** | Connects related incidents using shared indicators such as domains, phone numbers, email addresses, and other threat patterns. |
| **Community Module** | Allows users to report incidents, explore community alerts, search threats, and view related incidents. |
| **Browser Extension** | Supports users in identifying potentially suspicious online content while browsing. |

##  Unique Value Proposition

## FACTORA transforms individual cyber threat reports into shared community intelligence.

Instead of making every victim investigate the same scam independently, FACTORA helps connect related incidents and warn others about recurring threats.

##  Technology Stack

| Technology | Purpose |
|---|---|
| HTML, CSS, JavaScript | Frontend |
| Python | Backend development |
| FastAPI | Backend API framework |
| Uvicorn | API server |
| Pydantic | Data validation |
| Requests | HTTP communication |

##  Installation & Setup

### Prerequisites

- Python 3.10 or above
- Git
- Visual Studio Code
- Web browser

### 1. Clone the Repository

```bash
git clone <repository-url>
```

### 2. Install Backend Dependencies

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start the Backend Server

```bash
uvicorn main:app --reload
```

**API Documentation:** http://127.0.0.1:8000/docs

> If your FastAPI entry file is not named `main.py`, replace `main` with the correct filename.

### 4. Run the Frontend

Open the frontend `index.html` file using the VS Code Live Server extension.

##  Requirements

The backend dependencies are listed in `requirements.txt`:

```txt
fastapi>=0.110.0
uvicorn>=0.28.0
pydantic>=2.6.0
python-multipart>=0.0.9
requests>=2.31.0
```

##  Future Scope

- Expand threat intelligence sources and real-time data collection.
- Improve identification of recurring scam campaigns.
- Strengthen community-based threat verification.
- Extend protection to more users and online platforms.

##  Project Objective

To build a collaborative cyber threat intelligence ecosystem where information shared by one person can help protect many others.
