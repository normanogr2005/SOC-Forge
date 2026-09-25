 # 🛡️ SOC-Forge

### NORMANTOYS // SECURITY OPERATIONS

> BUILD. BREAK. UNDERSTAND.

SOC-Forge is a local Security Operations Center built to analyze security logs, detect suspicious authentication activity, correlate events and investigate incidents.

---

## ⚡ What is SOC-Forge?

SOC-Forge is a hands-on cybersecurity project focused on security monitoring and detection engineering.

The system processes authentication logs through a detection pipeline:

```text
AUTH LOG
   │
   ▼
PARSER
   │
   ▼
DETECTION ENGINE
   │
   ├── AUTH-001
   │   Failed authentication
   │
   └── AUTH-002
       Brute-force correlation
   │
   ▼
SQLITE
   │
   ▼
FASTAPI
   │
   ▼
SOC DASHBOARD



🔎 Detection Rules
AUTH-001

Detects individual failed authentication attempts.

AUTH-002

Correlates multiple failed authentication events from the same source IP and generates a higher-severity alert.


🖥️ Dashboard

SOC-Forge provides:

Alert statistics
Severity breakdown
Detection activity
Live threat feed
Source IP visibility
Filtering
Incident investigation
Evidence associated with detections


🧠 Architecture
              ┌──────────────┐
              │   auth.log   │
              └──────┬───────┘
                     │
                     ▼
              ┌──────────────┐
              │    Parser    │
              └──────┬───────┘
                     │
                     ▼
           ┌────────────────────┐
           │  Detection Engine  │
           └───────┬─────┬──────┘
                   │     │
              AUTH-001 AUTH-002
                   │     │
                   └──┬──┘
                      ▼
                ┌───────────┐
                │  SQLite   │
                └─────┬─────┘
                      │
                      ▼
                ┌───────────┐
                │  FastAPI  │
                └─────┬─────┘
                      │
                      ▼
                ┌───────────┐
                │ Dashboard │
                └───────────┘


🚀 Tech Stack
                Python
FastAPI
SQLite
Pytest
HTML / CSS
Linux


🧪 Testing
The project includes automated tests for:

Failed authentication detection
Normal authentication handling
Brute-force correlation
Threshold validation


Run:
python3 -m pytest


⚙️ Installation
git clone https://github.com/YOUR_USERNAME/SOC-Forge.git
cd SOC-Forge

python3 -m venv .venv
source .venv/bin/activate

pip install -e .


▶️ Usage
python3 -m socforge.main


Start the dashboard:
uvicorn socforge.web:app --reload


Open:
http://127.0.0.1:8000


🛡️ Project Philosophy
SOC-Forge is part of my practical approach to cybersecurity:

BUILD IT.
BREAK IT.
UNDERSTAND IT.
IMPROVE IT.

The goal is not only to use security tools, but to understand how the systems behind them work.


🗺️ Roadmap
 Authentication log parser
 Detection engine
 Failed login detection
 Brute-force correlation
 SQLite persistence
 FastAPI dashboard
 Incident investigation
 Detection activity visualization
 More detection rules
 Real-time log ingestion
 Authentication anomaly scoring
 Exportable incident reports
 Containerized deployment


 👤 NORMANTOYS

Cybersecurity student focused on learning through building.

Linux
Networking
C++
Python
Cybersecurity
Ethical Hacking
NORMANTOYS

BUILD // BREAK // UNDERSTAND


📄 License

MIT


4. Guarda:

```text
Ctrl + S

