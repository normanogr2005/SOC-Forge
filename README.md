 # 🛡️ SOC-Forge

### NORMANTOYS // SECURITY OPERATIONS

> BUILD. BREAK. UNDERSTAND.

SOC-Forge is a local Security Operations Center built to analyze security logs, detect suspicious authentication activity, correlate events, and investigate incidents.

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
```

---

## 🔎 Detection Rules

### AUTH-001

Detects individual failed authentication attempts.

### AUTH-002

Correlates multiple failed authentication events from the same source IP and generates a higher-severity alert.

---

## 🖥️ Dashboard

SOC-Forge provides:

- Alert statistics
- Severity breakdown
- Detection activity
- Live threat feed
- Source IP visibility
- Filtering
- Incident investigation
- Evidence associated with detections

---

## 🧠 Architecture

```text
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
```

---

## 🚀 Tech Stack

```text
Python
FastAPI
SQLite
Pytest
HTML / CSS
Linux
```

---

## 🧪 Testing

The project includes automated tests for:

- Failed authentication detection
- Normal authentication handling
- Brute-force correlation
- Threshold validation

Run:

```bash
python3 -m pytest
```

---

## ⚙️ Installation

```bash
git clone https://github.com/normanogr2005/SOC-Forge.git
cd SOC-Forge

python3 -m venv .venv
source .venv/bin/activate

pip install -e .
```

---

## ▶️ Usage

Run the detection engine:

```bash
python3 -m socforge.main
```

Start the dashboard:

```bash
uvicorn socforge.web:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

---

## 🛡️ Project Philosophy

SOC-Forge is part of my practical approach to cybersecurity:

```text
BUILD IT.
BREAK IT.
UNDERSTAND IT.
IMPROVE IT.
```

The goal is not only to use security tools, but to understand how the systems behind them work.

---

## 🗺️ Roadmap

- [x] Authentication log parser
- [x] Detection engine
- [x] Failed login detection
- [x] Brute-force correlation
- [x] SQLite persistence
- [x] FastAPI dashboard
- [x] Incident investigation
- [x] Detection activity visualization
- [x] Live threat feed
- [ ] More detection rules
- [ ] Real-time log ingestion
- [ ] Authentication anomaly scoring
- [ ] Exportable incident reports
- [ ] Containerized deployment

---

## 👤 NORMANTOYS

Cybersecurity student focused on learning through building.

```text
Linux
Networking
C++
Python
Cybersecurity
Ethical Hacking
```

### NORMANTOYS

> BUILD // BREAK // UNDERSTAND

---

## 📄 License

MIT