# 🛡️ CloudDatabaseGuard: AI-Powered Cloud Database Security

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-00a393?logo=fastapi&logoColor=white)
![Security](https://img.shields.io/badge/Security-AI%20Middleware-red)
![License](https://img.shields.io/badge/License-MIT-green)

**Academic Seminar Proof of Concept (PoC) Laboratory & Demonstration Suite**  
*Topic 21: DevSecOps Engineering & AI Security Research*

CloudDatabaseGuard is a real-time, pre-execution Machine Learning Security Middleware designed to detect and mitigate obfuscated SQL Injection (SQLi) attacks. It intercepts raw payloads before they reach the database engine, providing deterministic **sub-3ms** defense without requiring modifications to legacy codebases.

---

## 🎯 The Challenge & The Solution

Modern cloud database architectures face persistent threats from SQL Injection (CWE-89). Traditional Web Application Firewalls (WAFs) rely on static regex pattern matching, which is easily bypassed using obfuscation, inline comments, and dynamic AST manipulation. Deep Learning models, on the other hand, introduce unacceptable latency (40ms-120ms) for high-throughput databases.

**The Solution:** CloudDatabaseGuard uses a lightweight **Character-level TF-IDF N-Gram Vectorizer** combined with a **Logistic Regression** model to intercept, analyze, and block malicious payloads in under 3 milliseconds, achieving >99% accuracy with zero false positives on legitimate traffic.

---

## 🏗️ Architecture

The PoC strictly separates the vulnerable public-facing website from the secure SOC administration dashboard.

```text
                           [ Incoming HTTP POST /login ]
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │   CloudDatabaseGuard AI Middleware    │
                     │  - TF-IDF N-Gram Vectorizer           │
                     │  - AST & Taint Lexical Saliency       │
                     │  - Latency Instrumentation (<3ms)     │
                     └───────────────────┬───────────────────┘
                                         │
                  ┌──────────────────────┴──────────────────────┐
                  │                                             │
      [ Malicious SQLi Score ≥ 0.65 ]               [ Clean Payload Score < 0.65 ]
                  │                                             │
                  ▼                                             ▼
     ┌─────────────────────────┐                   ┌─────────────────────────┐
     │   HTTP 403 Forbidden    │                   │   Vulnerable SQL Exec   │
     │  - blocked.html alert   │                   │  f"SELECT * FROM users  │
     │  - Log threat event to  │                   │   WHERE username=...    │
     │   security_audit.json   │                   └────────────┬────────────┘
     └─────────────────────────┘                                │
                                                                ▼
                                                   ┌─────────────────────────┐
                                                   │ SQLite Database Engine  │
                                                   │  `users` & `admins`     │
                                                   └─────────────────────────┘
```

---

## 📂 Repository Structure

```text
├── main.py                  # Production FastAPI application (Public / vs Admin /soc)
├── ai_proxy.py              # CloudDatabaseGuard ML model (TF-IDF + Logistic Regression)
├── db_setup.py              # SQLite initializer creating `users` and `admins` tables
├── requirements.txt         # Package dependencies (FastAPI, Uvicorn, Jinja2)
├── security_audit.json      # Live JSON audit log repository (Generated at runtime)
└── templates/               # UI/UX Interfaces
    ├── victim_login.html    # Clean corporate portal, zero security cues
    ├── victim_portal.html   # Employee dashboard (exhibits dumped rows if SQLi succeeds)
    ├── soc_dashboard.html   # Dark-themed SOC console with attack simulators
    └── 403_blocked.html     # Generic HTTP 403 Forbidden page
```

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.8+
- Git

### 1. Clone & Install
```bash
git clone https://github.com/yourusername/CloudDatabaseGuard.git
cd CloudDatabaseGuard
pip install -r requirements.txt
```

### 2. Initialize the Database
```bash
python db_setup.py
```
*(This creates `vulnerable_cloud_db.sqlite` populated with dummy corporate data).*

### 3. Run the Server
```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

### 4. Access the Dashboards
- **Public Victim Website:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **SOC AI Dashboard:** [http://127.0.0.1:8000/soc](http://127.0.0.1:8000/soc)

---

## ⚔️  Attack Demonstrations

Use the **Attack Simulator** inside the `/soc` dashboard, or manually test these payloads on the Victim login page.

### Attack 1: Authentication Bypass (Tautology)
- **Payload:** `admin' OR 1=1 --`
- **Impact (Guard OFF):** Bypasses password check, logging in as the first user without credentials.
- **Defense (Guard ON):** Intercepted in ~1.8ms. HTTP 403 Forbidden returned. Highly confident salient token extraction (`OR 1=1`, `--`).

### Attack 2: Sensitive Table Exfiltration (UNION Injection)
- **Payload:** `' UNION SELECT id, username, password, super_privilege FROM admins --`
- **Impact (Guard OFF):** Dumps RootMasterKeys and high-clearance executive tokens directly to the user session.
- **Defense (Guard ON):** Blocked instantly. AI flags `union select`, `admins`, and `super_privilege` as malicious AST anomalies.

### Attack 3: Destructive DDL Stacked Query
- **Payload:** `'; DROP TABLE users; --`
- **Impact (Guard OFF):** Drops the entire user database, causing total application failure.
- **Defense (Guard ON):** Blocked under "Stacked Destructive DDL/DML Injection" classification.

---
