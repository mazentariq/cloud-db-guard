# Topic 21: AI-Powered Cloud Database Security
## Academic Seminar Proof of Concept (PoC) Laboratory & Demonstration Suite

**Author / Presenter:** Academic Seminar Candidate  
**Specialization:** DevSecOps Engineering & AI Security Research  
**Target Vulnerability:** Raw SQL String Concatenation (CWE-89)  
**Defense Mechanism:** Real-Time Pre-Execution ML Security Middleware (`CloudDatabaseGuard`)  

---

## 1. Project Overview & Architecture

Modern cloud database architectures (AWS Aurora, Google Cloud SQL, Azure SQL, SQLite distributed edges) face persistent threats from SQL Injection (SQLi). Traditional Web Application Firewalls (WAFs) rely on static regex pattern matching that can be bypassed using obfuscation, comments, encoding, and dynamic AST manipulation.

This PoC demonstrates an **AI-powered Security Middleware (`CloudDatabaseGuard`)** that intercepts incoming database queries, tokenizes the payload using character and word N-grams, computes vector inference via a trained Logistic Regression / AST saliency model, and enforces an immediate **HTTP 403 Forbidden** block with full SOC audit logging within **< 3ms**.

```
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

## 2. Directory Structure

```
python_poc/
├── db_setup.py              # Initializes SQLite DB with `users` and `admins` tables
├── ai_proxy.py              # CloudDatabaseGuard ML model & ASGI/WSGI middleware
├── app.py                   # FastAPI vulnerable web app (Jinja2 templates)
├── run_demo.py              # Zero-dependency standard library runner (instant demo)
├── requirements.txt         # Python package dependencies
├── security_audit.json      # Structured SOC threat telemetry log file
└── templates/
    ├── login.html           # Modern cybersecurity login portal + payload quick-inject
    ├── dashboard.html       # Post-login dashboard (shows exploited data if bypassed)
    ├── blocked.html         # High-alert red screen for AI blocked requests
    └── soc-logs.html        # Real-time SOC audit log viewer
```

---

## 3. Quickstart & Seminar Live Demo Steps

### Option A: Instant Zero-Dependency Run (No pip install needed!)
```bash
# 1. Initialize SQLite database
python3 db_setup.py

# 2. Run the standalone demonstration server
python3 run_demo.py 8080
```
Open your browser at `http://127.0.0.1:8080`

### Option B: Run via FastAPI & Uvicorn
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize database
python3 db_setup.py

# 3. Start FastAPI server
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at `http://127.0.0.1:8000`

---

## 4. Seminar Attack Demonstrations

### Attack 1: Authentication Bypass (Tautology)
- **Target:** Bypass password check and log in as the first user (`alice_dev`).
- **Payload:**
  - Username: `admin' OR 1=1 --`
  - Password: `any`
- **Result when AI Middleware is OFF:**
  - Raw query executes: `SELECT * FROM users WHERE username='admin' OR 1=1 --' AND password='any'`
  - Logs into the portal without knowing any password.
- **Result when AI Middleware is ON:**
  - Intercepted in ~1.8ms!
  - 403 Forbidden (`blocked.html`) displayed with 99.8% confidence and salient token extraction.

### Attack 2: Sensitive Table Exfiltration (UNION Injection on `admins`)
- **Target:** Steal super-privilege credentials and API keys from the separate `admins` table.
- **Payload:**
  - Username: `' UNION SELECT id, username, password, super_privilege FROM admins --`
  - Password: `any`
- **Result when AI Middleware is OFF:**
  - Dumps superadmin records, RootMasterKeys, and high-clearance executive tokens.
- **Result when AI Middleware is ON:**
  - Intercepted before the query reaches SQLite.
  - Saliency tags: `union select`, `admins`, `super_privilege`, `--`.

### Attack 3: Destructive DDL Stacked Query
- **Target:** Drop the entire `users` table.
- **Payload:**
  - Username: `'; DROP TABLE users; --`
  - Password: `any`
- **Defense:**
  - Blocked by `CloudDatabaseGuard` under "Stacked Destructive DDL/DML Injection".

---

## 5. Academic Discussion Points for Defense / Q&A
1. **Latency Overhead:** The model operates at sub-3ms inference latency, preserving database transaction throughput.
2. **False Positive Management:** Benign inputs (e.g. `alice_dev`) score ~0.076 (< 0.65 threshold), avoiding disruption to legitimate enterprise users.
3. **Defense-in-Depth:** While prepared statements remain best practice, an AI Security Middleware provides non-invasive zero-day protection for legacy monoliths and microservice databases without requiring codebase rewrites.
