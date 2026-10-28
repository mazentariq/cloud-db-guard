#!/usr/bin/env python3
"""
Academic Seminar PoC - Topic 21: AI-Powered Cloud Database Security
Vulnerable Web Application (app.py)

Demonstrates:
- Intentionally VULNERABLE SQL string concatenation in /login:
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
- Integrated `CloudDatabaseGuard` AI Security Middleware interceptor
- Real-time Threat Blocking & Logging to `security_audit.json`
- Supports FastAPI (via Uvicorn) with Jinja2 Templates
"""

import os
import sqlite3
import time
from typing import Optional

# Path to database & templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "vulnerable_cloud_db.sqlite")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Import AI Security Proxy components
from ai_proxy import guard_model, log_security_event, get_audit_logs

try:
    from fastapi import FastAPI, Request, Form, status
    from fastapi.responses import HTMLResponse, RedirectResponse
    from fastapi.templating import Jinja2Templates
    import uvicorn

    app = FastAPI(title="CloudDatabaseGuard Seminar PoC Lab")
    templates = Jinja2Templates(directory=TEMPLATES_DIR)

    # State toggle: Allows student to demonstrate attacks with guard ON vs OFF
    AI_GUARD_ACTIVE = True

    def get_db_connection():
        """Returns connection to SQLite database."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

    @app.get("/", response_class=HTMLResponse)
    async def get_login(request: Request, error: Optional[str] = None):
        """Renders the login portal with live AI Guard status."""
        return templates.TemplateResponse("login.html", {
            "request": request,
            "guard_active": AI_GUARD_ACTIVE,
            "error_msg": error
        })

    @app.post("/toggle-guard")
    async def toggle_guard(request: Request, redirect: str = Form("/")):
        """Toggles the AI Middleware on/off for live seminar demonstrations."""
        global AI_GUARD_ACTIVE
        AI_GUARD_ACTIVE = not AI_GUARD_ACTIVE
        print(f"[*] AI Guard state toggled. Active: {AI_GUARD_ACTIVE}")
        return RedirectResponse(url=redirect, status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/login", response_class=HTMLResponse)
    async def post_login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...)
    ):
        """
        The Intentionally Vulnerable Authentication Endpoint.
        Constructs raw SQL query via string concatenation:
        f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        """
        raw_payload = f"username={username}&password={password}"

        # ------------------------------------------------------------------
        # PHASE 1: AI SECURITY MIDDLEWARE INTERCEPTION
        # ------------------------------------------------------------------
        if AI_GUARD_ACTIVE:
            prediction = guard_model.predict(f"{username} {password}")
            
            if prediction["is_malicious"]:
                # Log incident to security_audit.json
                audit_record = {
                    "event_id": f"EVT-{int(time.time() * 1000)}",
                    "client_ip": request.client.host if request.client else "127.0.0.1",
                    "endpoint": "/login",
                    "method": "POST",
                    "payload": raw_payload,
                    "threat_type": prediction["threat_category"],
                    "confidence_score": prediction["confidence_score"],
                    "latency_ms": prediction["latency_ms"],
                    "salient_features": prediction["salient_tokens"],
                    "status": "BLOCKED_403",
                    "timestamp": prediction["timestamp"]
                }
                log_security_event(audit_record)

                # Return 403 Forbidden with blocked.html
                return templates.TemplateResponse("blocked.html", {
                    "request": request,
                    "audit_record": audit_record,
                    "threat": prediction["threat_category"],
                    "confidence": f"{prediction['confidence_score'] * 100:.2f}%",
                    "latency": f"{prediction['latency_ms']} ms",
                    "payload": f"username='{username}', password='{password}'",
                    "timestamp": prediction["timestamp"]
                }, status_code=403)

        # ------------------------------------------------------------------
        # PHASE 2: RAW UNPARAMETERIZED SQL QUERY EXECUTION (VULNERABILITY)
        # ------------------------------------------------------------------
        # DANGER: Intentional SQL injection vulnerability for seminar demonstration!
        raw_sql_query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"[!] Executing RAW SQL: {raw_sql_query}")

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Executes the raw query without parameterized placeholders
            cursor.execute(raw_sql_query)
            rows = cursor.fetchall()

            if rows:
                user_record = dict(rows[0])
                # Check if attacker exploited UNION to dump multiple rows or access admins
                is_exploited = len(rows) > 1 or "OR 1=1" in username.upper() or "UNION" in username.upper()

                return templates.TemplateResponse("dashboard.html", {
                    "request": request,
                    "user": user_record,
                    "is_exploited": is_exploited,
                    "executed_query": raw_sql_query,
                    "returned_records": [list(r) for r in rows]
                })
            else:
                return templates.TemplateResponse("login.html", {
                    "request": request,
                    "guard_active": AI_GUARD_ACTIVE,
                    "error_msg": "Invalid credentials. Query returned 0 rows.",
                    "username": username
                })

        except sqlite3.OperationalError as db_err:
            return templates.TemplateResponse("login.html", {
                "request": request,
                "guard_active": AI_GUARD_ACTIVE,
                "error_msg": f"SQLite Operational Syntax Error: {str(db_err)}",
                "username": username
            })
        finally:
            conn.close()

    @app.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard(request: Request):
        """Dashboard overview endpoint."""
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user": {"id": 1, "username": "alice_dev", "role": "engineer", "email": "alice.dev@cloudcorp.internal"},
            "is_exploited": False,
            "executed_query": "SELECT * FROM users WHERE id=1"
        })

    @app.get("/soc-logs", response_class=HTMLResponse)
    async def get_soc_logs(request: Request):
        """Admin SOC page displaying blocked SQL injection attempts from security_audit.json."""
        logs = get_audit_logs()
        return templates.TemplateResponse("soc-logs.html", {
            "request": request,
            "logs": logs
        })

    if __name__ == "__main__":
        print("[*] Starting CloudDatabaseGuard Web Application on http://127.0.0.1:8000...")
        uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

except ImportError:
    # If fastapi is not installed in the current environment, provide instructions
    print("[*] FastAPI or Uvicorn not installed in system Python.")
    print("[*] Run: pip install -r requirements.txt")
    print("[*] Or run standalone zero-dependency server: python3 run_demo.py")
