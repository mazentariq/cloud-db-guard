#!/usr/bin/env python3
import os
import sqlite3
import time
from typing import Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "vulnerable_cloud_db.sqlite")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

from ai_proxy import guard_model, log_security_event, get_audit_logs
from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import uvicorn

app = FastAPI(title="CloudDatabaseGuard Seminar PoC Lab")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

app.state.ai_guard_active = True


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def render_page(request: Request, name: str, context: dict = None, status_code: int = 200):
    if context is None:
        context = {}
    context["request"] = request
    return templates.TemplateResponse(request=request, name=name, context=context, status_code=status_code)


@app.get("/", response_class=HTMLResponse)
async def get_login(request: Request, error: Optional[str] = None):
    return render_page(request, "victim_login.html", {"error_msg": error})


@app.post("/login")
async def post_login(request: Request, username: str = Form(...), password: str = Form(...)):
    raw_payload = f"username={username}&password={password}"

    if app.state.ai_guard_active:
        prediction = guard_model.predict(f"{username} {password}")
        if prediction["is_malicious"]:
            audit_record = {
                "event_id": f"EVT-{int(time.time() * 1000)}",
                "client_ip": request.client.host if request.client else "127.0.0.1",
                "endpoint": "/login", "method": "POST", "payload": raw_payload,
                "threat_type": prediction["threat_category"], "confidence_score": prediction["confidence_score"],
                "latency_ms": prediction["latency_ms"], "salient_features": prediction["salient_tokens"],
                "status": "BLOCKED_403", "timestamp": prediction["timestamp"]
            }
            log_security_event(audit_record)
            return render_page(request, "403_blocked.html", {}, status_code=403)

    raw_sql_query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(raw_sql_query)
        rows = cursor.fetchall()
        if rows:
            user_record = dict(rows[0])
            is_exploited = len(rows) > 1 or "OR 1=1" in username.upper() or "UNION" in username.upper()
            return render_page(request, "victim_portal.html", {
                "user": user_record, "is_exploited": is_exploited, "executed_query": raw_sql_query,
                "returned_records": [list(r) for r in rows]
            })
        else:
            return render_page(request, "victim_login.html", {"error_msg": "Invalid credentials."})
    except sqlite3.OperationalError as e:
        return render_page(request, "victim_login.html", {"error_msg": f"SQLite Syntax Error: {str(e)}"})
    finally:
        conn.close()


@app.get("/portal", response_class=HTMLResponse)
async def get_portal(request: Request):
    return render_page(request, "victim_portal.html", {
        "user": {"username": "alice_dev", "role": "engineer"}, "is_exploited": False,
        "executed_query": "SELECT * FROM users WHERE id=1", "returned_records": []
    })


@app.get("/soc", response_class=HTMLResponse)
async def get_soc(request: Request):
    logs = get_audit_logs()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    db_users = [dict(r) for r in c.fetchall()]
    c.execute("SELECT * FROM admins")
    db_admins = [dict(r) for r in c.fetchall()]
    conn.close()

    return render_page(request, "soc_dashboard.html", {
        "guard_active": app.state.ai_guard_active, "logs": logs,
        "db_users": db_users, "db_admins": db_admins
    })


@app.post("/soc/toggle-guard")
async def toggle_guard(request: Request):
    app.state.ai_guard_active = not app.state.ai_guard_active
    return RedirectResponse(url="/soc", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/soc/reset-db")
async def reset_db(request: Request):
    import db_setup
    db_setup.init_database(DB_FILE)
    return RedirectResponse(url="/soc", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------
# API ROUTES FOR FRONTEND (AJAX/Fetch)
# ---------------------------------------------------------
@app.post("/soc/api/toggle-guard")
async def api_toggle_guard():
    app.state.ai_guard_active = not app.state.ai_guard_active
    print(f"[*] AI Guard toggled via API. Active: {app.state.ai_guard_active}")
    return {"status": "success", "guard_active": app.state.ai_guard_active}


@app.get("/soc/api/logs")
async def api_get_logs():
    return get_audit_logs()


# الرابط الجديد الذي كان يسبب المشكلة وتمت إضافته!
@app.get("/soc/api/db-data")
async def api_get_db_data():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    db_users = [dict(r) for r in c.fetchall()]
    c.execute("SELECT * FROM admins")
    db_admins = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"users": db_users, "admins": db_admins}


@app.post("/soc/api/simulate_attack")
async def api_simulate_attack(request: Request, payload: str = Form(...)):
    raw_payload = f"username={payload}&password=any"

    if app.state.ai_guard_active:
        prediction = guard_model.predict(f"{payload} any")
        if prediction["is_malicious"]:
            audit_record = {
                "event_id": f"EVT-{int(time.time() * 1000)}", "client_ip": "127.0.0.1",
                "endpoint": "/login", "method": "POST", "payload": raw_payload,
                "threat_type": prediction["threat_category"], "confidence_score": prediction["confidence_score"],
                "latency_ms": prediction["latency_ms"], "salient_features": prediction["salient_tokens"],
                "status": "BLOCKED_403", "timestamp": prediction["timestamp"]
            }
            log_security_event(audit_record)
            return JSONResponse(status_code=403,
                                content={"status": "blocked", "message": "AI Guard BLOCKED the payload."})

    raw_sql_query = f"SELECT * FROM users WHERE username='{payload}' AND password='any'"
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(raw_sql_query)
        rows = cursor.fetchall()
        return JSONResponse(status_code=200,
                            content={"status": "success", "message": "Attack SUCCEEDED. DB compromised."})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})
    finally:
        conn.close()


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8100, reload=True)