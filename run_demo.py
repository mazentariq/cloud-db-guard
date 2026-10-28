#!/usr/bin/env python3
"""
Academic Seminar PoC - Topic 21: AI-Powered Cloud Database Security
Standalone Standard Library Server (run_demo.py)

Strict Architectural Separation:
- Public Face: http://127.0.0.1:8080/ (Victim Login) & /portal (Victim Portal)
- Admin Face:  http://127.0.0.1:8080/soc (Cybersecurity SOC Dashboard with 4 Top Navbar Tabs)
"""

import os
import sys
import sqlite3
import time
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "vulnerable_cloud_db.sqlite")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

if not os.path.exists(DB_FILE):
    import db_setup
    db_setup.init_database(DB_FILE)

from ai_proxy import guard_model, log_security_event, get_audit_logs

AI_GUARD_ACTIVE = True

class SeminarAppHandler(BaseHTTPRequestHandler):
    def send_html(self, content: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def send_json(self, data: any, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. Victim Website (Public Face)
        if path == "/":
            with open(os.path.join(TEMPLATES_DIR, "victim_login.html"), "r") as f:
                html = f.read().replace("{{ error_msg }}", "").replace("{{ username or '' }}", "")
                if "{% if error_msg %}" in html:
                    p1 = html.split("{% if error_msg %}")[0]
                    p2 = html.split("{% endif %}")[1]
                    html = p1 + p2
            self.send_html(html)

        elif path == "/portal":
            with open(os.path.join(TEMPLATES_DIR, "victim_portal.html"), "r") as f:
                html = f.read()
                html = html.replace("{{ user.username if user else \"Employee\" }}", "alice_dev")
                html = html.replace("{{ user.username if user else \"User\" }}", "alice_dev")
                html = html.replace("{{ user.role if (user and user.role) else \"Standard Access\" }}", "cloud_engineer")
                html = html.replace("{{ user.id if user else \"1001\" }}", "1")
                html = html.replace("{{ user.email if (user and user.email) else \"employee@apexcloud.internal\" }}", "alice.dev@apexcloud.internal")
                html = html.replace("{{ \"ADMIN_ROOT\" if (user and (\"admin\" in user.username or user.super_privilege)) else \"STANDARD_TOKEN\" }}", "STANDARD_TOKEN")
                if "{% if dumped_records and dumped_records|length > 1 %}" in html:
                    p1 = html.split("{% if dumped_records and dumped_records|length > 1 %}")[0]
                    p2 = html.split("{% endif %}")[1]
                    html = p1 + p2
            self.send_html(html)

        # 2. SOC & AI Dashboard (Admin Face)
        elif path == "/soc":
            with open(os.path.join(TEMPLATES_DIR, "soc_dashboard.html"), "r") as f:
                html = f.read()
            self.send_html(html)

        # SOC APIs
        elif path == "/soc/api/logs":
            self.send_json(get_audit_logs())

        elif path == "/soc/api/db-data":
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            users = []
            admins = []
            try:
                cur.execute("SELECT id, username, password, email, role FROM users")
                users = [dict(r) for r in cur.fetchall()]
            except: pass
            try:
                cur.execute("SELECT id, username, password, super_privilege, api_secret, clearance_level FROM admins")
                admins = [dict(r) for r in cur.fetchall()]
            except: pass
            conn.close()
            self.send_json({"users": users, "admins": admins})

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = urllib.parse.parse_qs(body)

        global AI_GUARD_ACTIVE

        if path == "/soc/api/toggle-guard":
            AI_GUARD_ACTIVE = not AI_GUARD_ACTIVE
            self.send_json({"guard_active": AI_GUARD_ACTIVE})
            return

        if path == "/soc/api/reset-db":
            import db_setup
            db_setup.init_database(DB_FILE)
            self.send_json({"success": True})
            return

        if path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            raw_payload = f"username={username}&password={password}"

            # Step 1: AI Interception
            if AI_GUARD_ACTIVE:
                pred = guard_model.predict(f"{username} {password}")
                if pred["is_malicious"]:
                    event_id = f"EVT-{int(time.time() * 1000)}"
                    log_security_event({
                        "event_id": event_id,
                        "client_ip": self.client_address[0],
                        "endpoint": "/login",
                        "method": "POST",
                        "payload": raw_payload,
                        "threat_type": pred["threat_category"],
                        "confidence_score": pred["confidence_score"],
                        "latency_ms": pred["latency_ms"],
                        "salient_features": pred["salient_tokens"],
                        "status": "BLOCKED_403",
                        "timestamp": pred["timestamp"]
                    })
                    with open(os.path.join(TEMPLATES_DIR, "403_blocked.html"), "r") as f:
                        html = f.read().replace("{{ event_id or \"SEC-GATE-BLOCKED\" }}", event_id).replace("{{ timestamp or \"Now\" }}", pred["timestamp"])
                    self.send_html(html, code=403)
                    return

            # Step 2: Raw Vulnerable SQL Execution
            raw_sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            print(f"[!] Executing RAW SQL: {raw_sql}")

            try:
                conn = sqlite3.connect(DB_FILE)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(raw_sql)
                rows = cur.fetchall()
                conn.close()

                if rows:
                    first = dict(rows[0])
                    is_exploited = len(rows) > 1 or "'" in username or "UNION" in username.upper()
                    if is_exploited and not AI_GUARD_ACTIVE:
                        log_security_event({
                            "event_id": f"EVT-{int(time.time()*1000)}",
                            "client_ip": self.client_address[0],
                            "endpoint": "/login",
                            "method": "POST",
                            "payload": raw_payload,
                            "threat_type": "Exploit Succeeded (AI Middleware Bypassed)",
                            "confidence_score": 0.0,
                            "latency_ms": 0.5,
                            "salient_features": ["raw_sql_bypass"],
                            "status": "EXPLOITED_200",
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC")
                        })

                    with open(os.path.join(TEMPLATES_DIR, "victim_portal.html"), "r") as f:
                        html = f.read()

                    html = html.replace("{{ user.username if user else \"Employee\" }}", first.get("username", "Employee"))
                    html = html.replace("{{ user.username if user else \"User\" }}", first.get("username", "User"))
                    html = html.replace("{{ user.role if (user and user.role) else \"Standard Access\" }}", str(first.get("role", "Standard Access")))
                    html = html.replace("{{ user.id if user else \"1001\" }}", str(first.get("id", "1001")))
                    html = html.replace("{{ user.email if (user and user.email) else \"employee@apexcloud.internal\" }}", str(first.get("email", "employee@apexcloud.internal")))
                    html = html.replace("{{ \"ADMIN_ROOT\" if (user and (\"admin\" in user.username or user.super_privilege)) else \"STANDARD_TOKEN\" }}", "ADMIN_ROOT" if is_exploited else "STANDARD_TOKEN")

                    if is_exploited:
                        # Construct dumped rows
                        table_rows = "".join([f"<tr><td class='mono'>{r[0]}</td><td class='mono' style='font-weight:600;color:#1e3a8a;'>{r[1]}</td><td class='mono' style='color:#9f1239;'>{r[2]}</td><td class='mono'>{r[3]}</td></tr>" for r in rows])
                        html = html.replace("{% if dumped_records and dumped_records|length > 1 %}", "")
                        html = html.replace("{% for r in dumped_records %}", "")
                        html = html.replace("{% endfor %}", "")
                        html = html.replace("{{ dumped_records|length }}", str(len(rows)))
                        # Replace sample rows inside tbody
                        if "<tbody>" in html and "</tbody>" in html:
                            parts = html.split("<tbody>")
                            rest = parts[1].split("</tbody>")
                            html = parts[0] + "<tbody>" + table_rows + "</tbody>" + rest[1]
                        html = html.replace("{% endif %}", "")
                    else:
                        if "{% if dumped_records and dumped_records|length > 1 %}" in html:
                            p1 = html.split("{% if dumped_records and dumped_records|length > 1 %}")[0]
                            p2 = html.split("{% endif %}")[1]
                            html = p1 + p2

                    self.send_html(html, code=200)
                else:
                    with open(os.path.join(TEMPLATES_DIR, "victim_login.html"), "r") as f:
                        html = f.read()
                        html = html.replace("{% if error_msg %}", "").replace("{% endif %}", "")
                        html = html.replace("{{ error_msg }}", "Invalid credentials. Please verify your employee ID and password.")
                        html = html.replace("{{ username or '' }}", username)
                    self.send_html(html, code=200)

            except sqlite3.OperationalError as e:
                with open(os.path.join(TEMPLATES_DIR, "victim_login.html"), "r") as f:
                    html = f.read()
                    html = html.replace("{% if error_msg %}", "").replace("{% endif %}", "")
                    html = html.replace("{{ error_msg }}", f"Database Execution Error: {str(e)}")
                    html = html.replace("{{ username or '' }}", username)
                self.send_html(html, code=200)

def main():
    port = 8080
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    server = HTTPServer(("0.0.0.0", port), SeminarAppHandler)
    print(f"[+] Server started on http://127.0.0.1:{port}")
    print(f"[+] Public Victim Website: http://127.0.0.1:{port}/")
    print(f"[+] SOC AI Dashboard:      http://127.0.0.1:{port}/soc")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")

if __name__ == "__main__":
    main()
