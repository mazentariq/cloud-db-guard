#!/usr/bin/env python3
"""
Academic Seminar PoC - Topic 21: AI-Powered Cloud Database Security
Database Setup Script (db_setup.py)

Creates a realistic SQLite database with two distinct tables:
1. `users`: standard corporate accounts (id, username, password, email, role, created_at)
2. `admins`: privileged executive accounts (id, username, password, super_privilege, api_secret, clearance_level)
"""

import os
import sqlite3

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable_cloud_db.sqlite")

def init_database(db_path: str = DB_FILE):
    """Initializes schema and populates dummy enterprise data."""
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"[*] Cleared existing database at {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("[*] Creating table: `users` (standard employee accounts)...")
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'standard_user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    print("[*] Creating table: `admins` (privileged security/root accounts)...")
    cursor.execute("""
        CREATE TABLE admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            super_privilege INTEGER DEFAULT 1,
            api_secret TEXT NOT NULL,
            clearance_level TEXT DEFAULT 'LEVEL_5_TOP_SECRET'
        );
    """)

    dummy_users = [
        ("alice_dev", "P@ssword2026!", "alice.dev@apexcloud.internal", "cloud_engineer"),
        ("bob_analyst", "BobSecure#44", "bob.analyst@apexcloud.internal", "data_analyst"),
        ("charlie_ops", "OpsWinter$99", "charlie.ops@apexcloud.internal", "site_reliability"),
        ("diana_qa", "TestPass2026", "diana.qa@apexcloud.internal", "qa_lead"),
        ("evan_sales", "SalesTarget!2026", "evan.sales@apexcloud.internal", "account_exec"),
        ("fiona_hr", "PeopleOps#77", "fiona.hr@apexcloud.internal", "hr_manager"),
        ("george_intern", "Intern2026!", "george.intern@apexcloud.internal", "intern"),
        ("helen_finance", "AuditVault%88", "helen.finance@apexcloud.internal", "financial_controller")
    ]

    cursor.executemany("""
        INSERT INTO users (username, password, email, role)
        VALUES (?, ?, ?, ?);
    """, dummy_users)

    # Seed admins - Target for UNION SQLi Exfiltration
    dummy_admins = [
        ("superadmin", "RootMasterKey!999", 1, "sec_live_99f01abce291410d9e871", "LEVEL_5_EXECUTIVE"),
        ("secops_lead", "ZeroTrust#Enforcer", 1, "sec_live_44bcae1824aa4771bb890", "LEVEL_5_SECOPS"),
        ("cloud_architect", "InfraRoot$2026", 1, "sec_live_77ccdf9911ee2288aa334", "LEVEL_4_INFRA"),
        ("db_administrator", "PostgresRoot*Pass", 1, "sec_live_11aa22bb33cc44dd55ee6", "LEVEL_5_DBA"),
        ("emergency_breakglass", "BreakGlass_Key_K8s!", 1, "sec_live_00ff99ee88dd77cc66bb5", "LEVEL_5_BREAKGLASS")
    ]

    cursor.executemany("""
        INSERT INTO admins (username, password, super_privilege, api_secret, clearance_level)
        VALUES (?, ?, ?, ?, ?);
    """, dummy_admins)

    conn.commit()
    conn.close()

    print(f"[+] Successfully initialized database: {db_path}")
    print(f"[+] Populated {len(dummy_users)} standard users in `users`.")
    print(f"[+] Populated {len(dummy_admins)} privileged administrators in `admins`.")

if __name__ == "__main__":
    init_database()
