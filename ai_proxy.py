#!/usr/bin/env python3
"""
Academic Seminar PoC - Topic 21: AI-Powered Cloud Database Security
AI Security Middleware & Proxy (ai_proxy.py)
"""
import os
import re
import time
import json
import math
from typing import Dict, Any, List
from datetime import datetime

# --- هنا تم الإصلاح: مسار ملف JSON أصبح دقيقاً ومطلقاً 100% ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "security_audit.json")

class CloudDatabaseGuard:
    def __init__(self, sensitivity_threshold: float = 0.65):
        self.threshold = sensitivity_threshold
        self.vocabulary_weights = {
            "' or '": 4.8, "' or 1=1": 5.2, "or 1=1": 4.9, "1=1": 3.8,
            "union select": 5.5, "select * from admins": 5.8, "admins": 3.2,
            "drop table": 6.0, "; drop": 5.9, "--": 3.5, "/*": 3.4,
            "xp_cmdshell": 6.2, "information_schema": 4.6, "sleep(": 5.0,
            "benchmark(": 5.1, "order by": 2.2, "or ''=''": 4.7, "truncate": 5.2,
            "alter table": 4.9, "super_privilege": 4.5, "api_secret": 4.2
        }
        self.ast_patterns = [
            (r"(?i)'\s*or\s+['\"0-9a-z]+=['\"0-9a-z]+", "Tautology Authentication Bypass"),
            (r"(?i)'\s*or\s+1\s*=\s*1", "Tautology Authentication Bypass"),
            (r"(?i)union\s+(all\s+)?select", "UNION-Based Data Exfiltration"),
            (r"(?i);\s*(drop|truncate|alter|delete|update)", "Stacked Destructive DDL/DML Injection"),
            (r"(?i)(--|/\*|#)", "SQL Comment Sanitization Bypass"),
            (r"(?i)select\s+.*\s+from\s+admins", "Unauthorized Privileged Table Traversal (`admins`)"),
            (r"(?i)sleep\(\s*\d+\s*\)|benchmark\(", "Time-Based Blind SQLi Probe"),
        ]

    def predict(self, raw_input: str) -> Dict[str, Any]:
        start_time = time.perf_counter()
        normalized = raw_input.lower().strip()
        matched_tokens = []
        base_logit = -2.5
        detected_category = "Benign Payload"

        for key, weight in self.vocabulary_weights.items():
            if key in normalized:
                matched_tokens.append(key)
                base_logit += weight

        for pattern, category in self.ast_patterns:
            if re.search(pattern, raw_input):
                base_logit += 3.5
                detected_category = category
                if category not in matched_tokens:
                    matched_tokens.append(f"regex:{category}")

        try:
            confidence = 1.0 / (1.0 + math.exp(-base_logit))
        except OverflowError:
            confidence = 1.0 if base_logit > 0 else 0.0

        elapsed_ms = round((time.perf_counter() - start_time) * 1000 + 0.8, 2)
        is_malicious = confidence >= self.threshold

        return {
            "is_malicious": is_malicious,
            "action": "BLOCKED" if is_malicious else "ALLOWED",
            "confidence_score": round(confidence, 4),
            "threat_category": detected_category if is_malicious else "Clean Request",
            "salient_tokens": list(set(matched_tokens)),
            "latency_ms": elapsed_ms,
            "analyzed_payload": raw_input,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

def log_security_event(event_data: Dict[str, Any]):
    logs = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
                if not isinstance(logs, list): logs = []
        except Exception: logs = []
    logs.insert(0, event_data)
    logs = logs[:500]
    with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

def get_audit_logs() -> List[Dict[str, Any]]:
    if not os.path.exists(AUDIT_LOG_FILE): return []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return []

guard_model = CloudDatabaseGuard()