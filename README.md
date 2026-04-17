# 🔐 Python Cybersecurity Toolkit — Sandbox & Honeypot System

> Two production-inspired security systems built in Python demonstrating 
> defence-in-depth principles used in real-world security engineering.

---

## 📋 Overview

This repository contains two independent cybersecurity systems.

| System | Technique |
|--------|-----------|
| Controlled Execution Sandbox | AST Analysis + Runtime Isolation |
| Deception-Based Honeypot | Fake Login + Dummy API + Trap File |

---

## 🛡️ Controlled Execution Sandbox

### What it does
Safely executes untrusted Python code by enforcing strict 
security constraints across two independent layers.

### How it works

**Layer 1 — Static AST Analysis (before execution)**
- Parses input into an Abstract Syntax Tree
- Blocks all import statements (os, subprocess, socket, etc.)
- Blocks forbidden built-ins: exec(), eval(), open(), __import__()
- Blocks dunder escape chains (__class__, __bases__, __subclasses__)
- Blocks file system and network attribute access

**Layer 2 — Time-Limited Runtime Execution**
- Runs code in a restricted namespace (whitelisted builtins only)
- Kills execution after 5 seconds (infinite loop protection)
- Captures and truncates output to prevent memory exhaustion
- Logs all events to a persistent audit trail

### Attack vectors blocked
- ✅ import os / subprocess / socket
- ✅ exec() and eval() injection
- ✅ File read via open('/etc/passwd')
- ✅ Python sandbox escape via dunder chains
- ✅ Infinite loops and CPU exhaustion

### Run it
```bash
# Demo mode — tests all scenarios automatically
python3 task2_sandbox.py

# Interactive mode — test your own code
python3 task2_sandbox.py --interactive
```

---

## 🍯 Deception-Based Honeypot System

### What it does
Detects malicious behaviour by luring attackers into interacting 
with fake infrastructure. Any interaction triggers an immediate alert.

### Three traps deployed

**Trap 1 — Fake Login Portal (HTTP :8080)**
- Realistic corporate admin panel with dark theme and branding
- Captures attacker IP, User-Agent, and submitted credentials
- Password stored as SHA-256 hash (never plaintext)
- Triggers CRITICAL alert on login attempts

**Trap 2 — Dummy API Service (/api/admin/keys)**
- Simulates a real credential management REST API
- Returns convincing but entirely fake API key data
- Logs every request method, path, and request body
- Triggers HIGH alert on every interaction

**Trap 3 — Honeypot File (/tmp/honeypot_secrets.txt)**
- Planted file containing fake credentials and cloud keys
- Monitored every second via filesystem metadata polling
- Detects read, write, and delete events
- Triggers HIGH/CRITICAL alert the moment it is touched

### Alert severity levels
| Severity | Trigger |
|----------|---------|
| 🔴 CRITICAL | Login attempt with credentials submitted |
| 🟠 HIGH | API access, file read/write/delete |
| 🟡 MEDIUM | Login page probed (GET request) |
| 🔵 LOW | Unknown endpoint probe |

### Run it
```bash
# Demo mode — simulates full attacker session
python3 task3_honeypot.py --demo

# Live server mode — waits for real connections
python3 task3_honeypot.py --serve
```

---

## 📊 Sample Output

### Sandbox
▶ Test: ATTACK – import os
Status    : ❌ REJECTED
Violations: Line 1: Import statement forbidden: ['os']
Line 2: Forbidden attribute call: .listdir()
▶ Test: Safe arithmetic
Status    : ✅ ACCEPTED
Exec time : 0.002s
Output    : 2^10 = 1024

### Honeypot


🔴 [CRITICAL] FAKE_LOGIN_PORTAL | POST login attempt | user=admin
🟠 [HIGH    ] DUMMY_API         | GET /api/admin/keys
🟠 [HIGH    ] HONEYPOT_FILE     | File READ detected

---

## 🗂️ Log Files Generated

| File | Contents |
|------|----------|
| `sandbox_audit.log` | Timestamped log of all sandbox executions |
| `honeypot_alerts.log` | Plain text alert log |
| `honeypot_alerts.json` | Structured JSON alerts (SIEM-ready) |

---

## ⚙️ Requirements

- Python 3.11+
- No external dependencies — standard library only

---

## 🧠 Key Security Concepts Demonstrated

- **Defence in depth** — multiple independent security layers
- **Principle of least privilege** — whitelist over blacklist
- **Deception-based detection** — honeypot architecture
- **Audit logging** — tamper-evident event trails
- **Threat intelligence** — attacker behaviour capture

---

## 📁 File Structure

├── task2_sandbox.py       # Controlled Execution Sandbox
├── task3_honeypot.py      # Deception-Based Honeypot System
└── README.md

---

## 👩‍💻 Author
Suhana 
