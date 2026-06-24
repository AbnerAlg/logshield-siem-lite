# LogShield SIEM Lite 🛡️

A lightweight Security Information and Event Management (SIEM) MVP designed to parse, analyze, and visualize server logs for automated security threat detection.

## Overview

LogShield SIEM Lite allows system administrators and security analysts to upload log files (Apache/Nginx/Linux) and automatically scan them for malicious patterns. The application parses raw text data into structured security events and triggers alerts based on predefined correlation rules.

### Key Features (MVP)
* **Log Ingestion:** Manual file upload for Apache, Nginx, or Linux access logs.
* **Automated Parser:** Extracts crucial data points (IP address, Timestamp, HTTP Method, Request Path, Status Code).
* **Security Rule Engine:** Detects anomalies such as:
  * Brute Force attacks (5+ failed logins from the same IP in 60 seconds).
  * Web Directory Busting & Path Traversal (Suspicious patterns like `../`, `etc/passwd`, `/admin`).
  * 404 Error Storms (High frequency of Not Found responses).
* **Interactive Dashboard:** Visualizes critical metrics, severities, top attacking IPs, and an event timeline.
* **Reports:** Export security findings into structured JSON files.

## 🛠️ Tech Stack

* **Backend:** Python, FastAPI, Pydantic, SQLAlchemy.
* **Database:** PostgreSQL.
* **Frontend:** Vue.js (Vite), Tailwind CSS, Chart.js / ApexCharts (for metrics).

## 🛑 Scope & Out of Scope (MVP V1 Limits)

To ensure a realistic and functional Minimum Viable Product (MVP), this initial version (V1) focuses strictly on the core log parsing and basic security rule detection. 

**The Rule:** If it does not directly help with uploading a log file and detecting brute-force or immediate anomalies, it is out of scope for V1.

### 🚫 Out of Scope for V1 (Planned for Future Releases)
* **No Real-Time Analysis:** Logs are processed via manual file upload (`.log` or `.txt`). Real-time streaming is not supported yet.
* **No Authentication or User Roles:** There is no login, registration, or multi-tenant admin roles. The dashboard is open for local or single-instance use.
* **No Advanced Visualizations:** No complex charts, graphs, or geographic maps for IP tracking will be included in the V1 UI.
* **No WebSockets or Event Queues:** Data is fetched via standard HTTP REST endpoints.
* **Simulated/Standard Logs Only:** The parser targets standard Nginx/Apache Common Log Format (CLF). Raw, non-standard enterprise Linux system logs are out of scope for now.
