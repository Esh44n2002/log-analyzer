# Security Log Analyzer

A Python and SQLite-based security log analyzer that processes structured login logs, validates data, stores records in a database, and detects suspicious authentication attacks.

--------------------------------------------------

FEATURES

- Parses structured log data (IP, status, timestamp, port, service)
- Validates and skips invalid or malformed log entries
- Stores logs in SQLite database
- Uses SQL to analyze failed login attempts
- Detects:
  - SSH brute force attacks (port 22)
  - RDP brute force attacks (port 3389)
  - Possible credential stuffing
- Displays:
  - Attack type
  - Entry point (service)
  - Port
  - Attack start time
- Detects possible credential stuffing based on     repeated failed attempts followed by a successful  login
--------------------------------------------------

LOG FORMAT

Each log entry follows:

IP STATUS TIMESTAMP PORT SERVICE

Example:

192.168.1.1 FAIL 2026-04-13T10:01:00 22 SSH
192.168.1.3 FAIL 2026-04-13T10:06:00 3389 RDP

--------------------------------------------------

EXAMPLE OUTPUT

---- SECURITY ALERT REPORT ----
Valid rows inserted: 22
Invalid rows skipped: 2

IP: 192.168.1.1
Attack Type: SSH Brute Force Attack
Entry Point: SSH Authentication Service
Port: 22
Start Time: 2026-04-13T10:01:00
Details: Multiple failed SSH login attempts detected

IP: 192.168.1.3
Attack Type: RDP Brute Force Attack
Entry Point: RDP Authentication Service
Port: 3389
Start Time: 2026-04-13T10:06:00
Details: Multiple failed RDP login attempts detected

---- POSSIBLE CREDENTIAL STUFFING REPORT ----

IP: 192.168.1.11
Attack Type: Possible Credential Stuffing
Entry Point: SSH Authentication Service
Port: 22
Start Time: 2026-04-13T10:20:00
Details: Multiple failed login attempts followed by a successful SSH login from the same source IP

--------------------------------------------------

HOW TO RUN

1. Make sure Python 3 is installed
2. Run:

python3 security_log_analyzer.py

--------------------------------------------------

PROJECT STRUCTURE

security_log_analyzer.py   -> Main script  
logs.txt                   -> Input log file  
README.md                  -> Documentation  
.gitignore                 -> Ignored files  

--------------------------------------------------

SKILLS DEMONSTRATED

- Python (file handling, logic, validation)
- SQLite (database operations)
- SQL (GROUP BY, aggregation, filtering)
- Log parsing and structured data processing
- Basic cybersecurity concepts (authentication attacks, brute force detection)

--------------------------------------------------

NOTES

- logs.db is generated automatically and ignored via .gitignore
- Project focuses on authentication-based attack detection
- Simulates a simplified real-world log analysis system

--------------------------------------------------

FUTURE IMPROVEMENTS

- Credential stuffing detection (FAIL → SUCCESS pattern)
- Time-based attack detection
- Support for additional services and ports
- Multi-source log correlation