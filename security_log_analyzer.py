import sqlite3

#Connect to SQL databaase
conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

#Reset table so every run starts fresh
cursor.execute("DROP TABLE IF EXISTS logs")

#Create logs table
cursor.execute(""" 
CREATE TABLE logs (
    ip TEXT,
    status TEXT,
    timestamp TEXT,
    port INTEGER,
    service TEXT           
)
""")

invalid_count = 0
valid_count = 0

#Read logs from file and insert into database
with open("logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split()

        #Each valid line must have 5 parts
        if len(parts) != 5:
            invalid_count +=1
            continue

        ip = parts[0]
        status = parts[1]
        timestamp = parts[2]
        port = parts[3]
        service = parts[4]

        #Status must be either FAIL or SUCCESS
        if status not in ["FAIL", "SUCCESS"]:
            invalid_count += 1
            continue

        cursor.execute(
            "INSERT INTO logs (ip, status, timestamp, port, service) VALUES (?, ?, ?, ?, ?)",
            (ip,status, timestamp, port, service)
        )

        valid_count += 1

#save inserted row
conn.commit()

print("---- POSSIBLE CREDENTIAL STUFFING REPORT ----")
print()

#Query failed attempts per IP
cursor.execute("""
SELECT ip, port, service,
    SUM(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) AS fail_count,
    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS success_count,
    MIN(timestamp)
FROM logs
GROUP BY ip, port, service
""")

rows = cursor.fetchall()

fail_threshold = 3

for row in rows:
    ip = row[0]
    port = row[1]
    service = row[2]
    fail_count = row[3]
    success_count = row[4]
    start_time = row[5]

    if fail_count >= fail_threshold and success_count >= 1:
        
        #Attack classification
        if str(port) == "22" or service.upper() == "SSH":
            attack_type = "Possible Credential Stuffing"
            entry_point = "SSH Authentication Service"
            details = "Multiple failed login attempts followed by a successful SSH login from the same source IP"

        elif str(port) == "3389" or service.upper() == "RDP":
            attack_type = "Possible Credential Stuffing"
            entry_point = "RDP Authentication Service"
            details = "Multiple failed login attempts followed by a successful RDP login from the same source IP"

        else:
            attack_type = "Possible Credential Stuffing"
            entry_point = f"{service} Service"
            details = "Multiple failed login attempts followed by a successful authentication from the same source IP"
            
        
        print("IP:", ip)
        print("Attack Type:", attack_type)
        print("Entry Point:", entry_point)
        print("Port:", port)
        print("Start Time:", start_time)
        print("Details:", details)
        print()

#Close database connection
conn.close()
