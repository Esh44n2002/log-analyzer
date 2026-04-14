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

#Query failed attempts per IP
cursor.execute("""
SELECT ip, port, service, COUNT(*), MIN(timestamp)
FROM logs
WHERE status = 'FAIL' 
GROUP BY ip, port, service
""")

rows = cursor.fetchall()

print("----SUSPICIOUS ACTIVITY REPORT----")

threshold = 3

for row in rows:
    ip = row[0]
    port = row[1]
    service = row[2]
    count = row[3]
    start_time = row[4]

    if count >= threshold:
        
        #Attack classification
        if str(port) == "22" or service.upper() == "SSH":
            attack_type = "SSH Brute Force Attack"
            entry_point = "SSH Authentication Service"
            details = "Multiple failed SSH login attempts detected"

        elif str(port) == "3389" or service.upper() == "RDP":
            attack_type = "RDP Brute Force Attack"
            entry_point = "RDP Authentication Service"
            details = "Multiple failed RDP login attempts detected"
        
        else:
            attack_type = "Suspicious Authentication Activity"
            entry_point = f"{service} Service"
            details = "Multiple failed authentication attempts detected"

        print("IP", ip)
        print("Attack Type:", attack_type)
        print("Entry Point:", entry_point)
        print("Port:", port)
        print("Start Time:", start_time)
        print("Details:", details)
        print()

#Close database connection
conn.close()
