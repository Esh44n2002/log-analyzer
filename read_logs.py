ip_fail_count ={} #Dictionary to store failed login attemts per IP

#opens and reads the log file
with open("logs.txt", "r") as file: 
    for line in file:
        parts = line.strip().split()

        ip = parts[0]
        status = parts[1]

        #Counts only failed attempts
        if status =="FAIL": 
            if ip in ip_fail_count:
                ip_fail_count[ip] += 1
            else:
                ip_fail_count[ip] = 1

threshold = 3 #Threshold for suspicious activity

print("----Suspicious Activity Report----")

#Check and print results
for ip in ip_fail_count:
    if ip_fail_count[ip] >= 3:
        print(ip, "is suspicious with", ip_fail_count[ip], "failed attempts")
    else:
        print(ip, "failed", ip_fail_count[ip], "times")
