logs = ["FAIL", "SUCCESS", "FAIL", "FAIL", "SUCCESS"]

fail_count = 0

for log in logs:
    if log == "FAIL":
        fail_count += 1

print("Total FAIL:", fail_count) 
print("Done for today")
