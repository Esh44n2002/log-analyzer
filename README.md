#Log analyzer
This project analyzes login logs and detects suspicious IP addresses based on repeated failed login attempts.

## Features
- Reads login data from a file
- Counts failed login attempts per IP
- Flags suspicious IPs using a threshold

## Example Input
192.168.1.1 FAIL
192.168.1.2 SUCCESS
192.168.1.1 FAIL
192.168.1.3 SUCCESS
192.168.1.1 FAIL

## Example output
192.168.1.1 is suspicious with 3 failed attempts

## How to run
python3 read_logs.py
