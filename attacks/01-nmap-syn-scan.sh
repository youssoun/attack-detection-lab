#!/bin/bash
# 01 - SYN port scan, the classic. Detected: ET SCAN NMAP -sS window 1024
# Target: the router, over the wire. A target on the same hypervisor would not be seen.
nmap -sS -Pn -p 1-400 192.168.100.1
