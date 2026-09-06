#!/bin/bash
# 05 - fast scan. masscan at 600 packets per second.
# Detected: ET EXPLOIT RST Flood With Window (x4), plus ET SCAN NMAP -sS.
# A tool that screams leaves fingerprints from two different rule families.
masscan 192.168.100.1 -p1-500 --rate=600
