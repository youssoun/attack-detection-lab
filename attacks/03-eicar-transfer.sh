#!/bin/bash
# 03 - malware test file over HTTP. EICAR, the standard antivirus test string,
# served by the bait server, downloaded by the attack box.
# Detected: ETPRO INFO Observed EICAR Test File String Inbound
wget -q -T 8 http://192.168.100.50:8080/eicar.txt -O /dev/null
