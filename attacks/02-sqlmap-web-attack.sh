#!/bin/bash
# 02 - SQL injection probes with the sqlmap user agent, no sqlmap needed.
# Detected: ET SCAN Sqlmap SQL Injection Scan
#           ETPRO WEB_SERVER SQLMap Scan Tool User Agent
# The bait server was a static python http server on port 8080, started
# for the test and stopped after. Suricata inspects the requests on the
# wire, it does not care what the server does with them.
curl -s -A "sqlmap/1.7#stable" "http://192.168.100.50:8080/login.php?id=1%20OR%201=1%20UNION%20SELECT%20password%20FROM%20users--" -o /dev/null
curl -s -A "sqlmap/1.7#stable" "http://192.168.100.50:8080/shop.php?cat=1%27%20AND%20SLEEP(5)--" -o /dev/null
