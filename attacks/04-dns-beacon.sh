#!/bin/bash
# 04 - DNS beaconing. One TXT query every 3 seconds, numbered subdomains,
# to a domain that does not exist. No signature fires on this. The evidence
# lives in Zeek dns.log: 15 queries, qf1..qf15.c2b6.local, all NXDOMAIN,
# metronomic cadence. A frequency query on any domain catches this shape.
for i in $(seq 1 15); do
  dig +short +time=2 +tries=1 @8.8.8.8 qF$i.c2b6.local TXT >/dev/null 2>&1
  sleep 3
done
