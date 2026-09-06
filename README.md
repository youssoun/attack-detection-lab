# attack-detection-lab

Real attacks launched against a home network, and the honest answer of a
Corelight software sensor (Zeek + Suricata) watching the wire through a
managed switch SPAN port. Every detection below actually fired. The gaps
are documented too, because a table that only shows wins is marketing,
not detection engineering.

## The chain

```
Kali VM (attack box)
        |
managed switch ---- SPAN port ----> Corelight software sensor
        |                                 |  (Zeek + Suricata)
consumer router                             v
                                   Elasticsearch + Kibana
```

One Proxmox host runs the sensor and Elasticsearch. The sensor sees the
SPAN feed from the switch, not a mirrored virtual switch, which matters
later: traffic between two machines on the same host never touches the
SPAN and is invisible. That blind spot is documented at the end.

## What actually fired

Six attacks, run from the attack box against targets that are reachable
over the wire. All timestamps in UTC. The sensor and the SIEM are on
RFC1918 addresses only, nothing here is routable.

| # | Attack | Tool | Detection | MITRE |
|---|--------|------|-----------|-------|
| 1 | SYN port scan, 400 ports | nmap | `ET SCAN NMAP -sS window 1024`, plus 14 `GPL SNMP` alerts from the service probes | T1046 |
| 2 | Fast port scan, 500 ports at 600 pps | masscan | `ET EXPLOIT RST Flood With Window` x4, plus the NMAP signature | T1046 |
| 3 | SQL injection probes | curl, sqlmap user agent, UNION and SLEEP payloads | `ET SCAN Sqlmap SQL Injection Scan` x2 and `ETPRO WEB_SERVER SQLMap Scan Tool User Agent` | T1190 |
| 4 | Malware test file over HTTP | wget | `ETPRO INFO Observed EICAR Test File String Inbound` | T1105 |
| 5 | DNS beaconing, 15 TXT queries every 3 s | dig | Zeek `dns.log`: subdomain pattern `qf1..qf15.c2b6.local`, all NXDOMAIN, fixed 3 s cadence. No signature, pure telemetry | T1071.004 |
| 6 | Nothing at all | a Kali VM joining the network | `ET INFO Possible Kali Linux hostname in DHCP Request Packet` | passive |

Number 6 is my favorite. The sensor identified the attack box by its
DHCP hostname before a single packet of the campaign was sent. The
attack box cannot hide its nature on this network, and neither can a
rogue laptop plugged into the same switch.

Extra signals that fired during the same window, worth keeping in mind
for any red team work: `ET INFO Wget User Agent`, `ET INFO Python
SimpleHTTP ServerBanner` x3 (the bait server got fingerprinted the same
way an attacker would fingerprint a victim), `ET INFO HTTP Request on
Unusual Port Possibly Hostile`. Total for the campaign window: 31
Suricata alerts, plus the Zeek DNS evidence.

## What did not fire

Two findings, both useful.

**SSH brute force is a coverage gap.** Hydra ran 200 password attempts
against an SSH target over the wire, 12 parallel connections, and
nothing alerted. I queried 30 days of history: not a single alert from
any SSH rule ever, so the brute force ruleset is simply not part of the
deployed policy. The fix is known, enable the SSH scan category in the
Fleet policy. The gap itself is the finding: an attack every security
team assumes is covered was free to run here.

**Same host, same bridge, invisible.** Traffic between the Kali VM and
a container on the same Proxmox host never leaves the host, so the SPAN
never sees it. Measured: the round trip was 27 microseconds, which is a
local bridge shortcut, and zero corresponding events in the sensor. Any
lab design where the attack box and the victim share a hypervisor is
partially blind. Put the attack box on different hardware, or accept
that those flows are outside the sensor's view.

## Reproducing

Attack scripts are in `attacks/`, one per technique, plain bash. The
SIEM queries are in `queries.md`, they are plain Elasticsearch queries
that run from any machine that can reach the cluster. The sensor needs
an interface on a SPAN port with no IP address, and the capture host
must sit on a different machine than the attack box, as explained above.

The bait HTTP server used for attacks 3 and 4 is three lines of python
`http.server`, serving a static EICAR file and a fake login page, bound
to a LAN address for the duration of the test, then stopped.

## Queries

See `queries.md`. The two I ended up using the most:

Alerts from one source, last N minutes:

```
GET logs-corelight.suricata*
{ "query": { "bool": { "filter": [
  { "range": { "@timestamp": { "gte": "now-10m" } } },
  { "term": { "source.ip": "192.168.100.10" } }
] } }, "sort": [{ "@timestamp": "desc" }] }
```

DNS beaconing: subdomain pattern plus NXDOMAIN, fixed cadence:

```
GET logs-corelight.dns*
{ "query": { "bool": { "filter": [
  { "range": { "@timestamp": { "gte": "now-15m" } } },
  { "match": { "dns.question.name": "c2b6.local" } }
] } } }
```

## Why this exists

A network detection chain is easy to install and easy to misjudge. The
only way to know what your sensor actually sees is to attack it on
purpose, then read the answer. This repo is that answer for one
particular home lab, with the gaps left in on purpose.
