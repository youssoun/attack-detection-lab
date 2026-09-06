# Queries used to read the answer

All of these ran against Elasticsearch 8, index pattern
`logs-corelight.*`, from a machine that can reach the cluster. Replace
the source IP with the attack box of your own lab.

## Alerts from the attack box, campaign window

    GET logs-corelight.suricata*/_search
    {
      "size": 20,
      "query": { "bool": { "filter": [
        { "range": { "@timestamp": { "gte": "now-10m" } } },
        { "term": { "source.ip": "192.168.100.10" } }
      ] } },
      "sort": [{ "@timestamp": "desc" }]
    }

Same, with a rule breakdown (the one that produced the counts table):

    GET logs-corelight.suricata*/_search
    {
      "size": 0,
      "query": { "bool": { "filter": [
        { "range": { "@timestamp": { "gte": "now-10m" } } },
        { "term": { "source.ip": "192.168.100.10" } },
        { "exists": { "field": "rule.signature_id" } }
      ] } },
      "aggs": { "rules": { "terms": { "field": "rule.name", "size": 15 } } }
    }

## DNS beaconing hunt

    GET logs-corelight.dns*/_search
    {
      "size": 20,
      "query": { "bool": { "filter": [
        { "range": { "@timestamp": { "gte": "now-15m" } } },
        { "term": { "source.ip": "192.168.100.10" } }
      ] } },
      "sort": [{ "@timestamp": "desc" }]
    }

Sample of what came back for the beacon, 15 entries of this shape, three
seconds apart, every one of them NXDOMAIN:

    22:50:32  qf15.c2b6.local  NXDOMAIN
    22:50:29  qf14.c2b6.local  NXDOMAIN
    22:50:26  qf13.c2b6.local  NXDOMAIN
    22:50:23  qf12.c2b6.local  NXDOMAIN

A production hunt would not know the domain name in advance. The
shapeless version looks for fixed-length subdomain labels with a high
NXDOMAIN ratio from one client, then pivots on that client. One day of
this lab's DNS log is around 300 000 events, the query takes seconds.

## The negative result query

Before claiming a gap, check the rule family has EVER fired:

    GET logs-corelight.suricata*/_search
    {
      "size": 0,
      "query": { "match_phrase": { "rule.name": "SSH" } }
    }

Zero hits over 30 days of history on this sensor, which is how the SSH
brute force gap was confirmed: the rules simply are not in the policy,
it is not a detection failure but a coverage hole.
