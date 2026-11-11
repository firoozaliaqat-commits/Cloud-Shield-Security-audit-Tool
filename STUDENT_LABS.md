# HCCDP Cloud Security Practical — student worksheet

Record each exercise with a screenshot and interpretation. Don't only click Start: **explain what the evidence means**.

| # | Exercise | Evidence to record |
|---|---|---|
| 1 | View dashboard and health | HTTP 200 from `/healthz` |
| 2 | Inspect container health | `docker compose ps` |
| 3 | Inspect WAF proxying | Protected `/target/data` returns HTTP 200 |
| 4 | Normal HTTP traffic with k6 | Run ID and summary |
| 5 | Valid demo login | HTTP 200 |
| 6 | Invalid demo login | HTTP 401 |
| 7 | Five invalid logins | Lab Guard timed ban appears |
| 8 | Observe ban enforcement | HTTP 429 for banned test source |
| 9 | Change automatic-ban TTL | One-minute test policy saved |
| 10 | Observe automatic unban | Ban disappears on expiry |
| 11 | Manually block private IP | IP and reason appear in bans table |
| 12 | Manually unblock IP | Activity logged in events |
| 13 | Trigger safe WAF signature | WAF denial appears; Coraza container logs |
| 14 | Run higher k6 virtual users | Compare request rate and errors |
| 15 | Trigger Emergency Stop | Job stops before configured duration |
| 16 | Stream 4 MiB per request | Throughput vs latency/CPU |
| 17 | View Prometheus raw metrics | `/metrics` request and block counters |
| 18 | View Grafana requests/sec | Compare before/after load |
| 19 | Compare HTTP 401 / 429 / 403 | Which layer generated each? |
| 20 | Check CrowdSec log acquisition | `cscli metrics` parser/acquisition counters |
| 21 | Add genuine CrowdSec decision | CLI decision list contains lab IP |
| 22 | Observe CrowdSec bouncer | Request receives HTTP 403 (after cache TTL) |
| 23 | Remove CrowdSec decision | Request no longer blocked (after cache TTL) |
| 24 | Enable ClamAV profile | Daemon ready after signature download |
| 25 | Upload ordinary text file | Real ClamAV clean verdict |
| 26 | Upload EICAR safe test file | Signature detected; no live malware |
| 27 | Analyze generated PCAP | Suricata `eve.json` alert |
| 28 | Investigate alert rule SID | Find SID 1000001 in `lab.rules` |
| 29 | Restart the Compose stack | SQLite bans/reports persist in named volume |
| 30 | Write an incident report | Detection, source, evidence, TTL, recovery and false positives |

## Reflection questions

- Why can an application-level ban be ineffective for non-HTTP SSH traffic?
- Why does a WAF response 403 not guarantee CrowdSec has also detected the request?
- Why do 40 k6 VUs **not** equate to 40 Gbps or 40 concurrent sockets at all times?
- What architecture changes are necessary to capture traffic from a *different* ECS in the same VPC?
- How do you distinguish a ClamAV clean result from proof that a file is safe?
- Why is a no-login classroom control panel unsafe to expose on a public ECS IP?

### Optional second ECS

After instructor whitelists `VPC_TARGET_URL` using a private RFC1918 address, use the **Private VPC HTTP GET** profile (at most 20 VUs/120 seconds) and compare HTTP latency and service health on the remote ECS. Do not treat this HTTP test as an iperf3 bandwidth test.

## Demo Store journey (v1.1)

- [ ] Open `http://localhost:8080/target/store` using the SSH tunnel and capture the storefront.
- [ ] Search for a product and place a fake order; capture the returned order ID. No payment is involved.
- [ ] Start CloudShield **Demo Store journey** with 5 virtual users for 30 seconds.
- [ ] Increase to 10 and 20 users in separate runs; compare request count, p95 latency and errors.
- [ ] Trigger 5 failed logins against the included sample app; verify the appropriate test client is banned.
- [ ] Record block response and the exact ban expiry time; verify access is restored after TTL.
- [ ] Test the WAF signature scenario and inspect proxy logs. Do not claim WAF success without observing an actual 403 block.
- [ ] Submit screenshots of demo-store order, CloudShield runs/bans, and Grafana metrics alongside a short analysis of what was truly observed.
