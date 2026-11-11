# CloudShield KooLab 1.0 — Huawei ECS Security & Load Testing Classroom

CloudShield is an **actual source-code application**, delivered with an Ubuntu Docker Compose stack and a single-node K3s/Kubernetes deployment path. It teaches students how an HTTP WAF, behavioral IP bans, a CrowdSec decision bouncer, metrics collection, antivirus scanning, an IDS, and bounded application load generation work together.

**Safety scope:** The web UI has no login **by classroom design**. The Compose port is **bound to localhost by default**. Do not publish the unauthenticated control UI to the public Internet. Use an SSH tunnel, restrictive Huawei ECS security group, or a private VPN. The k6 runner has NO arbitrary Internet target feature: the five demonstration profiles target only the protected internal web app. A sixth, instructor-configured profile can send a bounded HTTP GET load to a literal RFC1918 private address inside the VPC. This is a teaching system, **not production security middleware**.

## 1. Fast classroom installation — Ubuntu 24.04 on Huawei ECS

Recommended baseline: 4 vCPU, 8 GiB RAM, 30 GiB free disk, outbound Internet for first-time Docker image pulls, Ubuntu 24.04 amd64. On smaller ECS, use only the core first and scale up gradually. All other stack components live in the ZIP; the ZIP does **not** include pre-downloaded Docker images.

Unzip the supplied archive, enter the folder, and install Docker Compose v2 if it isn't present:

```bash
unzip CloudShield_Huawei_KooLab.zip
cd CloudShield_Huawei_KooLab
sudo bash scripts/install-docker-ubuntu.sh
sudo bash scripts/start.sh
```

If Docker/Compose are already installed, skip the install step. On subsequent boots use `sudo bash scripts/start.sh`. The installer supports Ubuntu 22.04/24.04 and expects normal apt repositories.

View container status and run a smoke test:

```bash
sudo bash scripts/status.sh
bash scripts/smoke-test.sh
```

The web UI is initially reachable **on the ECS itself** at `http://127.0.0.1:8080/`. On your Windows/laptop terminal, establish a secure tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 ubuntu@YOUR_ECS_IP
```

Open `http://localhost:8080/` for CloudShield, `http://localhost:3000/` for Grafana. Replace `ubuntu` with the actual SSH username and retain your usual SSH key options (`-i ...`) if required. Huawei security group needs SSH (22) only from your trusted workstation; **do not open 8080/3000/9090 to the Internet**. On private KOOLab ECS without a public IP, use an authorized bastion host or the lab-provided private access path.

### Stress-test another authorized ECS inside the same VPC

For the scenario where the application under test is on a **different Huawei ECS**, the instructor can explicitly configure **one fixed HTTP GET URL** in `.env` before starting or restarting the stack:

```bash
# Edit .env and add an APPROVED private address (no hostname, public IP or query string):
VPC_TARGET_URL=http://10.0.1.25:8080/health
# Then restart the labapp to read it:
sudo docker compose up -d --force-recreate labapp
```

Use the **Private VPC HTTP GET** profile in the dashboard. It is limited to **20 VUs and 120 seconds**, cannot be redirected by the student to another host, and does not include login attacks or file uploads against that external ECS. Disable redirects in the k6 script. Ensure the target ECS security group accepts connections **only from the test ECS private IP**, and that you are authorized to load-test the service. For Kubernetes, set `VPC_TARGET_URL` on deployment `labapp` in the `cloudshield` namespace and restart it. The WAF and bans in this package protect the **built-in demonstration app**, not the separate ECS target.

### Optional heavy antivirus engine

ClamAV can consume several gigabytes of RAM loading signatures. On a 4-vCPU/8-GB ECS, **do not enable it during maximum-load stress tests**. Enable it for a separate session:

```bash
sudo docker compose --profile antivirus up -d clamav
sudo docker compose logs -f --tail 30 clamav
```

Wait for signature database download and `clamd` availability. In CloudShield → Security Engines → Antivirus upload, upload an ordinary text file and view an actual scan verdict. For a harmless malware-positive demonstration use the official [EICAR antivirus test file](https://www.eicar.org/download-anti-malware-testfile/). Do not use live malware. Results come from the real ClamAV daemon; if unavailable, the API clearly returns HTTP 503, not a fabricated result.

### Optional Docker-network throughput practical (iperf3)

Use **iperf3** to measure TCP throughput between two containers on this ECS's Docker bridge. This does **not** measure Huawei VPC cross-ECS network performance:

```bash
sudo docker compose --profile network up -d --build iperf3-server
sudo docker compose --profile network run --rm --no-deps iperf3-server -c iperf3-server -t 10 -P 2
```

For a real inter-ECS VPC test, deploy an iperf3 server on ECS A and connect from ECS B over their private VPC IPs with appropriately restricted security-group rules. Keep all bandwidth tests authorized and rate-limited.

### Real Suricata IDS PCAP exercise

```bash
sudo bash scripts/test-suricata.sh
```

This runs the **real Suricata engine** against a synthetic PCAP containing a harmless marker (`LAB_TEST_MARKER`). It checks a real local IDS signature, writes `eve.json` into the shared data volume, and displays alerts in the dashboard. **It is an offline PCAP practical, not an inline IDS/IPS on the VPC**. Inline packet inspection of all ECS traffic requires a separate packet-mirroring/traffic-capture design and cannot be achieved by merely installing Suricata inside one container.

## 2. First student experiment (about 5 actions)

1. Open Dashboard, check status and active ban count. Set **Auto-ban duration = 1 minute**, then save.
2. In Traffic Simulation Center select **Failed logins**, 1 virtual user, 10 seconds, and click Start.
3. Open Security Events: failed login and `ip_banned` events should appear. Test traffic from the k6 source will receive 429 responses after five failures.
4. Observe the offending private source IP in Temporary IP Bans, with a real expiry countdown. You can click Unblock to verify instant lab-only release.
5. Repeat with a 1-minute ban and wait for its TTL to expire; requests from that source resume. Repeat the Normal / Spike / File transfer / WAF-signature profiles (normal may remain blocked until the previous ban is removed).

**Expected HTTP codes:** 200 = normal; 401 = wrong demo password; 403 = WAF/CrowdSec block; 429 = built-in timed Lab Guard block. 422 = invalid input or ClamAV detected known signature; 503 = requested optional engine unavailable.

### Inspect real CrowdSec detections & bouncer decisions

```bash
sudo docker compose exec crowdsec cscli metrics
sudo docker compose exec crowdsec cscli decisions list
sudo docker compose logs --tail 50 crowdsec
```

For a deterministic CrowdSec decision integration test, choose a **private lab IP** (shown for the test client in the dashboard) and use:

```bash
sudo docker compose exec crowdsec cscli decisions add --ip 172.20.10.25 --duration 4h --reason "Instructor lab validation"
sudo docker compose exec crowdsec cscli decisions list
```

Use the actual test client IP, not the sample address. The CloudShield bouncer checks CrowdSec LAPI decisions on requests to `/target/*` using a generated bouncer API key. To remove the CrowdSec decision:

```bash
sudo docker compose exec crowdsec cscli decisions delete --ip 172.20.10.25
```

**Important distinction:** Lab Guard's 5-failed-login detector and timed bans are implemented by the CloudShield app and stored in SQLite. CrowdSec is a separate **real open-source security engine** processing backend access logs, and its decisions are independently enforced by the bouncer. CrowdSec's built-in scenarios depend on its configured collections and real matching log patterns; not every five-login lab exercise necessarily creates a CrowdSec decision. Also, WAF-denied requests do not reach the backend log source by default. Do not confuse the two ban sources.

## 3. Engines and deployment modes

| Mode | Components | How to start |
|---|---|---|
| Core | CloudShield UI, local threat rules, genuine k6 runner, protected sample web API, Coraza/OWASP CRS WAF | `sudo docker compose up -d --build` |
| Classroom default | Core + CrowdSec and bouncer + Prometheus + provisioned Grafana | `sudo bash scripts/start.sh` |
| Antivirus | ClamAV clamd, signatures | `sudo docker compose --profile antivirus up -d clamav` |
| IDS PCAP lab | Suricata 8.x + local IDS signature + synthetic packet | `sudo bash scripts/test-suricata.sh` |
| Network throughput | iperf3 server/client on Docker bridge | `sudo docker compose --profile network up -d --build iperf3-server` |
| Kubernetes | K3s manifests for core, CrowdSec, monitoring; optional ClamAV and IDS Job | `sudo bash scripts/k3s-deploy.sh` |

Prometheus is configured to scrape `/metrics` every 5 seconds. Grafana includes four real panels: rate, status codes, blocks and p95 handler latency. The CloudShield UI displays real audit events, job states, bans and live status. k6 exports per-run JSON summaries to the persistent volume; inspect using `/api/runs/{id}`.

## 4. Load-test safeguards and meaningful interpretation

- Built-in 6 profiles: **Normal**, **Spike**, **Failed logins**, **4-MiB transfer**, **WAF signature**, plus **instructor-approved Private VPC HTTP GET**. These are executed by a genuine k6 binary embedded in the app image.
- User-configurable bounded load: default up to **40 virtual users**, **180 seconds** on the demo app; **20 VUs/120 seconds on an approved private VPC target**; one concurrent k6 job, with an Emergency Stop. Values are configurable in `.env` up to a hard ceiling of 100 VUs / 300s for this version. The demo traffic target is immutable; the optional second-ECS target is configured by the instructor, not by students.
- A virtual user is not a guaranteed simultaneous active connection; request rates and observed data transfer depend on response times and k6 scripts.
- A single ECS tests application behavior and host bottlenecks but **does not benchmark Huawei VPC inter-ECS throughput**. Use a second ECS with iperf3 for that separate course topic.
- No UDP floods, SYN floods, spoofing, arbitrary target URLs, shell execution, exploitation of real systems, or external DDoS capability are provided.
- Suricata is PCAP-only here, no host network privileges. ClamAV is on-demand for file uploads, not universal endpoint protection. CrowdSec bouncer works only for the demo application paths, not host-wide Linux firewall services.

## 5. Kubernetes (single-node K3s)

**Do not start the Compose stack and K3s stack together on the same 8-GB machine**; they compete for resources. Stop Compose first:

```bash
sudo bash scripts/stop.sh
# Install K3s separately according to https://docs.k3s.io/quick-start
sudo bash scripts/k3s-deploy.sh
sudo k3s kubectl -n cloudshield get pods
sudo k3s kubectl -n cloudshield port-forward --address 127.0.0.1 svc/waf 8080:8080
```

The deploy script builds a custom application image using Docker, imports it into K3s's containerd, generates a Kubernetes Secret for the bouncer, supplies monitoring ConfigMaps, and applies the core / CrowdSec / monitoring Deployments. Use an SSH port-forward to the ECS as in section 1. No public NodePort is created.

Optional services:

```bash
sudo k3s kubectl apply -f k8s/30-antivirus.yaml
sudo bash scripts/k3s-suricata.sh
sudo k3s kubectl -n cloudshield port-forward --address 127.0.0.1 svc/grafana 3000:3000
```

**K3s limitations:** tested design is **one node with one application replica**. The SQLite persistent volume and CrowdSec log-reading pattern are not suitable for cross-node scaling or distributed production. CrowdSec K3s pod stores local detections in ephemeral storage (restart resets those decisions). A production architecture should use external database, shared object storage, hardened identity and a cloud-native network capture architecture.

## 6. Operational commands

```bash
sudo bash scripts/status.sh
sudo docker compose logs -f --tail 100 labapp waf crowdsec
sudo bash scripts/stop.sh
# Reset only if you intentionally want to erase lab bans, runs and saved dashboard data:
sudo docker compose --profile security --profile monitoring --profile antivirus --profile network down --volumes
```

The CLI scripts generate a `.env` file containing random secrets; it is intentionally excluded from the ZIP. Do not post `.env` in screenshots or distribute it to students after deployment.

## 7. Troubleshooting

- **Browser cannot connect**: CloudShield binds 127.0.0.1. Start SSH `-L` forwarding; check ECS `curl -I http://127.0.0.1:8080/`, Docker logs and SSH reachability.
- **WAF 502 / no service**: application healthcheck failed; inspect `sudo docker compose ps` and `logs labapp`.
- **ClamAV 503**: antivirus profile isn't running or signature initialization is incomplete; check `logs clamav` and available RAM.
- **No CrowdSec bans**: use `cscli decisions list`; remember built-in Lab Guard bans are a different engine. Confirm collection installation, file acquisition, and bouncer key.
- **Suricata no alerts**: view Suricata command logs; inspect `eve.json` after `scripts/test-suricata.sh`. Only PCAP packets are analyzed.
- **Old ban still active after local Unblock**: a separate CrowdSec decision may still apply; remove it with `cscli` when authorized.
- **Start hangs at image download**: Docker Hub/GHCR network egress might be blocked in KOOLab; Internet is needed for first deployment. There are no Docker image binaries in the ZIP.
- **Insufficient memory**: do not start ClamAV at the same time as high-load tests on an 8-GB ECS. Try 8 vCPU/16+ GiB for all engines concurrently.
- **CrowdSec image/collection incompatibility**: upstream image and rules update over time; pin image digests after validating your specific lab deployment.

## 8. Evidence & verification limitations

The source and Python behavior tests are included. The archive was validated via Python syntax checking, YAML parsing, and `pytest`. **A full live `docker compose up` / K3s cluster acceptance test could not be executed in the artifact-building environment because Docker and a Kubernetes cluster were unavailable.** Therefore first-run image pulls, upstream configuration compatibility and image runtime startup must be smoke-tested on the actual ECS. Do not represent this ZIP as certified error-free or production-ready without that step.

See `STUDENT_LABS.md` for a classroom checklist, `ACCEPTANCE.md` for operational gates, and `tests/` for source tests.

## 9. NEW: Protected Demo Store (version 1.1)

This build includes a **real working demonstration storefront** served from the same protected `/target/*` routes. Its catalog, search, cart, login demo, deliberately slow request, 1-MiB download and synthetic checkout are designed for CloudShield performance/security exercises. No real personal data, inventory or payments are used.

1. Deploy as described in Section 1: `sudo bash scripts/start.sh`.
2. SSH-tunnel port `8080` and visit `http://localhost:8080/target/store` for the storefront and `http://localhost:8080/` for CloudShield dashboard.
3. Explore storefront manually, search for `cloud`, add a product to cart and click **Complete dummy checkout**.
4. In CloudShield select **Demo Store journey**, **5 VUs**, **30 s**, then click **Start k6 Test**. It issues real HTTP requests to catalog, search, product detail, and synthetic checkout through the same Coraza WAF.
5. Observe CloudShield **Security Events**, **Run Results**, and Grafana (if the monitoring profile started).
6. For timed block: set auto-ban to **1 minute**, select **Failed logins** with **1 VU** for **10 seconds**. Its synthetic client should become blocked from all `/target/*` routes. Verify the ban in **Temporary IP Bans**. After one minute it expires. If you test failed logins in your own browser instead, it may block your browser's IP from the storefront until expiration.
7. For WAF enforcement select **WAF signature** and observe 403 codes. The test outcome depends on the active WAF ruleset version; view WAF logs if a rule doesn't fire.

A private VPC target on **another ECS is different**: the `vpc_get` profile only sends bounded GET load to `VPC_TARGET_URL`; it does not put that app behind CloudShield's WAF or timed ban mechanism. For full security tests, place that app behind its own WAF and remediation proxy or extend the architecture with a controlled reverse proxy to the ECS. Do not assume CloudShield protects arbitrary workloads elsewhere in the VPC.

To see storefront hits directly from the ECS:

```bash
curl -sS http://127.0.0.1:8080/target/store/api/products
curl -sS 'http://127.0.0.1:8080/target/store/api/search?q=cloud'
sudo docker compose logs --tail 50 waf labapp
```

The storefront is a teaching demo, not a production commerce platform. Synthetic checkout writes rows to the same local SQLite database as CloudShield; it is not suitable for distributed write-heavy performance benchmarks.
