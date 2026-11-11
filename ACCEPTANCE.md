# ECS Acceptance / Pre-class Checklist

This document separates **source-level tests passed** from **live ECS checks still required**.

## Automated source verification

From the repository on a development PC with Python, pytest, FastAPI, httpx, python-multipart, prometheus-client:

```bash
python -m pytest -q tests/test_app.py
python -m compileall -q app scripts
```

## Live ECS acceptance (in instructor environment)

- [ ] Docker Compose v2 is installed, `docker compose config` succeeds.
- [ ] `sudo bash scripts/start.sh` completes, all core/monitoring/security containers running.
- [ ] `bash scripts/smoke-test.sh` returns 200 checks and WAF 403 for benign probe.
- [ ] Normal k6 run finishes and appears in `/api/runs` with JSON summary.
- [ ] Failed-login k6 run produces a real timed ban; source IP is private.
- [ ] Requests from banned source receive HTTP 429; test source can be manually unbanned.
- [ ] One-minute ban expires and next test from source is allowed.
- [ ] CrowdSec `cscli decisions add` blocks selected source through the real bouncer (403).
- [ ] CrowdSec decision deletion restores access after 5-second local cache.
- [ ] Prometheus scrape target is UP and Grafana charts populate.
- [ ] `sudo bash scripts/test-suricata.sh` creates a detectable alert in EVE JSON.
- [ ] `docker compose --profile antivirus up -d clamav` initializes signatures successfully (optional).
- [ ] Normal text file scans clean; EICAR test file is rejected (optional).
- [ ] Load emergency stop interrupts a long k6 run without killing the main app.
- [ ] SSH tunnel works without exposing unauthenticated ports publicly.
- [ ] ECS RAM/CPU remain within budget during tests; no OOMKilled / memory pressure.
- [ ] Optional K3s: image import, pod readiness, port-forward and k6 exercise succeed.

## Claim levels

- **Confirmed by builder:** Python source compiles, YAML files parse, seven isolated app behavior tests pass, archive hashes/contents verify.
- **Not confirmed by builder:** live pulled images, Docker startup networking, third-party WAF/CrowdSec rule acquisition, K3s cluster runtime, ClamAV signature updates, cross-ECS performance metrics.

An instructor must run the live ECS checklist before distributing this as an "error-free" classroom package.
