"""CloudShield KooLab: bounded, local-only lab orchestrator.

This intentionally does not offer arbitrary-target load generation, remote shell,
packet flooding, Docker socket access, or public firewall rule changes.
"""
import ipaddress
import json
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest
from starlette.responses import Response

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("LAB_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "lab.sqlite3"
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
(LOG_DIR / "nginx-access.log").touch(exist_ok=True)
LAB_TARGET = os.getenv("LAB_TARGET_URL", "http://waf:8080")
# Internal DNS target ONLY. Do not let HTTP users substitute a host or URL.
if LAB_TARGET != "http://waf:8080" and os.getenv("LAB_ALLOW_LOCAL_TEST_TARGET") != "1":
    raise RuntimeError("LAB_TARGET_URL must be http://waf:8080")
CROWDSEC_URL = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
CROWDSEC_KEY = os.getenv("CROWDSEC_BOUNCER_KEY", "")
K6_PATH = os.getenv("K6_PATH", "/usr/local/bin/k6")
K6_SCRIPTS = Path(os.getenv("K6_SCRIPTS", "/app/k6"))
MAX_VUS = max(1, min(100, int(os.getenv("MAX_VUS", "40"))))
MAX_SECONDS = max(5, min(300, int(os.getenv("MAX_SECONDS", "180"))))
MAX_MB = 16
RUNNERS = {"normal": "normal.js", "store": "store.js", "spike": "spike.js", "auth": "auth.js", "transfer": "transfer.js", "waf": "waf.js", "vpc_get": "vpc_get.js"}
VPC_TARGET_URL = os.getenv("VPC_TARGET_URL", "").strip()
if VPC_TARGET_URL:
    parsed = urlsplit(VPC_TARGET_URL)
    try:
        target_ip = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise RuntimeError("VPC_TARGET_URL must use a literal RFC1918 private IP address")
    rfc1918 = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.fragment or parsed.query or not any(target_ip in r for r in rfc1918):
        raise RuntimeError("VPC_TARGET_URL must be http(s) to an RFC1918 private IPv4 address (path allowed; no query/credentials)")


app = FastAPI(title="CloudShield KooLab", version="1.0.0", docs_url=None, redoc_url=None)
REGISTRY = CollectorRegistry()
REQS = Counter("cloudshield_requests_total", "Target requests", ["method", "path", "status"], registry=REGISTRY)
BLOCKED = Counter("cloudshield_blocks_total", "Blocked test requests", ["engine"], registry=REGISTRY)
DURATION = Histogram("cloudshield_request_seconds", "Target handler duration", buckets=(.005,.01,.025,.05,.1,.25,.5,1,2,5,10), registry=REGISTRY)
lock = threading.RLock()
process = None
active_run = None
bouncer_cache = {}


@contextmanager
def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA busy_timeout=15000")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS bans (
            ip TEXT PRIMARY KEY, source TEXT NOT NULL, reason TEXT NOT NULL,
            created REAL NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS failed_login (ip TEXT NOT NULL, at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_fail_time ON failed_login(at);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
            event TEXT NOT NULL, ip TEXT, info TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS configs (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS store_orders (
            order_id TEXT PRIMARY KEY, created REAL NOT NULL, total_cents INTEGER NOT NULL, items_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, profile TEXT NOT NULL, vus INTEGER NOT NULL,
            seconds INTEGER NOT NULL, started REAL NOT NULL, ended REAL,
            status TEXT NOT NULL, exit_code INTEGER, summary TEXT, log TEXT);
        INSERT OR IGNORE INTO configs(key, value) VALUES ('ban_minutes','240');
        """)


init_db()


def stamp(t=None):
    return datetime.fromtimestamp(t or time.time(), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def event(kind, ip="", info=""):
    with connect() as db:
        db.execute("INSERT INTO events(at,event,ip,info) VALUES (?,?,?,?)", (time.time(), kind, ip, str(info)[:400]))
        db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)")


def expire_bans():
    now = time.time()
    with connect() as db:
        old = db.execute("SELECT ip FROM bans WHERE expires<=?", (now,)).fetchall()
        db.execute("DELETE FROM bans WHERE expires<=?", (now,))
    for item in old:
        event("unblocked_expiry", item["ip"], "TTL expired; access restored")


def active_ban(ip):
    expire_bans()
    with connect() as db:
        row = db.execute("SELECT * FROM bans WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None


def set_ban(ip, minutes, reason, source="lab_guard"):
    try:
        value = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "Invalid IP address")
    if not (value.is_private or value.is_loopback):
        raise HTTPException(422, "Lab can only ban private or loopback addresses")
    if not 1 <= minutes <= 1440:
        raise HTTPException(422, "Ban duration must be 1–1440 minutes")
    now = time.time()
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO bans(ip,source,reason,created,expires) VALUES(?,?,?,?,?)",
                   (str(value), source, reason[:140], now, now + minutes*60))
    event("ip_banned", str(value), f"{source}: {reason}; {minutes} minutes")


def get_minutes():
    with connect() as db:
        item = db.execute("SELECT value FROM configs WHERE key='ban_minutes'").fetchone()
    return int(item[0]) if item else 240


def client_ip(request: Request):
    # Internal WAF-to-app topology is an explicit trust boundary. The app is
    # never published directly; do not reuse this logic for an Internet proxy.
    peer = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        try:
            if ipaddress.ip_address(peer).is_private:
                raw = forwarded.split(",")[0].strip()
                return str(ipaddress.ip_address(raw))
        except ValueError:
            pass
    return peer


def check_crowdsec(ip):
    if not CROWDSEC_KEY:
        return False
    now = time.time()
    cached = bouncer_cache.get(ip)
    if cached and now - cached[0] < 5:
        return cached[1]
    try:
        resp = httpx.get(f"{CROWDSEC_URL}/v1/decisions", params={"ip": ip},
                         headers={"X-Api-Key": CROWDSEC_KEY}, timeout=0.55)
        blocked = resp.status_code == 200 and any(
            x.get("type") == "ban" for x in (resp.json() or []) if isinstance(x, dict)
        )
        bouncer_cache[ip] = (now, blocked)
        return blocked
    except (httpx.HTTPError, ValueError, TypeError):
        return False


def log_access(ip, method, path, code, user_agent=""):
    safe_path = path.replace('"', '').replace("\n", '')[:180]
    ua = user_agent.replace('"', '').replace("\n", '')[:120]
    line = f'{ip} - - [{datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {safe_path} HTTP/1.1" {code} 0 "-" "{ua}"\n'
    with lock:
        with (LOG_DIR / "nginx-access.log").open("a", encoding="utf-8") as f:
            f.write(line)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Enforcement is scoped to the built-in demonstration application.
    if not request.url.path.startswith("/target/"):
        return await call_next(request)
    start = time.monotonic()
    ip = client_ip(request)
    state = active_ban(ip)
    if state:
        result = JSONResponse({"blocked": True, "engine": "Lab Guard", "ip": ip,
                               "reason": state["reason"], "expires": state["expires"]}, status_code=429)
        BLOCKED.labels(engine="lab_guard").inc()
    elif check_crowdsec(ip):
        result = JSONResponse({"blocked": True, "engine": "CrowdSec bouncer", "ip": ip}, status_code=403)
        BLOCKED.labels(engine="crowdsec").inc()
    else:
        result = await call_next(request)
    DURATION.observe(time.monotonic() - start)
    path = request.url.path
    REQS.labels(method=request.method, path=path, status=str(result.status_code)).inc()
    log_access(ip, request.method, path, result.status_code, request.headers.get("user-agent", ""))
    return result


@app.get("/")
def ui():
    return FileResponse(APP_DIR / "static" / "index.html")


@app.get("/static/{name}")
def static(name: str):
    if name not in {"app.js", "style.css"}:
        raise HTTPException(404)
    return FileResponse(APP_DIR / "static" / name)


@app.get("/healthz")
def health():
    return {"status": "ok", "project": "CloudShield KooLab", "version": "1.0.0"}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/target/health")
def target_health():
    return {"ok": True, "service": "protected-demonstration-app"}


@app.get("/target/data")
def target_data():
    return {"message": "Protected sample workload", "items": [{"id": i, "value": i*7} for i in range(8)]}


@app.get("/target/echo")
def target_echo(q: str = "sample"):
    return {"query": q[:160], "note": "Display-only echo; never interpreted as SQL or commands"}


@app.post("/target/login")
async def target_login(request: Request):
    # Intentionally fake authentication, no real credentials or accounts.
    body = await request.json()
    ip = client_ip(request)
    if body.get("username") == "student" and body.get("password") == "classroom-demo":
        return {"ok": True, "message": "Demo credentials accepted"}
    now = time.time()
    with connect() as db:
        db.execute("DELETE FROM failed_login WHERE at < ?", (now - 90,))
        db.execute("INSERT INTO failed_login(ip,at) VALUES (?,?)", (ip, now))
        count = db.execute("SELECT COUNT(*) FROM failed_login WHERE ip=?", (ip,)).fetchone()[0]
        if count >= 5:
            db.execute("DELETE FROM failed_login WHERE ip=?", (ip,))
    event("login_failed", ip, "Incorrect demonstration credential")
    if count >= 5:
        set_ban(ip, get_minutes(), "5 failed demo logins within 90 seconds")
    return JSONResponse({"ok": False, "attempts_in_window": count,
                         "message": "Demo login failed"}, status_code=401)


@app.get("/target/download")
def target_download(mb: int = 1):
    if not 1 <= mb <= MAX_MB:
        raise HTTPException(422, f"mb must be 1–{MAX_MB}")
    def blocks():
        chunk = b"CloudShield-Lab-Data\n" * 3276  # ~65 KB
        todo = mb * 1048576
        while todo:
            data = chunk[:min(len(chunk), todo)]
            todo -= len(data)
            yield data
    return StreamingResponse(blocks(), media_type="application/octet-stream",
                             headers={"Content-Disposition": 'attachment; filename="lab-data.bin"'})


def clam_scan(raw: bytes):
    host = os.getenv("CLAMAV_HOST", "clamav")
    try:
        with socket.create_connection((host, 3310), timeout=3) as s:
            s.settimeout(12)
            s.sendall(b"zINSTREAM\0")
            for start in range(0, len(raw), 32768):
                chunk = raw[start:start + 32768]
                s.sendall(struct.pack("!I", len(chunk)) + chunk)
            s.sendall(struct.pack("!I", 0))
            result = s.recv(2048).decode("utf-8", errors="replace").strip("\x00\n")
            return result
    except (OSError, TimeoutError):
        raise HTTPException(503, "ClamAV unavailable; start the antivirus profile and allow signatures to load")


@app.post("/target/upload")
async def target_upload(request: Request, file: UploadFile = File(...)):
    # Stream capped input; reject oversized files instead of loading arbitrary blobs.
    raw = await file.read(1_048_577)
    if len(raw) > 1_048_576:
        raise HTTPException(413, "Maximum 1 MiB per lab scan")
    result = clam_scan(raw)
    ip = client_ip(request)
    if "FOUND" in result:
        event("malware_test_detected", ip, result)
        return JSONResponse({"safe": False, "scan": result}, status_code=422)
    if "OK" not in result:
        raise HTTPException(503, "ClamAV returned a scan error: " + result[:120])
    event("clean_file", ip, "ClamAV scan clean")
    return {"safe": True, "scan": result, "bytes": len(raw)}



# Demo Store: intentionally synthetic products and orders, with NO payment, personal data,
# external checkout, or real stock inventory. All paths are behind /target/ protection.
STORE_PRODUCTS = [
    {"id": 101, "name": "Cloud Lab Hoodie", "category": "Apparel", "price_cents": 3500, "emoji": "🧥", "inventory": 10000},
    {"id": 102, "name": "Network Engineer Mug", "category": "Accessories", "price_cents": 1250, "emoji": "☕", "inventory": 10000},
    {"id": 103, "name": "KooLab Backpack", "category": "Accessories", "price_cents": 4800, "emoji": "🎒", "inventory": 10000},
    {"id": 104, "name": "Cyber Defense Notebook", "category": "Stationery", "price_cents": 850, "emoji": "📘", "inventory": 10000},
    {"id": 105, "name": "DevOps Water Bottle", "category": "Accessories", "price_cents": 2200, "emoji": "🧴", "inventory": 10000},
    {"id": 106, "name": "Security Lab T-Shirt", "category": "Apparel", "price_cents": 2900, "emoji": "👕", "inventory": 10000},
]
STORE_BY_ID = {p["id"]: p for p in STORE_PRODUCTS}


@app.get("/target/store")
@app.get("/target/store/")
def store_ui():
    return FileResponse(APP_DIR / "static" / "store.html")


@app.get("/target/store/assets/{name}")
def store_asset(name: str):
    if name not in ("store.css", "store.js"):
        raise HTTPException(404, "Unknown demo asset")
    return FileResponse(APP_DIR / "static" / name)


@app.get("/target/store/api/products")
def store_products(category: str = ""):
    value = category.lower()[:40]
    items = [p for p in STORE_PRODUCTS if not value or p["category"].lower() == value]
    return {"items": items, "total": len(items), "note": "Synthetic training catalog"}


@app.get("/target/store/api/search")
def store_search(q: str = ""):
    value = q.strip().lower()[:80]
    items = [p for p in STORE_PRODUCTS if value in p["name"].lower() or value in p["category"].lower()]
    return {"items": items, "total": len(items), "query": q[:80]}


@app.get("/target/store/api/products/{product_id}")
def store_product(product_id: int):
    product = STORE_BY_ID.get(product_id)
    if product is None:
        raise HTTPException(404, "Product not found")
    return product


class StoreCartItem(BaseModel):
    product_id: int = Field(ge=1, le=99999)
    quantity: int = Field(ge=1, le=10)


class StoreCheckout(BaseModel):
    items: list[StoreCartItem] = Field(min_length=1, max_length=8)


@app.post("/target/store/api/checkout")
def store_checkout(body: StoreCheckout):
    normalized = {}
    for entry in body.items:
        if entry.product_id not in STORE_BY_ID:
            raise HTTPException(422, f"Unknown synthetic product {entry.product_id}")
        normalized[entry.product_id] = normalized.get(entry.product_id, 0) + entry.quantity
    if any(n > 10 for n in normalized.values()):
        raise HTTPException(422, "Maximum 10 of each item per demo order")
    order_items = [{"product_id": pid, "quantity": qty, "unit_price_cents": STORE_BY_ID[pid]["price_cents"]} for pid, qty in normalized.items()]
    total = sum(entry["quantity"] * entry["unit_price_cents"] for entry in order_items)
    order_id = "LAB-" + uuid.uuid4().hex[:10].upper()
    with connect() as db:
        db.execute("INSERT INTO store_orders(order_id,created,total_cents,items_json) VALUES(?,?,?,?)",
                   (order_id, time.time(), total, json.dumps(order_items)))
    event("store_order", "", f"Synthetic order {order_id} for {total/100:.2f} demo dollars")
    return {"ok": True, "order_id": order_id, "total_cents": total, "items": order_items, "message": "Synthetic checkout complete — no payment collected"}


@app.get("/target/store/api/orders/{order_id}")
def store_order(order_id: str):
    if not re.fullmatch(r"LAB-[A-F0-9]{10}", order_id):
        raise HTTPException(404, "Demo order not found")
    with connect() as db:
        row = db.execute("SELECT * FROM store_orders WHERE order_id=?", (order_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Demo order not found")
    return {"order_id": row["order_id"], "created": row["created"],
            "total_cents": row["total_cents"], "items": json.loads(row["items_json"])}


@app.get("/target/store/api/slow")
def store_slow(ms: int = 100):
    if not 1 <= ms <= 300:
        raise HTTPException(422, "ms must be 1–300")
    time.sleep(ms / 1000)
    return {"ok": True, "simulated_database_ms": ms, "note": "Bounded latency demo; not actual database profiling"}

@app.get("/api/status")
def status():
    expire_bans()
    with connect() as db:
        bans = db.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
        recent = db.execute("SELECT COUNT(*) FROM events WHERE at>?", (time.time()-3600,)).fetchone()[0]
    with lock:
        running = active_run is not None and process is not None and process.poll() is None
    return {"project": "CloudShield KooLab", "bans": bans, "events_last_hour": recent,
            "running": running, "max_vus": MAX_VUS, "max_seconds": MAX_SECONDS,
            "ban_minutes": get_minutes(), "crowdsec_configured": bool(CROWDSEC_KEY),
            "clamav": os.getenv("CLAMAV_HOST", "clamav"), "vpc_target_configured": bool(VPC_TARGET_URL), "time": time.time()}


@app.get("/api/bans")
def bans():
    expire_bans()
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM bans ORDER BY expires DESC")]


class BanReq(BaseModel):
    ip: str
    minutes: int = Field(default=60, ge=1, le=1440)
    reason: str = Field(default="Instructor demonstration", max_length=140)


@app.post("/api/bans")
def ban_manual(body: BanReq):
    set_ban(body.ip, body.minutes, body.reason, "manual")
    return {"ok": True}


@app.delete("/api/bans/{ip}")
def unban(ip: str):
    with connect() as db:
        affected = db.execute("DELETE FROM bans WHERE ip=?", (ip,)).rowcount
    if affected:
        event("unblocked_manual", ip, "Instructor removed lab ban")
    return {"ok": bool(affected), "note": "CrowdSec decisions, if any, require separate removal via cscli"}


class SettingsReq(BaseModel):
    ban_minutes: int = Field(ge=1, le=1440)


@app.post("/api/settings")
def settings(body: SettingsReq):
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO configs(key,value) VALUES('ban_minutes',?)", (str(body.ban_minutes),))
    event("settings_changed", "", f"Automatic lab bans now {body.ban_minutes} minutes")
    return {"ok": True, "ban_minutes": body.ban_minutes}


@app.get("/api/events")
def events():
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 80")]


class RunReq(BaseModel):
    profile: str
    vus: int = Field(default=5, ge=1, le=100)
    seconds: int = Field(default=30, ge=5, le=300)


def finish_run(run_id, proc):
    try:
        stdout, _ = proc.communicate(timeout=MAX_SECONDS + 40)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        stdout, _ = proc.communicate()
        code = 124
    summary_path = DATA_DIR / "results" / f"{run_id}.json"
    summary = None
    try:
        if summary_path.exists():
            summary = json.loads(summary_path.read_text())
    except (ValueError, OSError):
        pass
    status_text = "completed" if code == 0 else "stopped" if code in (-15, 143) else "failed"
    with connect() as db:
        db.execute("UPDATE runs SET ended=?, status=?, exit_code=?, summary=?, log=? WHERE id=?",
                   (time.time(), status_text, code, json.dumps(summary) if summary else None, stdout[-14000:], run_id))
    event("test_finished", "", f"{run_id} {status_text} (exit {code})")
    global active_run, process
    with lock:
        if active_run == run_id:
            active_run = None
            process = None


@app.post("/api/runs")
def start_run(body: RunReq):
    if body.profile not in RUNNERS:
        raise HTTPException(422, "Unknown profile")
    if body.vus > MAX_VUS or body.seconds > MAX_SECONDS:
        raise HTTPException(422, f"Limit: {MAX_VUS} VUs and {MAX_SECONDS} seconds")
    if body.profile == "vpc_get":
        if not VPC_TARGET_URL:
            raise HTTPException(422, "Instructor has not configured VPC_TARGET_URL in .env")
        if body.vus > 20 or body.seconds > 120:
            raise HTTPException(422, "Private VPC target limit: 20 VUs and 120 seconds")
    script = K6_SCRIPTS / RUNNERS[body.profile]
    if not script.is_file() or not Path(K6_PATH).is_file():
        raise HTTPException(503, "k6 binary or profile script is missing")
    global active_run, process
    with lock:
        if process is not None and process.poll() is None:
            raise HTTPException(409, "Another test is already running")
        run_id = uuid.uuid4().hex[:12]
        (DATA_DIR / "results").mkdir(exist_ok=True)
        effective_target = VPC_TARGET_URL if body.profile == "vpc_get" else LAB_TARGET
        args = [K6_PATH, "run", "--no-color", "--vus", str(body.vus),
                "--duration", f"{body.seconds}s", "--summary-export",
                str(DATA_DIR / "results" / f"{run_id}.json"),
                "-e", f"BASE_URL={effective_target}", str(script)]
        try:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, start_new_session=True)
        except OSError as e:
            raise HTTPException(503, f"Could not start k6: {e}")
        process = p
        active_run = run_id
        with connect() as db:
            db.execute("INSERT INTO runs(id,profile,vus,seconds,started,status) VALUES(?,?,?,?,?,?)",
                       (run_id, body.profile, body.vus, body.seconds, time.time(), "running"))
        threading.Thread(target=finish_run, args=(run_id, p), daemon=True).start()
    event("test_started", "", f"{body.profile}, {body.vus} VUs, {body.seconds}s, id {run_id}")
    return {"ok": True, "id": run_id, "target": "instructor-approved private VPC URL" if body.profile == "vpc_get" else "internal demo app through WAF"}


@app.post("/api/runs/stop")
def stop_run():
    with lock:
        if process is None or process.poll() is not None:
            return {"ok": False, "message": "No active test"}
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    event("test_stop_requested", "", "Student pressed emergency stop")
    return {"ok": True}


@app.get("/api/runs")
def list_runs():
    with connect() as db:
        rows = db.execute("SELECT id, profile,vus,seconds,started,ended,status,exit_code FROM runs ORDER BY started DESC LIMIT 30").fetchall()
    return [dict(row) for row in rows]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    if not re.fullmatch(r"[a-f0-9]{12}", run_id):
        raise HTTPException(404)
    with connect() as db:
        row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(404)
    result = dict(row)
    if result["summary"]:
        result["summary"] = json.loads(result["summary"])
    return result


@app.get("/api/ids/alerts")
def ids_alerts():
    path = DATA_DIR / "suricata" / "eve.json"
    if not path.exists():
        return {"available": False, "alerts": [], "note": "Run scripts/test-suricata.sh to analyze a lab PCAP"}
    items = []
    for line in path.read_text(errors="replace").splitlines()[-400:]:
        try:
            o = json.loads(line)
            if o.get("event_type") == "alert":
                items.append({"timestamp": o.get("timestamp"), "src_ip": o.get("src_ip"),
                              "signature": o.get("alert", {}).get("signature")})
        except ValueError:
            continue
    return {"available": True, "alerts": items[-30:]}
