"""Log ingestion (CSV -> logical facts) and synthetic dataset generator."""
import csv
import random
from datetime import datetime, timedelta, timezone

from .engine import Fact

FIELDS = ["timestamp", "event", "user", "src_ip", "detail"]
TS = "%Y-%m-%d %H:%M:%S"


def _epoch(s: str) -> float:
    return datetime.strptime(s, TS).replace(tzinfo=timezone.utc).timestamp()


def row_to_facts(row: dict) -> list:
    t, ev = _epoch(row["timestamp"]), row["event"].strip().upper()
    user, ip, detail = row["user"].strip(), row["src_ip"].strip(), row["detail"].strip()
    if ev == "LOGIN_FAILED":
        return [Fact("failed_login", (ip, user), t)]
    if ev == "LOGIN_SUCCESS":
        return [Fact("successful_login", (ip, user), t), Fact("login", (user,), t)]
    if ev == "CONNECTION":
        return [Fact("connection_attempt", (ip, int(detail)), t)]
    if ev == "PRIV_CHANGE":
        return [Fact("privilege_change", (user, detail), t)]
    raise ValueError(f"unknown event type: {ev}")


def load_facts(path: str) -> list:
    """Fact extractor: every log row becomes one or more logical facts."""
    with open(path, newline="") as fh:
        facts = [f for row in csv.DictReader(fh) for f in row_to_facts(row)]
    return sorted(facts, key=lambda f: f.time)


# ------------------------------------------------------------ generator ----
def generate(path: str, seed: int = 7) -> int:
    rng = random.Random(seed)
    base = datetime(2026, 10, 13, 9, 0, 0)
    rows = []

    def add(offset_s, event, user, ip, detail=""):
        rows.append({"timestamp": (base + timedelta(seconds=offset_s)).strftime(TS),
                     "event": event, "user": user, "src_ip": ip, "detail": detail})

    users = {"alice": "10.0.0.11", "bob": "10.0.0.21", "carol": "10.0.0.31",
             "dave": "10.0.0.12", "erin": "10.0.0.41"}

    # --- normal traffic -------------------------------------------------
    for u, ip in users.items():
        add(rng.randint(0, 600), "LOGIN_SUCCESS", u, ip)
        for _ in range(4):
            add(rng.randint(0, 10_000), "CONNECTION", "-", ip, rng.choice([80, 443, 22, 8080]))
    add(2400, "LOGIN_FAILED", "erin", users["erin"])           # one typo, then success
    add(2410, "LOGIN_SUCCESS", "erin", users["erin"])

    # --- benign near-misses (must NOT alert) ----------------------------
    for k in range(3):                                          # 3 failures < 5
        add(3000 + 7 * k, "LOGIN_FAILED", "bob", "10.0.0.22")
    add(3030, "LOGIN_SUCCESS", "bob", "10.0.0.22")
    for k in range(5):                                          # 5 failures but 30s apart
        add(3600 + 30 * k, "LOGIN_FAILED", "alice", "192.0.2.50")
    for k in range(15):                                         # 15 connections < 21
        add(4000 + k // 2, "CONNECTION", "-", "10.0.0.30", 1000 + k)
    add(5700, "LOGIN_SUCCESS", "alice", users["alice"])         # admin change hours later
    add(9000, "PRIV_CHANGE", "alice", users["alice"], "admin")

    # --- attack 1: brute force then compromise of carol -----------------
    atk = "198.51.100.23"
    for k in range(7):
        add(1200 + 3 * k, "LOGIN_FAILED", "carol", atk)
    add(1230, "LOGIN_SUCCESS", "carol", atk)

    # --- attack 2: brute force that never succeeds ----------------------
    for k in range(6):
        add(1800 + 2 * k, "LOGIN_FAILED", "admin", "203.0.113.9")

    # --- attack 3: port scan --------------------------------------------
    for k in range(30):
        add(2000 + k // 5, "CONNECTION", "-", "203.0.113.77", 20 + k)

    # --- attack 4: privilege escalation by dave -------------------------
    add(4800, "LOGIN_SUCCESS", "dave", users["dave"])
    add(4803, "PRIV_CHANGE", "dave", users["dave"], "admin")

    rows.sort(key=lambda r: r["timestamp"])
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return len(rows)
