from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import subprocess
import sqlite3
import re
from pathlib import Path
from datetime import datetime, timezone

app = FastAPI(title="Pi Network Sensor")

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "known.db"
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

ARP_SCAN = "/usr/sbin/arp-scan"
BLUETOOTHCTL = "/usr/bin/bluetoothctl"
BASH = "/usr/bin/bash"
TIMEOUT = "/usr/bin/timeout"

NEW_WINDOW_SECONDS = 300

BASE_CATEGORIES = [
    "pc","laptop","nas","server","iot","mobile","tablet",
    "tv","watch","camera","printer","router","switch","ap","unknown"
]


def now():
    return datetime.now(timezone.utc)


def run(cmd, timeout=60):
    return subprocess.check_output(cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS known_devices(
        kind TEXT,
        identifier TEXT,
        alias TEXT,
        category TEXT,
        notes TEXT,
        approved INTEGER DEFAULT 1,
        UNIQUE(kind,identifier)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS observations(
        kind TEXT,
        identifier TEXT,
        first_seen TEXT,
        last_seen TEXT,
        last_ip TEXT,
        UNIQUE(kind,identifier)
    )
    """)

    con.commit()
    con.close()


init_db()


def get_known(kind):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM known_devices WHERE kind=?", (kind,))
    rows = cur.fetchall()
    con.close()
    return {r["identifier"]: dict(r) for r in rows}


def get_categories():
    con = db()
    cur = con.cursor()
    cur.execute("SELECT DISTINCT category FROM known_devices")
    rows = [r[0] for r in cur.fetchall() if r[0]]
    con.close()
    return sorted(set(BASE_CATEGORIES + rows))


def upsert_known(kind, identifier, alias, category, notes, approved):
    con = db()
    cur = con.cursor()

    cur.execute("""
    INSERT INTO known_devices(kind,identifier,alias,category,notes,approved)
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(kind,identifier)
    DO UPDATE SET alias=?,category=?,notes=?,approved=?
    """, (kind,identifier,alias,category,notes,approved,alias,category,notes,approved))

    con.commit()
    con.close()


def lan_scan():

    out = run([ARP_SCAN,"--localnet"],45)

    hosts=[]

    for l in out.splitlines():
        m=re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)",l)
        if m:
            hosts.append({
                "ip":m.group(1),
                "mac":m.group(2).lower(),
                "vendor":m.group(3)
            })

    return hosts


def ble_scan():

    cmd=f"{TIMEOUT} 10s {BLUETOOTHCTL} -- scan on"

    out=run([BASH,"-c",cmd],25)

    devices={}

    for l in out.splitlines():

        m=re.search(r"Device\s+([0-9A-F:]{17})\s+(.+)",l)

        if m:
            devices[m.group(1).lower()]=m.group(2)

    return [{"addr":k,"name":v} for k,v in devices.items()]


@app.get("/",response_class=HTMLResponse)
def root():
    return RedirectResponse("/ui")


@app.get("/ui",response_class=HTMLResponse)
def ui(request:Request):

    lan=lan_scan()

    try:
        ble=ble_scan()
    except:
        ble=[]

    known_lan=get_known("lan")
    known_ble=get_known("ble")

    return templates.TemplateResponse("ui.html",{
        "request":request,
        "lan":lan,
        "ble":ble,
        "known_lan":known_lan,
        "known_ble":known_ble,
        "categories":get_categories()
    })


@app.post("/set/lan")
def set_lan(identifier:str=Form(...),
            alias:str=Form(""),
            category:str=Form(""),
            notes:str=Form(""),
            approved:int=Form(1)):

    upsert_known("lan",identifier,alias,category,notes,approved)

    return RedirectResponse("/ui",303)


@app.post("/set/ble")
def set_ble(identifier:str=Form(...),
            alias:str=Form(""),
            category:str=Form(""),
            notes:str=Form(""),
            approved:int=Form(1)):

    upsert_known("ble",identifier,alias,category,notes,approved)

    return RedirectResponse("/ui",303)