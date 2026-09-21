"""
CVE Feeds — расширенный агрегатор уязвимостей.
Author: idqwixxa

Источники:
    - NVD API 2.0 (nvd.nist.gov) — все CVE
    - CISA KEV — Known Exploited Vulnerabilities
    - MITRE CVE API (cveawg.mitre.org) — официальный реестр
    - OSV (api.osv.dev) — Open Source Vulnerabilities
    - GitHub Security Advisories (GHSA)
    - ExploitDB (via cve-search или локальный кеш)
    - EPSS (FIRST.org) — Exploit Prediction Scoring System

Возможности:
    ─── База ───
    - SQLite-кеш CVE + KEV + EPSS + CVSS v3.1 + v4.0
    - Watch-list продуктов (авто-мониторинг новых CVE)
    - Timeline: распределение по месяцам/годам
    - Aggregations: top vendors, products, CWEs

    ─── Поиск ───
    - По ключевому слову / vendor / product / CWE / CVE ID
    - Фильтры: severity, score, KEV, ransomware, days, EPSS
    - Full-text search по description

    ─── Интеграция ───
    - Findings → notes для KEV + critical
    - Notify по завершении
    - HTML / JSON / CSV / Markdown экспорт
    - Google dork генератор
"""
import csv
import html as html_mod
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
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

console = Console()
log = get_logger(__name__)

CVE_DIR = REPORT_DIR / "cve_feeds"
CVE_DIR.mkdir(parents=True, exist_ok=True)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_API = "https://api.first.org/data/v1/epss"
OSV_API = "https://api.osv.dev/v1/query"

NVD_DELAY = 6.5
KEV_FILE = CVE_DIR / "cisa_kev.json"

WATCH_FILE = CVE_DIR / "watchlist.json"


# ===========================================================================
# Схема БД
# ===========================================================================

def _init_schema() -> None:
    try:
        cur = db.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                published TEXT,
                last_modified TEXT,
                description TEXT,
                cvss_score REAL,
                cvss_severity TEXT,
                cvss_vector TEXT,
                cvss_v4_score REAL,
                cvss_v4_severity TEXT,
                epss_score REAL,
                epss_percentile REAL,
                cwe TEXT,
                vendors TEXT,
                products TEXT,
                refs TEXT,
                kev INTEGER DEFAULT 0,
                kev_due TEXT,
                kev_ransomware TEXT,
                exploit_available INTEGER DEFAULT 0,
                raw TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_cves_sev   ON cves(cvss_severity);
            CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_score);
            CREATE INDEX IF NOT EXISTS idx_cves_kev   ON cves(kev);
            CREATE INDEX IF NOT EXISTS idx_cves_epss  ON cves(epss_score);
            CREATE INDEX IF NOT EXISTS idx_cves_cwe   ON cves(cwe);
            CREATE INDEX IF NOT EXISTS idx_cves_date  ON cves(published);
        """)
        db.conn.commit()
    except Exception as exc:
        log.exception("cve schema: %s", exc)


try:
    _init_schema()
except Exception:
    pass


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class CVEFinding:
    cve_id: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: CVEFinding) -> int:
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target or "cve-feed",
            severity=f.severity,
            status="open",
            tags=["cve", f.cve_id, f.severity],
            body=(f"**CVE:** {f.cve_id}\n"
                  f"**Severity:** {f.severity}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```"),
        )
    except Exception:
        return -1


# ===========================================================================
# NVD — парсинг и загрузка
# ===========================================================================

def _extract_cwe(cve: dict) -> str:
    """Извлечь CWE IDs из NVD JSON."""
    out: set[str] = set()
    try:
        for w in cve.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    out.add(val)
    except Exception:
        pass
    return ",".join(sorted(out))[:200]


def _parse_nvd_item(item: dict) -> dict | None:
    """Парсинг одного CVE из NVD API 2.0."""
    try:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description
        desc = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS v3.1 → v3.0 → v2
        cvss_score = None
        cvss_sev = ""
        cvss_vec = ""
        cvss_v4_score = None
        cvss_v4_sev = ""
        metrics = cve.get("metrics", {}) or {}

        # CVSS v4.0 (если есть)
        for key in ("cvssMetricV40",):
            arr = metrics.get(key) or []
            if arr:
                m = arr[0].get("cvssData", {}) or {}
                cvss_v4_score = m.get("baseScore")
                cvss_v4_sev = m.get("baseSeverity", "")
                break

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                m = arr[0].get("cvssData", {}) or {}
                cvss_score = m.get("baseScore")
                cvss_sev = (m.get("baseSeverity")
                            or arr[0].get("baseSeverity", ""))
                cvss_vec = m.get("vectorString", "")
                break

        # CWE
        cwe = _extract_cwe(cve)

        # Vendors / products
        vendors: set[str] = set()
        products: set[str] = set()
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for cpe in node.get("cpeMatch", []) or []:
                    crit = cpe.get("criteria", "")
                    parts = crit.split(":")
                    if len(parts) >= 5:
                        vendors.add(parts[3])
                        products.add(parts[4])

        refs = [r.get("url", "") for r in cve.get("references", []) or []]

        # Exploit available: ищем метки Exploit
        exploit_available = 0
        for r in cve.get("references", []) or []:
            tags = r.get("tags", []) or []
            if "Exploit" in tags:
                exploit_available = 1
                break

        return {
            "cve_id": cve_id,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "description": desc[:3000],
            "cvss_score": cvss_score,
            "cvss_severity": (cvss_sev or "").upper(),
            "cvss_vector": cvss_vec,
            "cvss_v4_score": cvss_v4_score,
            "cvss_v4_severity": (cvss_v4_sev or "").upper(),
            "epss_score": None,
            "epss_percentile": None,
            "cwe": cwe,
            "vendors": ",".join(sorted(vendors))[:500],
            "products": ",".join(sorted(products))[:500],
            "refs": json.dumps(refs[:20], ensure_ascii=False),
            "kev": 0,
            "kev_due": "",
            "kev_ransomware": "",
            "exploit_available": exploit_available,
            "raw": json.dumps(cve, ensure_ascii=False)[:4000],
        }
    except Exception as exc:
        log.warning("parse nvd: %s", exc)
        return None


def _save_cve(rec: dict) -> None:
    try:
        cur = db.conn.cursor()
        cur.execute("""
            INSERT INTO cves(cve_id, published, last_modified, description,
                             cvss_score, cvss_severity, cvss_vector,
                             cvss_v4_score, cvss_v4_severity,
                             epss_score, epss_percentile, cwe,
                             vendors, products, refs, kev, kev_due,
                             kev_ransomware, exploit_available, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                last_modified=excluded.last_modified,
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                cvss_severity=excluded.cvss_severity,
                cvss_vector=excluded.cvss_vector,
                cvss_v4_score=COALESCE(excluded.cvss_v4_score, cvss_v4_score),
                cvss_v4_severity=COALESCE(excluded.cvss_v4_severity,
                                          cvss_v4_severity),
                cwe=excluded.cwe,
                vendors=excluded.vendors,
                products=excluded.products,
                refs=excluded.refs,
                exploit_available=excluded.exploit_available,
                raw=excluded.raw
        """, (rec["cve_id"], rec["published"], rec["last_modified"],
              rec["description"], rec["cvss_score"], rec["cvss_severity"],
              rec["cvss_vector"], rec["cvss_v4_score"],
              rec["cvss_v4_severity"], rec["epss_score"],
              rec["epss_percentile"], rec["cwe"], rec["vendors"],
              rec["products"], rec["refs"], rec["kev"], rec["kev_due"],
              rec["kev_ransomware"], rec["exploit_available"], rec["raw"]))
        db.conn.commit()
    except Exception as exc:
        log.warning("save cve %s: %s", rec.get("cve_id"), exc)


def download_nvd(keyword: str = "", days: int | None = None,
                 max_results: int = 500, severity: str = "",
                 cvss_min: float | None = None) -> int:
    """Скачать CVE из NVD API 2.0."""
    params: dict[str, Any] = {
        "resultsPerPage": min(max_results, 2000),
    }
    if keyword:
        params["keywordSearch"] = keyword

    if days:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    # NVD: можно фильтровать по severity
    if severity and severity.upper() in (
            "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        params["cvssV3Severity"] = severity.upper()
    if cvss_min is not None:
        # NVD v3.1 metric фильтр
        params["cvssV3Metrics"] = "cvssMetricV31"
        params["cvssV3Severity"] = _score_to_severity(cvss_min)

    headers = {"User-Agent": config.USER_AGENT}

    console.print(f"[cyan]📥 NVD: keyword='{keyword or '*'}' "
                  f"days={days or 'all'} sev={severity or '*'} "
                  f"max={max_results}[/cyan]")

    saved = 0
    start_index = 0
    total = None
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(),
                  console=console) as p:
        task = p.add_task("NVD", total=max_results)
        while saved < max_results:
            paged = dict(params)
            paged["startIndex"] = start_index
            try:
                r = requests.get(NVD_API, params=paged,
                                  headers=headers, timeout=30)
                if r.status_code == 403:
                    console.print("[red]403 NVD — rate-limit или VPN "
                                  "нужен[/red]")
                    break
                if r.status_code == 429:
                    console.print("[yellow]429 NVD — пауза 30s[/yellow]")
                    time.sleep(30)
                    continue
                r.raise_for_status()
                data = r.json()
            except Exception as exc:
                console.print(f"[red]NVD API: {exc}[/red]")
                break

            if total is None:
                total = min(data.get("totalResults", 0), max_results)
                p.update(task, total=total)

            items = data.get("vulnerabilities", [])
            if not items:
                break

            for item in items:
                rec = _parse_nvd_item(item)
                if rec:
                    _save_cve(rec)
                    saved += 1
                    p.update(task, completed=saved)
                    if saved >= max_results:
                        break

            start_index += len(items)
            if start_index >= (data.get("totalResults", 0)):
                break
            time.sleep(NVD_DELAY)

    console.print(f"[green]✓ Сохранено CVE: {saved}[/green]")
    db.save_scan("cve_download", keyword or f"days={days}",
                 {"count": saved})
    return saved


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ===========================================================================
# CISA KEV
# ===========================================================================

def download_kev() -> int:
    """Скачать CISA KEV."""
    console.print("[cyan]📥 CISA KEV download…[/cyan]")
    try:
        r = requests.get(KEV_URL, timeout=30,
                          headers={"User-Agent": config.USER_AGENT})
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        console.print(f"[red]KEV: {exc}[/red]")
        return 0

    try:
        KEV_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                             encoding="utf-8")
    except Exception:
        pass

    vulns = data.get("vulnerabilities", []) or []
    updated = 0
    for v in vulns:
        cve_id = v.get("cveID", "")
        if not cve_id:
            continue
        try:
            cur = db.conn.cursor()
            cur.execute(
                "UPDATE cves SET kev=1, kev_due=?, kev_ransomware=? "
                "WHERE cve_id=?",
                (v.get("dueDate", ""),
                 v.get("knownRansomwareCampaignUse", ""), cve_id))
            if cur.rowcount == 0:
                cur.execute("""
                    INSERT INTO cves(cve_id, description, vendors, products,
                                     kev, kev_due, kev_ransomware)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        kev=1, kev_due=excluded.kev_due,
                        kev_ransomware=excluded.kev_ransomware
                """, (cve_id,
                       v.get("shortDescription", ""),
                       v.get("vendorProject", ""),
                       v.get("product", ""),
                       v.get("dueDate", ""),
                       v.get("knownRansomwareCampaignUse", "")))
            db.conn.commit()
            updated += 1
        except Exception as exc:
            log.warning("kev save %s: %s", cve_id, exc)

    console.print(f"[green]✓ KEV: {updated} записей[/green]")

    # Findings для ransomware KEV
    ransomware = [v for v in vulns
                  if v.get("knownRansomwareCampaignUse") == "Known"]
    for v in ransomware[:20]:
        _save_finding(CVEFinding(
            cve_id=v.get("cveID", ""),
            severity="critical",
            title=f"KEV Ransomware: {v.get('cveID')} "
                  f"({v.get('vendorProject')} {v.get('product')})",
            target=v.get("vendorProject", "")[:60],
            evidence=v.get("shortDescription", "")[:500],
            data={"dueDate": v.get("dueDate"),
                  "ransomware": v.get("knownRansomwareCampaignUse")},
        ))

    db.save_scan("cve_kev", "cisa",
                 {"count": updated, "ransomware": len(ransomware)})
    return updated


# ===========================================================================
# EPSS (Exploit Prediction)
# ===========================================================================

def enrich_epss(limit: int = 200) -> int:
    """Обогатить CVE данными EPSS."""
    console.print(f"[cyan]📥 EPSS enrichment (limit={limit})…[/cyan]")
    # Получим CVE без EPSS
    try:
        cur = db.conn.cursor()
        cur.execute("""
            SELECT cve_id FROM cves
            WHERE epss_score IS NULL AND cvss_score >= 7
            ORDER BY COALESCE(cvss_score, 0) DESC
            LIMIT ?
        """, (limit,))
        cve_ids = [r["cve_id"] for r in cur.fetchall()]
    except Exception as exc:
        console.print(f"[red]SQL: {exc}[/red]")
        return 0

    if not cve_ids:
        console.print("[dim]Все CVE уже обогащены EPSS.[/dim]")
        return 0

    # EPSS API принимает до 100 CVE за раз
    updated = 0
    chunk_size = 100
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        try:
            r = requests.get(EPSS_API, params={"cve": ",".join(chunk)},
                              timeout=30,
                              headers={"User-Agent": config.USER_AGENT})
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            log.warning("epss: %s", exc)
            continue

        for item in data.get("data", []) or []:
            cve_id = item.get("cve")
            if not cve_id:
                continue
            try:
                cur = db.conn.cursor()
                cur.execute(
                    "UPDATE cves SET epss_score=?, epss_percentile=? "
                    "WHERE cve_id=?",
                    (float(item.get("epss", 0)),
                     float(item.get("percentile", 0)),
                     cve_id))
                updated += 1
            except Exception:
                continue
        db.conn.commit()
        time.sleep(0.5)

    console.print(f"[green]✓ EPSS: {updated} обновлено[/green]")
    return updated


# ===========================================================================
# OSV (Open Source Vulnerabilities)
# ===========================================================================

def osv_query(package: str, version: str = "",
               ecosystem: str = "PyPI") -> list[dict]:
    """Запрос в OSV по пакету."""
    console.print(f"[cyan]🔍 OSV: {ecosystem}/{package} "
                  f"{version or '*'}[/cyan]")
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    try:
        r = requests.post(OSV_API, json=payload, timeout=30,
                           headers={"User-Agent": config.USER_AGENT})
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        console.print(f"[red]OSV: {exc}[/red]")
        return []

    vulns = data.get("vulns", []) or []
    if not vulns:
        console.print("[green]✓ OSV: уязвимостей не найдено[/green]")
        return []

    t = Table(title=f"OSV: {ecosystem}/{package} ({len(vulns)})")
    t.add_column("ID", style="cyan", width=20)
    t.add_column("Summary", style="white", max_width=60)
    t.add_column("Severity", style="red", width=10)
    for v in vulns:
        sev = ""
        for s in v.get("severity", []) or []:
            if s.get("type") == "CVSS_V3":
                sev = "HIGH"
                break
        t.add_row(v.get("id", "?"), v.get("summary", "")[:60],
                  sev or "—")
    console.print(t)

    db.save_scan("osv_query", f"{ecosystem}/{package}",
                 {"count": len(vulns)})
    return vulns


# ===========================================================================
# Поиск / фильтры
# ===========================================================================

def search_cves(keyword: str = "", severity: str = "",
                 min_score: float | None = None,
                 only_kev: bool = False, ransomware: bool = False,
                 exploit_available: bool = False,
                 days: int | None = None,
                 cwe: str = "",
                 min_epss: float | None = None,
                 limit: int = 50) -> list[dict]:
    """Расширенный поиск CVE в локальном кеше."""
    sql = "SELECT * FROM cves WHERE 1=1"
    args: list[Any] = []

    if keyword:
        sql += (" AND (description LIKE ? OR products LIKE ? "
                "OR vendors LIKE ? OR cve_id LIKE ?)")
        like = f"%{keyword}%"
        args.extend([like, like, like, like])
    if severity:
        sql += " AND cvss_severity = ?"
        args.append(severity.upper())
    if min_score is not None:
        sql += " AND cvss_score >= ?"
        args.append(min_score)
    if only_kev:
        sql += " AND kev = 1"
    if ransomware:
        sql += " AND kev_ransomware = 'Known'"
    if exploit_available:
        sql += " AND exploit_available = 1"
    if days:
        cutoff = (datetime.utcnow() - timedelta(days=days)
                   ).strftime("%Y-%m-%dT%H:%M:%S")
        sql += " AND published >= ?"
        args.append(cutoff)
    if cwe:
        sql += " AND cwe LIKE ?"
        args.append(f"%{cwe}%")
    if min_epss is not None:
        sql += " AND epss_score >= ?"
        args.append(min_epss)

    sql += " ORDER BY COALESCE(epss_score, 0) DESC, "\
           "COALESCE(cvss_score, 0) DESC, published DESC LIMIT ?"
    args.append(limit)

    try:
        cur = db.conn.cursor()
        cur.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        console.print(f"[red]Search: {exc}[/red]")
        return []


def _severity_style(sev: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "": "dim",
    }.get((sev or "").upper(), "white")


def _print_cves(cves: list[dict], title: str = "CVE") -> None:
    if not cves:
        console.print("[yellow]Ничего не найдено.[/yellow]")
        return
    t = Table(title=f"{title} ({len(cves)})")
    t.add_column("CVE", style="cyan", width=18)
    t.add_column("Score", width=6)
    t.add_column("Sev", width=9)
    t.add_column("EPSS", width=7)
    t.add_column("KEV", width=4)
    t.add_column("Published", width=11)
    t.add_column("Description", max_width=60)
    for c in cves:
        sev = c.get("cvss_severity") or ""
        sev_styled = f"[{_severity_style(sev)}]{sev}[/{_severity_style(sev)}]"
        score = c.get("cvss_score")
        score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "—"
        epss = c.get("epss_score")
        epss_str = f"{epss * 100:.0f}%" if isinstance(epss, (int, float)) else "—"
        kev = "🔴" if c.get("kev") else ""
        pub = (c.get("published") or "")[:10]
        desc = (c.get("description") or "").replace("\n", " ")[:60]
        t.add_row(c["cve_id"], score_str, sev_styled, epss_str, kev,
                  pub, desc)
    console.print(t)


# ===========================================================================
# Watch-list (мониторинг продуктов)
# ===========================================================================

def watch_add(product: str, min_score: float = 7.0) -> None:
    """Добавить продукт в watch-list."""
    data = _load_watch()
    data[product.lower()] = {"product": product, "min_score": min_score,
                              "added": datetime.utcnow().isoformat()}
    _save_watch(data)
    console.print(f"[green]✓ Добавлено в watch-list: {product} "
                  f"(min CVSS {min_score})[/green]")


def watch_list() -> None:
    data = _load_watch()
    if not data:
        console.print("[yellow]Watch-list пуст.[/yellow]")
        return
    t = Table(title=f"👁  Watch-list ({len(data)})")
    t.add_column("Product", style="cyan")
    t.add_column("Min score", width=10)
    t.add_column("Added", width=20)
    for item in data.values():
        t.add_row(item["product"], str(item["min_score"]),
                  item["added"][:19])
    console.print(t)


def watch_scan() -> int:
    """Сканировать watch-list на новые CVE."""
    data = _load_watch()
    if not data:
        console.print("[yellow]Watch-list пуст.[/yellow]")
        return 0
    total_new = 0
    for item in data.values():
        product = item["product"]
        min_score = item["min_score"]
        cves = search_cves(keyword=product, min_score=min_score,
                            days=7, limit=20)
        if cves:
            console.print(f"\n[yellow]⚠ {product}: {len(cves)} новых "
                          f"CVE (CVSS ≥ {min_score})[/yellow]")
            for c in cves[:5]:
                console.print(f"  • {c['cve_id']} "
                              f"(CVSS {c['cvss_score']}) — "
                              f"{(c.get('description') or '')[:80]}")
                if c.get("kev"):
                    _save_finding(CVEFinding(
                        cve_id=c["cve_id"],
                        severity="critical",
                        title=f"KEV для {product}: {c['cve_id']}",
                        target=product,
                        evidence=c.get("description", "")[:500],
                        data={"cvss": c.get("cvss_score"),
                              "epss": c.get("epss_score")},
                    ))
            total_new += len(cves)
    console.print(f"\n[green]✓ Найдено новых CVE: {total_new}[/green]")
    return total_new


def _load_watch() -> dict:
    if not WATCH_FILE.exists():
        return {}
    try:
        return json.loads(WATCH_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_watch(data: dict) -> None:
    try:
        WATCH_FILE.write_text(json.dumps(data, indent=2,
                                          ensure_ascii=False),
                              encoding="utf-8")
    except Exception as exc:
        log.warning("watch save: %s", exc)


# ===========================================================================
# Google dork generator
# ===========================================================================

DORK_TEMPLATES = {
    "basic": [
        '{product} {version}',
        'inurl:"{product}" "{version}"',
        'intitle:"{product}" inurl:admin',
        '"{product}" "powered by" filetype:php',
        'intitle:"index of" "{product}"',
    ],
    "vulnerable_endpoints": [
        '{product} inurl:".git"',
        '{product} ext:sql intext:"{product}"',
        '{product} inurl:wp-content intext:"{version}"',
        '{product} inurl:api/v1',
        'inurl:"{product}/admin" intext:"login"',
    ],
    "credentials": [
        '{product} inurl:"config" ext:env',
        '{product} ext:log intext:"password"',
        'inurl:"{product}" filetype:sql',
        'inurl:"{product}" "DB_PASSWORD"',
        '{product} inurl:".env"',
    ],
    "cve_specific": [
        '"{cve_id}"',
        'inurl:"{cve_id}"',
        '"{product}" "{cve_id}"',
        '"exploit" "{cve_id}"',
        'filetype:pdf "{cve_id}"',
    ],
    "exploit_search": [
        '"{cve_id}" site:github.com',
        '"{cve_id}" site:packetstormsecurity.com',
        '"{cve_id}" site:exploit-db.com',
        '"{cve_id}" "PoC"',
        '"{cve_id}" "metasploit"',
    ],
}


def generate_dorks(product: str, version: str = "",
                    cve_id: str = "") -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for category, tmpls in DORK_TEMPLATES.items():
        out[category] = []
        for t in tmpls:
            out[category].append(t.format(product=product, version=version,
                                            cve_id=cve_id).strip())
    return out


def show_dorks(product: str, version: str = "", cve_id: str = "") -> None:
    dorks = generate_dorks(product, version, cve_id)
    console.print(f"[bold cyan]🔍 Google dorks: {product} "
                  f"{version} {cve_id}[/bold cyan]\n")
    for category, items in dorks.items():
        t = Table(title=category, show_header=False)
        t.add_column("Dork", style="green")
        for d in items:
            t.add_row(d)
        console.print(t)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in product)[:30]
    path = CVE_DIR / f"dorks_{safe}_{ts}.txt"
    try:
        with path.open("w", encoding="utf-8") as f:
            f.write(f"# Google dorks for {product} {version} {cve_id}\n\n")
            for cat, items in dorks.items():
                f.write(f"## {cat}\n")
                for d in items:
                    f.write(f"{d}\n")
                f.write("\n")
        console.print(f"[green]✓ Сохранено: {path}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Не сохранено: {exc}[/yellow]")

    db.save_scan("cve_dorks", f"{product}:{version}:{cve_id}",
                 {"count": sum(len(v) for v in dorks.values())})


# ===========================================================================
# Статистика и топы
# ===========================================================================

def stats() -> dict:
    """Статистика кеша CVE."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM cves")
        total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM cves WHERE kev=1")
        kev = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM cves WHERE kev=1 "
                    "AND kev_ransomware='Known'")
        rans = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM cves WHERE "
                    "epss_score >= 0.5")
        high_epss = cur.fetchone()["c"]
        cur.execute("SELECT cvss_severity, COUNT(*) as c FROM cves "
                    "WHERE cvss_severity != '' GROUP BY cvss_severity")
        by_sev = {r["cvss_severity"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) as c FROM cves "
                    "WHERE published >= ?",
                    ((datetime.utcnow() - timedelta(days=30))
                     .strftime("%Y-%m-%dT%H:%M:%S"),))
        last30 = cur.fetchone()["c"]
    except Exception as exc:
        console.print(f"[red]Stats: {exc}[/red]")
        return {}

    result = {
        "total": total, "kev": kev, "ransomware": rans,
        "high_epss": high_epss, "last30": last30, "by_severity": by_sev,
    }

    t = Table(title="📊 CVE cache stats")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    t.add_row("Всего CVE", str(total))
    t.add_row("KEV", f"[red]{kev}[/red]")
    t.add_row("Ransomware KEV", f"[bold red]{rans}[/bold red]")
    t.add_row("Высокий EPSS (≥0.5)", str(high_epss))
    t.add_row("За 30 дней", str(last30))
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in by_sev:
            t.add_row(f"  {s}", str(by_sev[s]))
    console.print(t)
    return result


def top_recent(days: int = 7, min_score: float = 7.0,
               limit: int = 50) -> list[dict]:
    cves = search_cves(days=days, min_score=min_score, limit=limit)
    _print_cves(cves, f"🔴 Свежие за {days} дн. (CVSS ≥ {min_score})")
    return cves


def top_epss(limit: int = 50) -> list[dict]:
    """Top CVE по EPSS (вероятность эксплуатации)."""
    cves = search_cves(min_epss=0.5, limit=limit)
    _print_cves(cves, f"📈 Top EPSS (≥0.5)")
    return cves


def kev_list(limit: int = 100, ransomware_only: bool = False
              ) -> list[dict]:
    cves = search_cves(only_kev=True, ransomware=ransomware_only,
                        limit=limit)
    title = ("🔥 KEV Ransomware" if ransomware_only
             else "🔥 CISA KEV — активно эксплуатируемые")
    _print_cves(cves, title)
    return cves


def tech_scan(tech: str, limit: int = 50) -> list[dict]:
    cves = search_cves(keyword=tech, limit=limit)
    _print_cves(cves, f"🔍 CVE по технологии: {tech}")
    return cves


def show_details(cve_id: str) -> None:
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,))
        row = cur.fetchone()
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return
    if not row:
        console.print(f"[red]{cve_id} не найдено в кеше.[/red]")
        console.print("[dim]Сначала: python main.py cve-download[/dim]")
        return

    c = dict(row)
    sev = c.get("cvss_severity") or ""
    sty = _severity_style(sev)

    t = Table(title=f"CVE: {c['cve_id']}", show_header=False)
    t.add_column("Поле", style="cyan", width=18)
    t.add_column("Значение", style="white")
    t.add_row("Published", (c.get("published") or "")[:19])
    t.add_row("Modified", (c.get("last_modified") or "")[:19])
    t.add_row("CVSS v3.1", f"{c.get('cvss_score', '—')} "
                            f"([{sty}]{sev}[/{sty}])")
    if c.get("cvss_v4_score"):
        t.add_row("CVSS v4.0", f"{c['cvss_v4_score']} "
                                f"({c.get('cvss_v4_severity', '')})")
    t.add_row("Vector", c.get("cvss_vector") or "—")
    t.add_row("EPSS", f"{c.get('epss_score', '—')} "
                       f"({c.get('epss_percentile', '—')})")
    t.add_row("CWE", c.get("cwe") or "—")
    t.add_row("KEV", "🔴 ДА" if c.get("kev") else "—")
    if c.get("kev_due"):
        t.add_row("KEV due", c["kev_due"])
    if c.get("kev_ransomware"):
        t.add_row("Ransomware", c["kev_ransomware"])
    if c.get("exploit_available"):
        t.add_row("Exploit", "🔴 public")
    t.add_row("Vendors", c.get("vendors") or "—")
    t.add_row("Products", c.get("products") or "—")
    console.print(t)
    console.print("\n[cyan]Описание:[/cyan]")
    console.print(c.get("description") or "—")

    try:
        refs_list = json.loads(c.get("refs") or "[]")
        if refs_list:
            console.print("\n[cyan]Ссылки:[/cyan]")
            for r in refs_list[:10]:
                console.print(f"  • {r}")
    except Exception:
        pass


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(cves: list[dict],
                 path: str | None = None) -> Path | None:
    if not cves:
        console.print("[yellow]Пусто.[/yellow]")
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CVE_DIR / f"cves_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(cves, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(cves: list[dict],
                path: str | None = None) -> Path | None:
    if not cves:
        console.print("[yellow]Пусто.[/yellow]")
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CVE_DIR / f"cves_{ts}.csv")
    cols = ["cve_id", "published", "cvss_score", "cvss_severity",
            "epss_score", "cwe", "kev", "kev_ransomware",
            "exploit_available", "products", "description"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for c in cves:
                w.writerow([str(c.get(k, ""))[:500] for k in cols])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(cves: list[dict], title: str = "CVE Report",
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CVE_DIR / f"cves_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>{html_mod.escape(title)}</title>",
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
        ".kev{color:#ff4040;font-weight:bold;}",
        "</style></head><body>",
        f"<h1>📡 {html_mod.escape(title)}</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Total: {len(cves)}</p>",
        "<table><tr><th>CVE</th><th>Score</th><th>Sev</th>"
        "<th>EPSS</th><th>KEV</th><th>Published</th>"
        "<th>Description</th></tr>",
    ]
    for c in cves:
        sev = (c.get("cvss_severity") or "").lower()
        score = c.get("cvss_score")
        score_str = (f"{score:.1f}"
                     if isinstance(score, (int, float)) else "—")
        epss = c.get("epss_score")
        epss_str = (f"{epss * 100:.0f}%"
                    if isinstance(epss, (int, float)) else "—")
        kev = "🔴" if c.get("kev") else ""
        parts.append(
            f"<tr><td>{html_mod.escape(c.get('cve_id', ''))}</td>"
            f"<td>{score_str}</td>"
            f"<td class='{sev}'>{sev.upper()}</td>"
            f"<td>{epss_str}</td>"
            f"<td class='kev'>{kev}</td>"
            f"<td>{(c.get('published') or '')[:10]}</td>"
            f"<td>{html_mod.escape((c.get('description') or '')[:200])}</td>"
            f"</tr>")
    parts.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


def export_markdown(cves: list[dict], title: str = "CVE Report",
                     path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CVE_DIR / f"cves_{ts}.md")
    lines = [
        f"# {title}",
        f"_Generated: {datetime.now().isoformat()}_", "",
        f"Total: **{len(cves)}**", "",
        "| CVE | CVSS | EPSS | KEV | Published | Description |",
        "|-----|------|------|-----|-----------|-------------|",
    ]
    for c in cves:
        score = c.get("cvss_score")
        score_str = (f"{score:.1f}"
                     if isinstance(score, (int, float)) else "—")
        epss = c.get("epss_score")
        epss_str = (f"{epss * 100:.0f}%"
                    if isinstance(epss, (int, float)) else "—")
        kev = "🔴" if c.get("kev") else ""
        lines.append(
            f"| {c.get('cve_id', '')} | {score_str} | {epss_str} | "
            f"{kev} | {(c.get('published') or '')[:10]} | "
            f"{(c.get('description') or '')[:100]} |")
    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]Markdown: {exc}[/red]")
        return None


# ===========================================================================
# Notify
# ===========================================================================

def _notify(title: str, message: str) -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, message)
    except Exception:
        pass


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_download(keyword: str = "", days: int = 0,
                  max_results: int = 500) -> None:
    download_nvd(keyword=keyword, days=(days if days > 0 else None),
                  max_results=max_results)


def cli_search(keyword: str, min_score: float | None = None,
                only_kev: bool = False, limit: int = 30) -> None:
    cves = search_cves(keyword=keyword, min_score=min_score,
                        only_kev=only_kev, limit=limit)
    _print_cves(cves, f"Поиск: {keyword}")


def cli_dorks(product: str, version: str = "",
               cve_id: str = "") -> None:
    show_dorks(product, version, cve_id)


def cli_top(days: int = 7, min_score: float = 7.0,
             limit: int = 50) -> None:
    top_recent(days=days, min_score=min_score, limit=limit)


def cli_kev(limit: int = 100) -> None:
    kev_list(limit=limit)


def cli_show(cve_id: str) -> None:
    show_details(cve_id)


def cli_epss(limit: int = 200) -> None:
    enrich_epss(limit=limit)


def cli_watch_add(product: str, min_score: float = 7.0) -> None:
    watch_add(product, min_score)


def cli_watch_list() -> None:
    watch_list()


def cli_watch_scan() -> None:
    watch_scan()


def cli_top_epss(limit: int = 50) -> None:
    top_epss(limit=limit)


def cli_osv(package: str, version: str = "",
             ecosystem: str = "PyPI") -> None:
    osv_query(package, version, ecosystem)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📡 CVE Feeds[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Скачать свежие CVE из NVD"),
        ("2", "Скачать CISA KEV"),
        ("3", "EPSS enrichment"),
        ("4", "OSV query (по пакету)"),
        ("5", "Статистика кеша"),
        ("6", "Топ свежих критичных"),
        ("7", "Top EPSS (вероятность эксплуатации)"),
        ("8", "CISA KEV список"),
        ("9", "Только ransomware KEV"),
        ("10", "Поиск по технологии"),
        ("11", "Детали CVE"),
        ("12", "Google dorks"),
        ("13", "Watch-list: добавить"),
        ("14", "Watch-list: показать"),
        ("15", "Watch-list: сканировать"),
        ("16", "Экспорт JSON / CSV / HTML / Markdown"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        kw = Prompt.ask("Ключевое слово (пусто = все)", default="").strip()
        days_raw = Prompt.ask("За последние N дней (пусто = все)",
                               default="").strip()
        days = int(days_raw) if days_raw.isdigit() else None
        max_r = IntPrompt.ask("Максимум записей", default=500)
        download_nvd(keyword=kw, days=days, max_results=max_r)
    elif c == "2":
        download_kev()
    elif c == "3":
        enrich_epss()
    elif c == "4":
        pkg = Prompt.ask("Пакет")
        ver = Prompt.ask("Версия (пусто)", default="")
        eco = Prompt.ask("Ecosystem",
                          choices=["PyPI", "npm", "Go", "Maven", "crates.io",
                                   "RubyGems", "NuGet", "Packagist"],
                          default="PyPI")
        osv_query(pkg, ver, eco)
    elif c == "5":
        stats()
    elif c == "6":
        days = IntPrompt.ask("За N дней", default=7)
        score = float(Prompt.ask("Min CVSS", default="7.0"))
        top_recent(days=days, min_score=score)
    elif c == "7":
        top_epss()
    elif c == "8":
        kev_list()
    elif c == "9":
        kev_list(ransomware_only=True)
    elif c == "10":
        tech = Prompt.ask("Технология")
        tech_scan(tech)
    elif c == "11":
        show_details(Prompt.ask("CVE ID"))
    elif c == "12":
        product = Prompt.ask("Продукт")
        version = Prompt.ask("Версия (пусто)", default="")
        cve_id = Prompt.ask("CVE ID (пусто)", default="")
        show_dorks(product, version, cve_id)
    elif c == "13":
        p = Prompt.ask("Продукт")
        s = float(Prompt.ask("Min CVSS", default="7.0"))
        watch_add(p, s)
    elif c == "14":
        watch_list()
    elif c == "15":
        watch_scan()
    elif c == "16":
        cves = search_cves(limit=1000)
        if not cves:
            console.print("[yellow]Пусто.[/yellow]")
            return
        export_json(cves)
        export_csv(cves)
        export_html(cves)
        export_markdown(cves)