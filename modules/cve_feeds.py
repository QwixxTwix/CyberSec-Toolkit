"""
CVE Feeds — загрузка и анализ CVE.
Author: idqwixxa

Источники:
    - NVD API 2.0 (nvd.nist.gov) — все CVE, ключ не обязателен (rate-limit)
    - CISA KEV (известные эксплуатируемые) — публичный JSON

Возможности:
    - Кеш CVE в SQLite (таблица cves)
    - Поиск по ключевому слову (продукт, вендор)
    - Фильтр по CVSS score, severity, дате
    - Список CISA KEV (активно эксплуатируемые)
    - Генератор Google dork'ов под CVE (поиск уязвимых инстансов)
    - Экспорт результатов в JSON/CSV/Markdown
"""
import csv
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# Пауза между запросами к NVD без API-key (rate-limit ~5 запросов / 30 сек)
NVD_DELAY = 6.5
KEV_FILE = REPORT_DIR / "cisa_kev.json"


# ===========================================================================
# Схема БД
# ===========================================================================

def _init_schema() -> None:
    try:
        cur = db.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                published TEXT,
                last_modified TEXT,
                description TEXT,
                cvss_score REAL,
                cvss_severity TEXT,
                cvss_vector TEXT,
                vendors TEXT,
                products TEXT,
                refs TEXT,
                kev INTEGER DEFAULT 0,
                kev_due TEXT,
                kev_ransomware TEXT,
                raw TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_cves_sev   ON cves(cvss_severity);
            CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(cvss_score);
            CREATE INDEX IF NOT EXISTS idx_cves_kev   ON cves(kev);
            """
        )
        db.conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.exception("cve schema: %s", exc)


try:
    _init_schema()
except Exception:
    pass


# ===========================================================================
# NVD: парсинг и загрузка
# ===========================================================================

def _parse_nvd_item(item: dict) -> dict | None:
    """Парсинг одного CVE из ответа NVD API 2.0."""
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

        # CVSS (v3.1 → v3.0 → v2)
        cvss_score = None
        cvss_sev = ""
        cvss_vec = ""
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                m = arr[0].get("cvssData", {}) or {}
                cvss_score = m.get("baseScore")
                cvss_sev = m.get("baseSeverity") or arr[0].get("baseSeverity", "")
                cvss_vec = m.get("vectorString", "")
                break

        # Vendors / products
        vendors: set[str] = set()
        products: set[str] = set()
        for cfg in cve.get("configurations", []) or []:
            for node in cfg.get("nodes", []) or []:
                for cpe in node.get("cpeMatch", []) or []:
                    crit = cpe.get("criteria", "")
                    parts = crit.split(":")
                    # cpe:2.3:a:vendor:product:version:...
                    if len(parts) >= 5:
                        vendors.add(parts[3])
                        products.add(parts[4])

        # References
        refs = [r.get("url", "") for r in cve.get("references", []) or []]

        return {
            "cve_id": cve_id,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "description": desc[:2000],
            "cvss_score": cvss_score,
            "cvss_severity": (cvss_sev or "").upper(),
            "cvss_vector": cvss_vec,
            "vendors": ",".join(sorted(vendors))[:500],
            "products": ",".join(sorted(products))[:500],
            "refs": json.dumps(refs[:20], ensure_ascii=False),
            "kev": 0,
            "kev_due": "",
            "kev_ransomware": "",
            "raw": json.dumps(cve, ensure_ascii=False)[:4000],
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("parse nvd: %s", exc)
        return None


def _save_cve(rec: dict) -> None:
    """UPSERT CVE в БД."""
    try:
        cur = db.conn.cursor()
        cur.execute(
            """
            INSERT INTO cves(cve_id, published, last_modified, description,
                             cvss_score, cvss_severity, cvss_vector,
                             vendors, products, refs, kev, kev_due,
                             kev_ransomware, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                last_modified=excluded.last_modified,
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                cvss_severity=excluded.cvss_severity,
                cvss_vector=excluded.cvss_vector,
                vendors=excluded.vendors,
                products=excluded.products,
                refs=excluded.refs,
                raw=excluded.raw
            """,
            (rec["cve_id"], rec["published"], rec["last_modified"],
             rec["description"], rec["cvss_score"], rec["cvss_severity"],
             rec["cvss_vector"], rec["vendors"], rec["products"],
             rec["refs"], rec["kev"], rec["kev_due"],
             rec["kev_ransomware"], rec["raw"]),
        )
        db.conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("save cve %s: %s", rec.get("cve_id"), exc)


def download_nvd(keyword: str = "", days: int | None = None,
                 max_results: int = 500) -> int:
    """
    Скачать CVE из NVD по фильтрам.
    days — за последние N дней.
    Возвращает количество сохранённых записей.
    """
    params: dict[str, Any] = {
        "resultsPerPage": min(max_results, 2000),
    }
    if keyword:
        params["keywordSearch"] = keyword

    if days:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        # NVD API 2.0 требует ISO8601 без Z
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {"User-Agent": config.USER_AGENT}
    if config.GITHUB_TOKEN and "apiKey" not in params:
        headers["apiKey"] = config.GITHUB_TOKEN  # не критично, но NVD принимает свой

    console.print(f"[cyan]📥 NVD download: keyword='{keyword or '*'}' "
                  f"days={days or 'all'} max={max_results}[/cyan]")

    saved = 0
    start_index = 0
    total = None
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as p:
        task = p.add_task("NVD", total=max_results)
        while saved < max_results:
            paged = dict(params)
            paged["startIndex"] = start_index
            try:
                r = requests.get(NVD_API, params=paged,
                                 headers=headers, timeout=30)
                if r.status_code == 403:
                    console.print("[red]403 от NVD — включи VPN или "
                                  "получи API key (nvd.nist.gov)[/red]")
                    break
                r.raise_for_status()
                data = r.json()
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]NVD API error: {exc}[/red]")
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
            # вежливая пауза (rate limit NVD без ключа)
            if not headers.get("apiKey"):
                time.sleep(NVD_DELAY)

    console.print(f"[green]✓ Сохранено CVE: {saved}[/green]")
    db.save_scan("cve_download", keyword or f"days={days}",
                 {"count": saved})
    return saved


# ===========================================================================
# CISA KEV
# ===========================================================================

def download_kev() -> int:
    """Скачать CISA KEV (Known Exploited Vulnerabilities)."""
    console.print("[cyan]📥 CISA KEV download…[/cyan]")
    try:
        r = requests.get(KEV_URL, timeout=30,
                         headers={"User-Agent": config.USER_AGENT})
        r.raise_for_status()
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]KEV error: {exc}[/red]")
        return 0

    try:
        KEV_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                            encoding="utf-8")
    except Exception:  # noqa: BLE001
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
                (v.get("dueDate", ""), v.get("knownRansomwareCampaignUse", ""),
                 cve_id),
            )
            if cur.rowcount == 0:
                # CVE ещё нет — создадим минимальную запись
                cur.execute(
                    """
                    INSERT INTO cves(cve_id, description, vendors, products,
                                     kev, kev_due, kev_ransomware)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        kev=1, kev_due=excluded.kev_due,
                        kev_ransomware=excluded.kev_ransomware
                    """,
                    (cve_id,
                     v.get("shortDescription", ""),
                     v.get("vendorProject", ""),
                     v.get("product", ""),
                     v.get("dueDate", ""),
                     v.get("knownRansomwareCampaignUse", "")),
                )
            db.conn.commit()
            updated += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("kev save %s: %s", cve_id, exc)

    console.print(f"[green]✓ KEV: обновлено {updated} записей[/green]")
    console.print(f"[dim]Всего в KEV: {len(vulns)}[/dim]")
    db.save_scan("cve_kev", "cisa", {"count": updated})
    return updated


# ===========================================================================
# Поиск / фильтры
# ===========================================================================

def search_cves(keyword: str = "", severity: str = "",
                min_score: float | None = None,
                only_kev: bool = False, days: int | None = None,
                limit: int = 50) -> list[dict]:
    """Поиск CVE в локальном кеше."""
    sql = "SELECT * FROM cves WHERE 1=1"
    args: list[Any] = []

    if keyword:
        sql += " AND (description LIKE ? OR products LIKE ? OR vendors LIKE ?)"
        like = f"%{keyword}%"
        args.extend([like, like, like])
    if severity:
        sql += " AND cvss_severity = ?"
        args.append(severity.upper())
    if min_score is not None:
        sql += " AND cvss_score >= ?"
        args.append(min_score)
    if only_kev:
        sql += " AND kev = 1"
    if days:
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime(
            "%Y-%m-%dT%H:%M:%S")
        sql += " AND published >= ?"
        args.append(cutoff)

    sql += " ORDER BY COALESCE(cvss_score, 0) DESC, published DESC LIMIT ?"
    args.append(limit)

    try:
        cur = db.conn.cursor()
        cur.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Search error: {exc}[/red]")
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

    table = Table(title=f"{title} ({len(cves)})")
    table.add_column("CVE", style="cyan", width=18)
    table.add_column("Score", width=6)
    table.add_column("Sev", width=9)
    table.add_column("KEV", width=4)
    table.add_column("Published", width=11)
    table.add_column("Description", max_width=70)

    for c in cves:
        sev = c.get("cvss_severity") or ""
        sev_styled = f"[{_severity_style(sev)}]{sev}[/{_severity_style(sev)}]"
        score = c.get("cvss_score")
        score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "—"
        kev = "🔴" if c.get("kev") else ""
        pub = (c.get("published") or "")[:10]
        desc = (c.get("description") or "").replace("\n", " ")[:70]
        table.add_row(c["cve_id"], score_str, sev_styled, kev, pub, desc)
    console.print(table)


# ===========================================================================
# Google dork генератор
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
}


def generate_dorks(product: str, version: str = "",
                   cve_id: str = "") -> dict[str, list[str]]:
    """Сгенерировать Google dork'и для продукта/CVE."""
    out: dict[str, list[str]] = {}
    for category, tmpls in DORK_TEMPLATES.items():
        out[category] = []
        for t in tmpls:
            dork = t.format(product=product, version=version, cve_id=cve_id)
            out[category].append(dork.strip())
    return out


def show_dorks(product: str, version: str = "", cve_id: str = "") -> None:
    """Показать Google dork'и."""
    dorks = generate_dorks(product, version, cve_id)
    console.print(f"[bold cyan]🔍 Google dorks: {product} "
                  f"{version} {cve_id}[/bold cyan]\n")

    for category, items in dorks.items():
        table = Table(title=category, show_header=False)
        table.add_column("Dork", style="green")
        for d in items:
            table.add_row(d)
        console.print(table)

    # Сохранить в файл
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in product)[:30]
    path = REPORT_DIR / f"dorks_{safe}_{ts}.txt"
    try:
        with path.open("w", encoding="utf-8") as f:
            f.write(f"# Google dorks for {product} {version} {cve_id}\n\n")
            for cat, items in dorks.items():
                f.write(f"## {cat}\n")
                for d in items:
                    f.write(f"{d}\n")
                f.write("\n")
        console.print(f"[green]✓ Сохранено: {path}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Не удалось сохранить: {exc}[/yellow]")

    db.save_scan("cve_dorks", f"{product}:{version}:{cve_id}",
                 {"count": sum(len(v) for v in dorks.values())})


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(cves: list[dict], path: str | None = None) -> Path | None:
    if not cves:
        console.print("[yellow]Пустой список.[/yellow]")
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(REPORT_DIR / f"cves_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(cves, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(cves: list[dict], path: str | None = None) -> Path | None:
    if not cves:
        console.print("[yellow]Пустой список.[/yellow]")
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(REPORT_DIR / f"cves_{ts}.csv")
    cols = ["cve_id", "published", "cvss_score", "cvss_severity",
            "kev", "cvss_vector", "products", "description"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for c in cves:
                w.writerow([str(c.get(k, ""))[:500] for k in cols])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def show_details(cve_id: str) -> None:
    """Показать детали одного CVE."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,))
        row = cur.fetchone()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    if not row:
        console.print(f"[red]{cve_id} не найдено в кеше.[/red]")
        console.print("[dim]Сначала скачай: python main.py cve-download[/dim]")
        return

    c = dict(row)
    sev = c.get("cvss_severity") or ""
    sty = _severity_style(sev)

    table = Table(title=f"CVE: {c['cve_id']}", show_header=False)
    table.add_column("Поле", style="cyan", width=16)
    table.add_column("Значение", style="white")
    table.add_row("Published", (c.get("published") or "")[:19])
    table.add_row("Modified", (c.get("last_modified") or "")[:19])
    table.add_row("CVSS", f"{c.get('cvss_score', '—')} "
                          f"([{sty}]{sev}[/{sty}])")
    table.add_row("Vector", c.get("cvss_vector") or "—")
    table.add_row("KEV", "🔴 ДА" if c.get("kev") else "—")
    if c.get("kev_due"):
        table.add_row("KEV due", c["kev_due"])
    if c.get("kev_ransomware"):
        table.add_row("Ransomware", c["kev_ransomware"])
    table.add_row("Vendors", c.get("vendors") or "—")
    table.add_row("Products", c.get("products") or "—")
    console.print(table)
    console.print("\n[cyan]Описание:[/cyan]")
    console.print(c.get("description") or "—")
    refs = c.get("refs") or "[]"
    try:
        refs_list = json.loads(refs)
        if refs_list:
            console.print("\n[cyan]Ссылки:[/cyan]")
            for r in refs_list[:10]:
                console.print(f"  • {r}")
    except Exception:
        pass


# ===========================================================================
# Публичные высокоуровневые функции
# ===========================================================================

def stats() -> None:
    """Статистика кеша CVE."""
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM cves")
        total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM cves WHERE kev=1")
        kev = cur.fetchone()["c"]
        cur.execute("SELECT cvss_severity, COUNT(*) as c FROM cves "
                    "WHERE cvss_severity != '' GROUP BY cvss_severity")
        by_sev = {r["cvss_severity"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) as c FROM cves "
                    "WHERE published >= ?",
                    ((datetime.utcnow() - timedelta(days=30))
                     .strftime("%Y-%m-%dT%H:%M:%S"),))
        last30 = cur.fetchone()["c"]
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return

    table = Table(title="📊 CVE cache stats")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Всего CVE", str(total))
    table.add_row("Из них KEV", str(kev))
    table.add_row("За 30 дней", str(last30))
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in by_sev:
            table.add_row(f"  {s}", str(by_sev[s]))
    console.print(table)


def top_recent(days: int = 7, min_score: float = 7.0,
               limit: int = 50) -> list[dict]:
    """Топ свежих CVE за N дней с CVSS >= порога."""
    cves = search_cves(days=days, min_score=min_score, limit=limit)
    _print_cves(cves, f"🔴 Критичные за {days} дн. (CVSS ≥ {min_score})")
    return cves


def kev_list(limit: int = 100) -> list[dict]:
    """Список активных KEV."""
    cves = search_cves(only_kev=True, limit=limit)
    _print_cves(cves, "🔥 CISA KEV — активно эксплуатируемые")
    return cves


def tech_scan(tech: str, limit: int = 50) -> list[dict]:
    """Найти CVE для технологии (продукт/вендор)."""
    cves = search_cves(keyword=tech, limit=limit)
    _print_cves(cves, f"🔍 CVE по технологии: {tech}")
    return cves


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]📡 CVE Feeds[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Скачать свежие CVE из NVD"),
        ("2", "Скачать CISA KEV (активно эксплуатируемые)"),
        ("3", "Статистика кеша"),
        ("4", "Топ свежих критичных CVE"),
        ("5", "CISA KEV список"),
        ("6", "Поиск по технологии"),
        ("7", "Детали CVE"),
        ("8", "Генератор Google dork'ов"),
        ("9", "Экспорт в JSON/CSV"),
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
        stats()
    elif c == "4":
        days = IntPrompt.ask("За N дней", default=7)
        score = float(Prompt.ask("Минимальный CVSS", default="7.0"))
        top_recent(days=days, min_score=score)
    elif c == "5":
        kev_list()
    elif c == "6":
        tech = Prompt.ask("Технология (apache, nginx, wordpress…)")
        tech_scan(tech)
    elif c == "7":
        show_details(Prompt.ask("CVE ID (CVE-YYYY-NNNNN)"))
    elif c == "8":
        product = Prompt.ask("Продукт")
        version = Prompt.ask("Версия (пусто)", default="")
        cve_id = Prompt.ask("CVE ID (пусто)", default="")
        show_dorks(product, version, cve_id)
    elif c == "9":
        cves = search_cves(limit=1000)
        if not cves:
            console.print("[yellow]Пусто.[/yellow]")
            return
        export_json(cves)
        export_csv(cves)


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_download(keyword: str = "", days: int = 0,
                 max_results: int = 500) -> None:
    download_nvd(keyword=keyword,
                 days=(days if days > 0 else None),
                 max_results=max_results)


def cli_search(keyword: str, min_score: float | None = None,
               only_kev: bool = False, limit: int = 30) -> None:
    cves = search_cves(keyword=keyword, min_score=min_score,
                       only_kev=only_kev, limit=limit)
    _print_cves(cves, f"Поиск: {keyword}")


def cli_dorks(product: str, version: str = "", cve_id: str = "") -> None:
    show_dorks(product, version, cve_id)


def cli_top(days: int = 7, min_score: float = 7.0,
            limit: int = 50) -> None:
    top_recent(days=days, min_score=min_score, limit=limit)


def cli_kev(limit: int = 100) -> None:
    kev_list(limit=limit)


def cli_show(cve_id: str) -> None:
    show_details(cve_id)