"""
Cloud Storage Enumeration — расширенный.
Author: idqwixxa

⚠ Только для этичного использования и bug bounty.

Возможности:
    ─── Провайдеры ───
    - AWS S3 (+ все регионы, ACL, Policy, Website)
    - Google Cloud Storage (+ Firebase)
    - Azure Blob Storage (+ Static Website)
    - DigitalOcean Spaces
    - Linode Object Storage
    - Backblaze B2
    - Wasabi
    - Alibaba OSS
    - Oracle OCI
    - Cloudflare R2

    ─── Проверки ───
    - List (public listing)
    - Read (public GetObject)
    - Write (public PutObject — critical!)
    - ACL (AccessControlPolicy)
    - Policy (BucketPolicy)
    - CORS (заголовки)
    - Website (static hosting)

    ─── Генерация имён ───
    - Из домена: company-{suffixes}
    - Prefix + company
    - Bare names (общие)
    - Wordlist-based (wordlists/)

    ─── Интеграция ───
    - Findings → notes для critical/high
    - HTML / JSON / CSV экспорт
    - Notify по завершении
"""
import csv
import html as html_mod
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable
from xml.etree import ElementTree as ET

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR, WORDLIST_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STORAGE_DIR = REPORT_DIR / "cloud_storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 10
MAX_WORKERS = 50


# ===========================================================================
# Словари имён
# ===========================================================================

COMMON_SUFFIXES = [
    "backup", "backups", "bak", "old", "new", "dev", "development",
    "test", "testing", "stage", "staging", "prod", "production",
    "prod-backup", "dev-backup", "static", "assets", "media", "images",
    "img", "files", "file", "downloads", "uploads", "public", "private",
    "internal", "external", "data", "db", "database", "sql", "dump",
    "dumps", "logs", "log", "archive", "archives", "temp", "tmp",
    "cache", "cdn", "web", "s3", "bucket", "cloud", "storage", "store",
    "documents", "docs", "reports", "export", "exports", "customer",
    "customers", "user", "users", "admin", "api", "sdk", "client",
    "mobile", "app", "website", "site", "www", "source", "src", "build",
    "builds", "dist", "release", "releases", "config", "configs",
    "secret", "secrets", "keys", "credentials", "migration",
    "migrations", "mail", "email", "emails", "invoices", "receipts",
    "pdf", "pdfs", "share", "shared", "office", "cdn-assets",
    "web-assets", "static-content", "terraform", "tfstate",
    "cloudformation", "k8s", "kubernetes", "deploy", "deployment",
]

COMMON_PREFIXES = [
    "dev", "test", "staging", "stage", "prod", "production",
    "internal", "external", "public", "private", "backup", "old",
    "new", "temp", "app", "web", "api", "my", "corp", "company",
]

COMMON_BARE_NAMES = [
    "backup", "backups", "test", "dev", "prod", "public", "private",
    "static", "assets", "media", "files", "data", "logs", "web",
    "storage", "bucket", "cloud", "docs", "documents", "downloads",
    "uploads", "temp", "tmp", "archive", "old", "config", "secrets",
]


# ===========================================================================
# Model
# ===========================================================================

@dataclass
class Bucket:
    name: str
    provider: str       # s3 | gcs | azure | do | linode | b2 | wasabi |
                        # alibaba | oci | r2 | firebase
    url: str = ""
    region: str = ""
    exists: bool = False
    public_list: bool = False
    public_read: bool = False
    public_write: bool = False
    public_acl: bool = False
    public_policy: bool = False
    cors_enabled: bool = False
    website_enabled: bool = False
    files_count: int = 0
    sample_files: list[str] = field(default_factory=list)
    index_html_present: bool = False
    index_title: str = ""
    error: str = ""
    status_code: int = 0

    def severity(self) -> str:
        if not self.exists:
            return "info"
        if self.public_write:
            return "critical"
        if self.public_list or self.public_policy:
            return "high"
        if self.public_read or self.website_enabled:
            return "medium"
        if self.public_acl:
            return "low"
        return "info"


def _save_finding(b: Bucket) -> int:
    """Сохранить critical/high findings в notes."""
    if b.severity() not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f"Cloud bucket {b.severity()}: {b.name} ({b.provider})",
            target=b.name,
            severity=b.severity(),
            status="open",
            tags=["cloud-storage", b.provider, b.severity()],
            body=(f"**Provider:** {b.provider}\n"
                  f"**Name:** {b.name}\n"
                  f"**URL:** {b.url}\n"
                  f"**Region:** {b.region or '?'}\n\n"
                  f"**Access:**\n"
                  f"- List: {b.public_list}\n"
                  f"- Read: {b.public_read}\n"
                  f"- Write: {b.public_write}\n"
                  f"- ACL public: {b.public_acl}\n"
                  f"- Policy public: {b.public_policy}\n\n"
                  f"**Files count:** {b.files_count}\n"
                  f"**Sample:** {', '.join(b.sample_files[:5])}"),
        )
    except Exception:
        return -1


# ===========================================================================
# AWS S3
# ===========================================================================

S3_URLS = [
    "https://{name}.s3.amazonaws.com/",
    "https://s3.amazonaws.com/{name}/",
    "https://{name}.s3.us-east-1.amazonaws.com/",
]


def _parse_s3_list_xml(xml_text: str) -> tuple[int, list[str]]:
    try:
        root = ET.fromstring(xml_text)
        keys = root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Key")
        if not keys:
            keys = root.findall(".//Key")
        names = [k.text for k in keys if k.text][:20]
        return len(names), names
    except Exception:
        return 0, []


def _extract_region_from_301(headers: dict, body: str) -> str:
    loc = headers.get("x-amz-bucket-region", "")
    if loc:
        return loc
    m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body)
    if m:
        return m.group(1)
    m = re.search(r"<Region>([^<]+)</Region>", body)
    if m:
        return m.group(1)
    return ""


def _check_index_html(url: str) -> tuple[bool, str]:
    """Проверить наличие index.html и извлечь title."""
    try:
        r = requests.get(
            url + "index.html", timeout=TIMEOUT, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200 and "<html" in r.text.lower():
            m = re.search(r"<title>([^<]+)</title>", r.text, re.I)
            title = m.group(1).strip()[:100] if m else ""
            return True, title
    except Exception:
        pass
    return False, ""


def check_s3(name: str, check_write: bool = False,
             timeout: int = TIMEOUT) -> Bucket:
    """Полная проверка S3-бакета."""
    b = Bucket(name=name, provider="s3")

    for url_tpl in S3_URLS:
        url = url_tpl.format(name=name)
        b.url = url
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
        except Exception as exc:
            b.error = str(exc)[:80]
            continue

        b.status_code = r.status_code

        if r.status_code == 200:
            b.exists = True
            b.public_list = True
            b.files_count, b.sample_files = _parse_s3_list_xml(r.text)
            break
        if r.status_code in (301, 307):
            region = _extract_region_from_301(dict(r.headers), r.text)
            b.region = region
            b.exists = True
            if region:
                try:
                    url2 = f"https://{name}.s3.{region}.amazonaws.com/"
                    r2 = requests.get(url2, timeout=timeout, verify=False,
                                       allow_redirects=False,
                                       headers={"User-Agent":
                                                config.USER_AGENT})
                    b.url = url2
                    if r2.status_code == 200:
                        b.public_list = True
                        b.files_count, b.sample_files = \
                            _parse_s3_list_xml(r2.text)
                    elif r2.status_code == 403:
                        b.public_list = False
                    b.status_code = r2.status_code
                except Exception:
                    pass
            break
        if r.status_code == 403:
            b.exists = True
            b.public_list = False
            break
        if r.status_code == 404:
            continue
        if 200 <= r.status_code < 500:
            b.exists = True
            break

    if not b.exists:
        return b

    # ACL
    try:
        r = requests.get(b.url + "?acl", timeout=timeout, verify=False,
                          allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
        if r.status_code == 200 and "AccessControlPolicy" in r.text:
            b.public_acl = True
    except Exception:
        pass

    # Policy
    try:
        r = requests.get(b.url + "?policy", timeout=timeout, verify=False,
                          allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
        if r.status_code == 200:
            try:
                policy = r.json()
                statements = policy.get("Statement", []) or []
                if any(s.get("Principal") == "*"
                        for s in statements if isinstance(s, dict)):
                    b.public_policy = True
            except Exception:
                pass
    except Exception:
        pass

    # CORS
    try:
        r = requests.options(b.url, timeout=timeout, verify=False,
                              headers={"User-Agent": config.USER_AGENT,
                                       "Origin": "https://evil.example.com"})
        if r.headers.get("Access-Control-Allow-Origin"):
            b.cors_enabled = True
    except Exception:
        pass

    # Website
    try:
        r = requests.get(f"http://{name}.s3-website-us-east-1.amazonaws.com/",
                          timeout=timeout, verify=False, allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
        if r.status_code in (200, 301, 302):
            b.website_enabled = True
    except Exception:
        pass

    # Public read
    if not b.public_list:
        try:
            test_key = b.sample_files[0] if b.sample_files else "index.html"
            r = requests.get(
                b.url + test_key, timeout=timeout, verify=False,
                allow_redirects=False,
                headers={"User-Agent": config.USER_AGENT},
            )
            if r.status_code == 200 and int(
                    r.headers.get("Content-Length", "0") or 0) > 0:
                b.public_read = True
        except Exception:
            pass

    # index.html check
    b.index_html_present, b.index_title = _check_index_html(b.url)

    # Public write
    if check_write and b.exists:
        try:
            r = requests.put(
                b.url + "pentest-write-test.txt",
                data=b"CyberSec Toolkit — write test (authorized only)",
                timeout=timeout, verify=False,
                headers={"User-Agent": config.USER_AGENT},
            )
            if r.status_code in (200, 201):
                b.public_write = True
        except Exception:
            pass

    return b


# ===========================================================================
# Google Cloud Storage
# ===========================================================================

GCS_URLS = [
    "https://storage.googleapis.com/{name}/",
    "https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults=10",
    "https://{name}.storage.googleapis.com/",
]


def check_gcs(name: str, check_write: bool = False,
              timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="gcs")

    try:
        url = f"https://storage.googleapis.com/storage/v1/b/{name}/o?maxResults=10"
        b.url = url
        r = requests.get(url, timeout=timeout, verify=False,
                          headers={"User-Agent": config.USER_AGENT})
        b.status_code = r.status_code
        if r.status_code == 200:
            b.exists = True
            b.public_list = True
            data = r.json()
            items = data.get("items", []) or []
            b.files_count = len(items)
            b.sample_files = [i.get("name", "") for i in items[:20]]
            return b
        if r.status_code == 403:
            b.exists = True
            return b
    except Exception as exc:
        b.error = str(exc)[:80]

    try:
        url = f"https://storage.googleapis.com/{name}/"
        b.url = url
        r = requests.get(url, timeout=timeout, verify=False,
                          allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
        b.status_code = r.status_code
        if r.status_code == 200 and "ListBucketResult" in r.text:
            b.exists = True
            b.public_list = True
            b.files_count, b.sample_files = _parse_s3_list_xml(r.text)
        elif r.status_code == 403:
            b.exists = True
    except Exception:
        pass

    return b


# ===========================================================================
# Firebase Storage
# ===========================================================================

def check_firebase(name: str, check_write: bool = False,
                    timeout: int = TIMEOUT) -> Bucket:
    """Firebase Storage бакет (совместим с GCS)."""
    # Firebase storage обычно = <project>.appspot.com или <project>.firebaseapp.com
    b = Bucket(name=name, provider="firebase")
    url = f"https://firebasestorage.googleapis.com/v0/b/{name}.appspot.com/o"
    b.url = url
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                          headers={"User-Agent": config.USER_AGENT})
        b.status_code = r.status_code
        if r.status_code == 200:
            try:
                data = r.json()
                items = data.get("items", []) or []
                b.exists = True
                b.public_list = True
                b.files_count = len(items)
                b.sample_files = [i.get("name", "") for i in items[:20]]
            except Exception:
                pass
    except Exception as exc:
        b.error = str(exc)[:80]
    return b


# ===========================================================================
# Azure Blob Storage
# ===========================================================================

AZURE_CONTAINERS = [
    "public", "media", "uploads", "data", "backup", "backups",
    "static", "assets", "files", "images", "img", "documents",
    "docs", "logs", "web", "cdn", "storage", "temp", "$web",
]


def check_azure(account: str, containers: list[str] | None = None,
                 timeout: int = TIMEOUT) -> list[Bucket]:
    if not containers:
        containers = AZURE_CONTAINERS
    out: list[Bucket] = []
    base = f"https://{account}.blob.core.windows.net"

    for c in containers:
        b = Bucket(name=f"{account}/{c}", provider="azure",
                    url=f"{base}/{c}?restype=container&comp=list")
        try:
            r = requests.get(b.url, timeout=timeout, verify=False,
                              headers={"User-Agent": config.USER_AGENT})
            b.status_code = r.status_code
            if r.status_code == 200 and "EnumerationResults" in r.text:
                b.exists = True
                b.public_list = True
                try:
                    root = ET.fromstring(r.text)
                    blobs = root.findall(".//Blob")
                    b.files_count = len(blobs)
                    names = []
                    for blob in blobs[:20]:
                        n = blob.find("Name")
                        if n is not None and n.text:
                            names.append(n.text)
                    b.sample_files = names
                except Exception:
                    pass
                out.append(b)
            elif r.status_code == 403:
                b.exists = True
                out.append(b)
        except Exception as exc:
            b.error = str(exc)[:80]

    # Check $web (static website)
    try:
        w = Bucket(name=f"{account}/$web", provider="azure",
                    url=f"{base}/$web?restype=container&comp=list")
        r = requests.get(w.url, timeout=timeout, verify=False,
                          headers={"User-Agent": config.USER_AGENT})
        if r.status_code == 200 and "EnumerationResults" in r.text:
            w.exists = True
            w.public_list = True
            w.website_enabled = True
            out.append(w)
    except Exception:
        pass

    return out


# ===========================================================================
# DigitalOcean Spaces
# ===========================================================================

def check_do(name: str, check_write: bool = False,
              timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="do")
    # DO Spaces: <name>.<region>.digitaloceanspaces.com
    for region in ("nyc3", "sfo3", "sgp1", "ams3", "fra1", "blr1", "syd1"):
        url = f"https://{name}.{region}.digitaloceanspaces.com/"
        b.url = url
        b.region = region
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            b.status_code = r.status_code
            if r.status_code == 200:
                b.exists = True
                b.public_list = True
                b.files_count, b.sample_files = _parse_s3_list_xml(r.text)
                return b
            if r.status_code == 403:
                b.exists = True
                return b
        except Exception:
            continue
    return b


# ===========================================================================
# Linode Object Storage
# ===========================================================================

def check_linode(name: str, check_write: bool = False,
                  timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="linode")
    for region in ("us-east-1", "us-west-1", "eu-central-1",
                    "ap-south-1", "ap-southeast-1"):
        url = f"https://{name}.{region}.linodeobjects.com/"
        b.url = url
        b.region = region
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            b.status_code = r.status_code
            if r.status_code == 200:
                b.exists = True
                b.public_list = True
                b.files_count, b.sample_files = _parse_s3_list_xml(r.text)
                return b
            if r.status_code == 403:
                b.exists = True
                return b
        except Exception:
            continue
    return b


# ===========================================================================
# Backblaze B2
# ===========================================================================

def check_b2(name: str, check_write: bool = False,
              timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="b2")
    url = f"https://f000.backblazeb2.com/file/{name}/"
    b.url = url
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                          allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
        b.status_code = r.status_code
        if r.status_code == 200:
            b.exists = True
            b.public_list = True
            # B2 uses HTML index, не XML
            b.files_count = r.text.count("<a href=")
    except Exception as exc:
        b.error = str(exc)[:80]
    return b


# ===========================================================================
# Alibaba OSS
# ===========================================================================

def check_alibaba(name: str, check_write: bool = False,
                   timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="alibaba")
    for region in ("oss-us-west-1", "oss-us-east-1", "oss-eu-central-1",
                    "oss-ap-southeast-1", "oss-ap-northeast-1"):
        url = f"https://{name}.{region}.aliyuncs.com/"
        b.url = url
        b.region = region
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            b.status_code = r.status_code
            if r.status_code == 200:
                b.exists = True
                b.public_list = True
                b.files_count, b.sample_files = _parse_s3_list_xml(r.text)
                return b
            if r.status_code == 403:
                b.exists = True
                return b
        except Exception:
            continue
    return b


# ===========================================================================
# Cloudflare R2
# ===========================================================================

def check_r2(name: str, check_write: bool = False,
              timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="r2")
    # R2 — S3-compatible, but public URL is usually custom domain
    # Пробуем через S3 endpoint (может не сработать без аккаунта)
    url = f"https://{name}.r2.cloudflarestorage.com/"
    b.url = url
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                          allow_redirects=False,
                          headers={"User-Agent": config.USER_AGENT})
        b.status_code = r.status_code
        if r.status_code in (200, 403):
            b.exists = True
            if r.status_code == 200:
                b.public_list = True
    except Exception as exc:
        b.error = str(exc)[:80]
    return b


# ===========================================================================
# Generic S3-compatible (для расширения)
# ===========================================================================

def check_wasabi(name: str, check_write: bool = False,
                  timeout: int = TIMEOUT) -> Bucket:
    b = Bucket(name=name, provider="wasabi")
    for region in ("us-east-1", "us-east-2", "us-central-1",
                    "us-west-1", "eu-central-1", "ap-northeast-1"):
        url = f"https://s3.{region}.wasabisys.com/{name}/"
        b.url = url
        b.region = region
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                              allow_redirects=False,
                              headers={"User-Agent": config.USER_AGENT})
            b.status_code = r.status_code
            if r.status_code == 200:
                b.exists = True
                b.public_list = True
                b.files_count, b.sample_files = _parse_s3_list_xml(r.text)
                return b
            if r.status_code == 403:
                b.exists = True
                return b
        except Exception:
            continue
    return b


# ===========================================================================
# Генерация имён
# ===========================================================================

def _name_variants(domain: str,
                    include_wordlist: bool = False,
                    max_names: int = 200) -> list[str]:
    """Сгенерировать возможные имена бакетов."""
    base = extract_host(domain).lower()
    base = base.replace("www.", "")
    parts = base.split(".")
    company = parts[0] if parts else base
    if len(company) < 3:
        company = base.replace(".", "")
    company_clean = re.sub(r"[^a-z0-9]", "", company)

    names: set[str] = set()
    # Основные
    names.add(company_clean)
    names.add(base.replace(".", "-"))
    names.add(base.replace(".", ""))
    # Суффиксы
    for suf in COMMON_SUFFIXES:
        names.add(f"{company_clean}-{suf}")
        names.add(f"{company_clean}_{suf}")
        names.add(f"{company_clean}.{suf}")
    # Префиксы
    for pre in COMMON_PREFIXES:
        names.add(f"{pre}-{company_clean}")
        names.add(f"{pre}_{company_clean}")
    # Bare
    for bare in COMMON_BARE_NAMES:
        names.add(bare)

    # Wordlist
    if include_wordlist:
        wl = WORDLIST_DIR / "cloud_buckets.txt"
        if wl.exists():
            try:
                extra = [w.strip() for w in wl.read_text(
                    encoding="utf-8", errors="ignore").splitlines()
                    if w.strip() and not w.startswith("#")]
                for w in extra[:500]:
                    names.add(w)
                    names.add(f"{w}-{company_clean}")
                    names.add(f"{company_clean}-{w}")
            except Exception:
                pass

    # Filter
    out = sorted(
        n for n in names
        if 3 <= len(n) <= 63
        and re.match(r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$", n)
    )
    return out[:max_names]


# ===========================================================================
# Оркестратор
# ===========================================================================

PROVIDER_FUNCS: dict[str, Callable] = {
    "s3": check_s3,
    "gcs": check_gcs,
    "do": check_do,
    "linode": check_linode,
    "b2": check_b2,
    "alibaba": check_alibaba,
    "r2": check_r2,
    "wasabi": check_wasabi,
}


def scan_domain(domain: str, provider: str = "s3",
                 threads: int = MAX_WORKERS,
                 check_write: bool = False,
                 max_names: int = 200,
                 include_wordlist: bool = False,
                 save_findings: bool = True) -> list[Bucket]:
    """Сканировать домен по всем сгенерированным именам."""
    if not confirm_external(domain):
        return []

    names = _name_variants(domain, include_wordlist=include_wordlist,
                            max_names=max_names)
    console.print(
        f"[cyan]🔍 {provider.upper()}: проверяю {len(names)} имён "
        f"для {domain} (threads={threads})[/cyan]")

    check_fn = PROVIDER_FUNCS.get(provider)
    if not check_fn:
        console.print(f"[red]Провайдер {provider} не поддержан.[/red]")
        console.print(f"[dim]Доступно: {', '.join(PROVIDER_FUNCS)}[/dim]")
        return []

    results: list[Bucket] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(),
                  console=console) as p:
        task = p.add_task(f"scan {provider}", total=len(names))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(check_fn, n, check_write): n for n in names}
            for f in as_completed(futs):
                p.advance(task)
                try:
                    res = f.result()
                    if res and res.exists:
                        results.append(res)
                except Exception as exc:
                    log.warning("bucket %s: %s", futs[f], exc)

    _print_results(results, title=f"{provider.upper()} @ {domain}")

    # Findings → notes
    if save_findings:
        saved = sum(1 for b in results if _save_finding(b) > 0)
        if saved:
            console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("cloud_storage", f"{provider}:{domain}", {
        "checked": len(names),
        "found": len(results),
        "public_list": sum(1 for r in results if r.public_list),
        "public_write": sum(1 for r in results if r.public_write),
        "by_severity": {
            s: sum(1 for r in results if r.severity() == s)
            for s in ("critical", "high", "medium", "low")
        },
    })
    return results


def scan_azure_domain(domain: str, threads: int = 10
                       ) -> list[Bucket]:
    """Azure: перебор storage account + контейнеров."""
    if not confirm_external(domain):
        return []
    company = extract_host(domain).split(".")[0].lower()
    company_clean = re.sub(r"[^a-z0-9]", "", company)
    accounts: list[str] = []
    for suf in ("", "dev", "prod", "test", "stage", "backup", "data",
                "media", "static", "files", "storage", "001", "1",
                "prod", "prd", "acct", "sa", "str"):
        acc = f"{company_clean}{suf}"[:24]
        if 3 <= len(acc) <= 24:
            accounts.append(acc)

    console.print(f"[cyan]🔍 Azure: проверяю {len(accounts)} аккаунтов "
                  f"для {domain}[/cyan]")

    results: list[Bucket] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(check_azure, acc) for acc in accounts]
        for f in as_completed(futs):
            try:
                for b in f.result():
                    if b.exists:
                        results.append(b)
            except Exception:
                pass

    _print_results(results, title=f"Azure @ {domain}")

    saved = sum(1 for b in results if _save_finding(b) > 0)
    if saved:
        console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("cloud_storage", f"azure:{domain}", {
        "found": len(results),
        "buckets": [asdict(r) for r in results],
    })
    return results


def scan_all_providers(domain: str, threads: int = MAX_WORKERS,
                        check_write: bool = False) -> list[Bucket]:
    """Скан по всем S3-совместимым провайдерам."""
    results: list[Bucket] = []
    for provider in ("s3", "gcs", "do", "linode", "b2", "alibaba",
                      "r2", "wasabi"):
        try:
            res = scan_domain(domain, provider, threads, check_write,
                               max_names=100, save_findings=False)
            results.extend(res)
        except Exception as exc:
            console.print(f"[red]{provider}: {exc}[/red]")
    try:
        results.extend(scan_azure_domain(domain, threads // 3))
    except Exception as exc:
        console.print(f"[red]azure: {exc}[/red]")

    if results:
        console.print(f"\n[bold cyan]Всего найдено: {len(results)}"
                      f"[/bold cyan]")
        saved = sum(1 for b in results if _save_finding(b) > 0)
        if saved:
            console.print(f"[green]✓ Findings в notes: {saved}[/green]")

        # Notify
        try:
            from modules import notifier
            crit = sum(1 for b in results if b.severity() == "critical")
            high = sum(1 for b in results if b.severity() == "high")
            notifier.notify_all(
                f"☁  Cloud Storage: {domain}",
                f"Buckets found: {len(results)}\n"
                f"Critical: {crit}\nHigh: {high}")
        except Exception:
            pass

    return results


def check_one(name: str, provider: str = "s3",
               check_write: bool = False) -> Bucket | None:
    """Проверить один конкретный бакет."""
    if not confirm_external(name):
        return None
    check_fn = PROVIDER_FUNCS.get(provider)
    if not check_fn:
        console.print(f"[red]Провайдер {provider} не поддержан.[/red]")
        return None
    b = check_fn(name, check_write=check_write)
    if b.exists:
        _print_results([b], title=f"{name} ({provider})")
        _save_finding(b)
    else:
        console.print(f"[yellow]Бакет {name} не найден.[/yellow]")
    return b


def check_list(source: str, provider: str = "s3",
                threads: int = 20,
                check_write: bool = False) -> list[Bucket]:
    """Проверить список имён (файл или строка через запятую)."""
    import os
    names: list[str] = []
    if os.path.isfile(source):
        try:
            names = [l.strip() for l in open(source, encoding="utf-8",
                                              errors="ignore")
                     if l.strip() and not l.startswith("#")]
        except Exception as exc:
            console.print(f"[red]Не могу прочитать: {exc}[/red]")
            return []
    else:
        names = [n.strip() for n in source.split(",") if n.strip()]

    if not names:
        console.print("[red]Пустой список.[/red]")
        return []

    check_fn = PROVIDER_FUNCS.get(provider)
    if not check_fn:
        console.print(f"[red]Провайдер {provider} не поддержан.[/red]")
        return []

    console.print(f"[cyan]Проверяю {len(names)} имён ({provider})…[/cyan]")
    results: list[Bucket] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check_fn, n, check_write): n for n in names}
        for f in as_completed(futs):
            try:
                r = f.result()
                if r and r.exists:
                    results.append(r)
            except Exception:
                pass

    _print_results(results, title=f"Batch ({provider})")
    for b in results:
        _save_finding(b)

    db.save_scan("cloud_storage_batch", f"{provider}:{len(names)}", {
        "found": len(results),
        "buckets": [asdict(r) for r in results],
    })
    return results


# ===========================================================================
# Печать
# ===========================================================================

def _sev_style(sev: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }.get(sev, "white")


def _print_results(results: list[Bucket], title: str = "Buckets") -> None:
    if not results:
        console.print("[yellow]Открытых бакетов не найдено.[/yellow]")
        return

    table = Table(title=f"☁  {title} ({len(results)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Name", style="cyan", max_width=35)
    table.add_column("Prov", width=8)
    table.add_column("Region", width=12)
    table.add_column("List", width=5)
    table.add_column("Read", width=5)
    table.add_column("Write", width=6)
    table.add_column("ACL", width=5)
    table.add_column("Files", width=6)
    table.add_column("Sev", width=10)
    for i, b in enumerate(sorted(results,
                                  key=lambda x: x.severity(),
                                  reverse=True), 1):
        sev = b.severity()
        sty = _sev_style(sev)
        table.add_row(
            str(i), b.name, b.provider, (b.region or "—")[:12],
            "✓" if b.public_list else "—",
            "✓" if b.public_read else "—",
            "[red]✓[/red]" if b.public_write else "—",
            "✓" if b.public_acl else "—",
            str(b.files_count),
            f"[{sty}]{sev.upper()}[/{sty}]",
        )
    console.print(table)

    for b in results:
        if b.public_write:
            console.print(f"\n[bold red]⚠ PUBLIC WRITE: {b.url}[/bold red]")
        if b.sample_files:
            console.print(f"\n[cyan]{b.url}[/cyan]")
            console.print(f"  [dim]Файлы ({b.files_count}):[/dim]")
            for f in b.sample_files[:5]:
                console.print(f"    • {f}")
        if b.index_title:
            console.print(f"  [green]index.html:[/green] {b.index_title}")


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(results: list[Bucket],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(STORAGE_DIR / f"buckets_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(b) for b in results], indent=2,
                        ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(results: list[Bucket],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(STORAGE_DIR / f"buckets_{ts}.csv")
    cols = ["name", "provider", "url", "region", "exists", "public_list",
            "public_read", "public_write", "public_acl", "public_policy",
            "cors_enabled", "website_enabled", "files_count"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for b in results:
                w.writerow([str(getattr(b, c, "")) for c in cols])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(results: list[Bucket],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(STORAGE_DIR / f"buckets_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Cloud Storage Enumeration</title>",
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
        f"<h1>☁  Cloud Storage ({len(results)})</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>Name</th><th>Provider</th><th>Region</th>"
        "<th>List</th><th>Read</th><th>Write</th><th>ACL</th>"
        "<th>Files</th><th>Sev</th></tr>",
    ]
    for b in sorted(results, key=lambda x: x.severity(), reverse=True):
        sev = b.severity()
        parts.append(
            f"<tr><td>{html_mod.escape(b.name)}</td>"
            f"<td>{html_mod.escape(b.provider)}</td>"
            f"<td>{html_mod.escape(b.region or '—')}</td>"
            f"<td>{'✓' if b.public_list else '—'}</td>"
            f"<td>{'✓' if b.public_read else '—'}</td>"
            f"<td>{'✓' if b.public_write else '—'}</td>"
            f"<td>{'✓' if b.public_acl else '—'}</td>"
            f"<td>{b.files_count}</td>"
            f"<td class='{sev}'>{sev.upper()}</td></tr>"
        )
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

def cli_scan(domain: str, provider: str = "s3", threads: int = 30,
              check_write: bool = False) -> None:
    results = scan_domain(domain, provider=provider, threads=threads,
                           check_write=check_write)
    if results and Confirm.ask("Экспорт (JSON + HTML)?", default=False):
        export_json(results)
        export_html(results)


def cli_scan_all(domain: str, threads: int = 30,
                  check_write: bool = False) -> None:
    results = scan_all_providers(domain, threads, check_write)
    if results and Confirm.ask("Экспорт (JSON + HTML)?", default=False):
        export_json(results)
        export_html(results)


def cli_check(name: str, provider: str = "s3") -> None:
    check_one(name, provider)


def cli_batch(source: str, provider: str = "s3",
               threads: int = 20) -> None:
    check_list(source, provider, threads)


def cli_azure(account: str) -> None:
    results = check_azure(account)
    _print_results(results, title=f"Azure {account}")
    for b in results:
        _save_finding(b)


def cli_providers() -> None:
    """Показать список поддерживаемых провайдеров."""
    t = Table(title=f"Cloud Storage Providers ({len(PROVIDER_FUNCS) + 2})")
    t.add_column("Slug", style="cyan")
    t.add_column("Name", style="white")
    t.add_column("URL pattern")
    providers_info = [
        ("s3", "AWS S3", "*.s3.amazonaws.com"),
        ("gcs", "Google Cloud Storage", "storage.googleapis.com/*"),
        ("azure", "Azure Blob Storage", "*.blob.core.windows.net/*"),
        ("do", "DigitalOcean Spaces", "*.{region}.digitaloceanspaces.com"),
        ("linode", "Linode Object Storage", "*.{region}.linodeobjects.com"),
        ("b2", "Backblaze B2", "f000.backblazeb2.com/file/*"),
        ("alibaba", "Alibaba OSS", "*.{region}.aliyuncs.com"),
        ("r2", "Cloudflare R2", "*.r2.cloudflarestorage.com"),
        ("wasabi", "Wasabi", "s3.{region}.wasabisys.com/*"),
        ("firebase", "Firebase Storage",
         "firebasestorage.googleapis.com/v0/b/*"),
    ]
    for slug, name, pattern in providers_info:
        t.add_row(slug, name, pattern)
    console.print(t)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]☁  Cloud Storage Enumeration[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Скан домена — AWS S3"),
        ("2", "Скан домена — Google Cloud Storage"),
        ("3", "Скан домена — Azure Blob Storage"),
        ("4", "Скан домена — DigitalOcean Spaces"),
        ("5", "Скан домена — Linode Object Storage"),
        ("6", "Скан домена — Backblaze B2"),
        ("7", "Скан домена — ВСЕ провайдеры"),
        ("8", "Проверить один бакет"),
        ("9", "Проверить список (файл / через запятую)"),
        ("10", "Список провайдеров"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования и bug bounty."
                  "[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c in ("1", "2", "4", "5", "6"):
        pmap = {"1": "s3", "2": "gcs", "4": "do", "5": "linode", "6": "b2"}
        provider = pmap[c]
        domain = Prompt.ask("Домен (например example.com)")
        threads = IntPrompt.ask("Потоков", default=30)
        cw = Confirm.ask("Проверять право на запись (медленнее)?",
                          default=False)
        scan_domain(domain, provider, threads, check_write=cw)
    elif c == "3":
        domain = Prompt.ask("Домен")
        scan_azure_domain(domain)
    elif c == "7":
        domain = Prompt.ask("Домен")
        threads = IntPrompt.ask("Потоков", default=30)
        cli_scan_all(domain, threads)
    elif c == "8":
        name = Prompt.ask("Имя бакета")
        prov = Prompt.ask("Провайдер",
                          choices=list(PROVIDER_FUNCS.keys()),
                          default="s3")
        check_one(name, prov)
    elif c == "9":
        src = Prompt.ask("Файл или список имён через запятую")
        prov = Prompt.ask("Провайдер",
                          choices=list(PROVIDER_FUNCS.keys()),
                          default="s3")
        check_list(src, prov)
    elif c == "10":
        cli_providers()