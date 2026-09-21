"""
GraphQL / API Discovery.
Author: idqwixxa

Возможности:
    - Поиск GraphQL-endpoint'ов (общие пути)
    - Introspection query (полный schema dump)
    - Field suggestions attack (когда introspection отключён)
    - Поиск API endpoints в JS/HTML (regex)
    - Swagger / OpenAPI discovery
    - REST endpoint enumeration (типовые пути)
    - Сохранение schema в reports/gql_schema_*.json
"""
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ===========================================================================
# ГрафQL
# ===========================================================================

COMMON_GQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/index.php?graphql", "/graphql/console", "/graphql.php",
    "/altair", "/playground", "/api/v1/graphql", "/api/query",
    "/wp-graphql", "/graphql/v1",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields {
        name
        description
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
""".strip()


@dataclass
class GQLEndpoint:
    url: str
    method: str = "POST"
    status: int = 0
    introspection: bool = False
    schema: dict | None = None
    type_count: int = 0
    query_count: int = 0
    mutation_count: int = 0
    error: str = ""


def _gql_probe(url: str, timeout: int = 10) -> GQLEndpoint:
    """Проверить endpoint на GraphQL."""
    result = GQLEndpoint(url=url)

    # 1. Простой POST с query { __typename }
    try:
        r = requests.post(
            url,
            json={"query": "{__typename}"},
            timeout=timeout, verify=False,
            headers={"User-Agent": config.USER_AGENT,
                     "Content-Type": "application/json"},
        )
        result.status = r.status_code
        if r.status_code not in (200, 400):
            result.error = f"status {r.status_code}"
            return result
        try:
            data = r.json()
            if "data" in data or "errors" in data:
                # endpoint отвечает JSON-RPC стилем → вероятно GraphQL
                pass
            else:
                result.error = "not gql"
                return result
        except Exception:
            result.error = "not json"
            return result
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)[:60]
        return result

    # 2. Introspection
    try:
        r = requests.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            timeout=timeout + 10, verify=False,
            headers={"User-Agent": config.USER_AGENT,
                     "Content-Type": "application/json"},
        )
        if r.status_code == 200:
            data = r.json()
            if "data" in data and data["data"] and "__schema" in data["data"]:
                result.introspection = True
                result.schema = data["data"]["__schema"]
                schema = result.schema
                types = schema.get("types", []) or []
                result.type_count = len(types)
                qt = schema.get("queryType") or {}
                mt = schema.get("mutationType") or {}
                # Считаем поля
                for t in types:
                    if t.get("name") == qt.get("name"):
                        result.query_count = len(t.get("fields", []) or [])
                    if t.get("name") == mt.get("name"):
                        result.mutation_count = len(t.get("fields", []) or [])
    except Exception as exc:  # noqa: BLE001
        log.debug("introspection %s: %s", url, exc)

    return result


def discover_gql(base: str, threads: int = 20) -> list[GQLEndpoint]:
    """Перебрать общие пути GraphQL."""
    base = normalize_url(base).rstrip("/")
    found: list[GQLEndpoint] = []

    def _one(path: str) -> GQLEndpoint | None:
        url = urljoin(base + "/", path.lstrip("/"))
        ep = _gql_probe(url)
        if ep.status in (200, 400) and not ep.error:
            return ep
        # Также сохраним endpoints с включённым introspection даже если
        # основной запрос вернул что-то странное
        if ep.introspection:
            return ep
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_one, p) for p in COMMON_GQL_PATHS]
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)

    return found


def show_gql_endpoints(endpoints: list[GQLEndpoint]) -> None:
    """Показать найденные endpoint'ы."""
    if not endpoints:
        console.print("[yellow]GraphQL endpoints не найдены.[/yellow]")
        return
    table = Table(title=f"🔎 GraphQL endpoints ({len(endpoints)})")
    table.add_column("URL", style="cyan", max_width=60)
    table.add_column("Status", width=7)
    table.add_column("Introspection", width=14)
    table.add_column("Types", width=6)
    table.add_column("Q", width=5)
    table.add_column("M", width=5)
    for ep in endpoints:
        intro = "[green]✓ вкл[/green]" if ep.introspection else "[dim]выкл[/dim]"
        table.add_row(ep.url, str(ep.status), intro,
                      str(ep.type_count), str(ep.query_count),
                      str(ep.mutation_count))
    console.print(table)


def dump_schema(schema: dict, name: str = "schema") -> Path | None:
    """Сохранить schema в файл."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"gql_{name}_{ts}.json"
    try:
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        console.print(f"[green]✓ Schema: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка сохранения: {exc}[/red]")
        return None


def show_schema_summary(schema: dict) -> None:
    """Показать сводку схемы: queries, mutations, types."""
    types = schema.get("types", []) or []
    qt = (schema.get("queryType") or {}).get("name")
    mt = (schema.get("mutationType") or {}).get("name")

    # Queries
    q_fields = []
    m_fields = []
    for t in types:
        if t.get("name") == qt:
            q_fields = t.get("fields") or []
        if t.get("name") == mt:
            m_fields = t.get("fields") or []

    if q_fields:
        table = Table(title=f"📖 Queries ({len(q_fields)})")
        table.add_column("Field", style="cyan")
        table.add_column("Args", style="yellow", max_width=40)
        table.add_column("Return", style="green", max_width=30)
        for f_ in q_fields[:30]:
            args = ", ".join(a.get("name", "") for a in (f_.get("args") or []))
            rtype = _type_name(f_.get("type"))
            table.add_row(f_.get("name", ""), args[:40], rtype)
        console.print(table)

    if m_fields:
        table = Table(title=f"✏️  Mutations ({len(m_fields)})",
                      border_style="magenta")
        table.add_column("Field", style="cyan")
        table.add_column("Args", style="yellow", max_width=40)
        for f_ in m_fields[:30]:
            args = ", ".join(a.get("name", "") for a in (f_.get("args") or []))
            table.add_row(f_.get("name", ""), args[:40])
        console.print(table)


def _type_name(t: dict | None) -> str:
    """Получить человекочитаемое имя типа."""
    if not t:
        return "?"
    kind = t.get("kind", "")
    name = t.get("name", "")
    if kind == "NON_NULL":
        return _type_name(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + _type_name(t.get("ofType")) + "]"
    return name or "?"


# ===========================================================================
# Suggestions attack (когда introspection выключён)
# ===========================================================================

def suggestions_attack(url: str, timeout: int = 10) -> list[str]:
    """
    Пытаемся получить имена полей через suggestions GraphQL.
    При запросе несуществующего поля — GraphQL возвращает
    'Did you mean' или 'Cannot query field... Did you mean "X"?'
    """
    url = normalize_url(url)
    fields: set[str] = set()
    probes = ["us", "use", "user", "users", "me", "query", "admin",
              "auth", "login", "product", "order", "item", "node",
              "account", "profile", "post", "comment", "search"]
    for p in probes:
        try:
            r = requests.post(
                url,
                json={"query": f"{{ {p} }}"},
                timeout=timeout, verify=False,
                headers={"User-Agent": config.USER_AGENT,
                         "Content-Type": "application/json"},
            )
            if r.status_code != 200:
                continue
            text = r.text
            # "Did you mean" + имена
            for m in re.finditer(r'Did you mean\s+["\']?([a-zA-Z_]\w+)',
                                 text):
                fields.add(m.group(1))
            # Прочие подсказки
            for m in re.finditer(r'["\']([a-zA-Z_]\w*)["\']',
                                 text):
                cand = m.group(1)
                if len(cand) > 2 and cand.isidentifier():
                    fields.add(cand)
        except Exception:
            continue
    # Само поле из probes тоже добавим — оно часто существует
    fields |= set(probes)
    return sorted(fields)


# ===========================================================================
# API Discovery (JS/HTML)
# ===========================================================================

API_URL_REGEXES = [
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-/]+)["']"""),
    re.compile(r"""["'](/v\d+/[a-zA-Z0-9_\-/]+)["']"""),
    re.compile(r"""["'](https?://[^"']+/api/[^"']+)["']"""),
    re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
    re.compile(r"""axios\.[a-z]+\(\s*["']([^"']+)["']"""),
    re.compile(r"""\$\.(?:get|post|ajax)\(\s*["']([^"']+)["']"""),
    re.compile(r"""["'](/graphql[^"']*)["']"""),
]

SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json",
    "/swagger-ui.html", "/swagger-ui/",
    "/api/swagger.json", "/api/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi.json",
    "/redoc", "/docs", "/api/docs",
]

REST_COMMON_PATHS = [
    "/api/v1/users", "/api/v1/user", "/api/users", "/api/user",
    "/api/v1/items", "/api/items", "/api/v1/products",
    "/api/v1/orders", "/api/v1/auth", "/api/auth",
    "/api/v1/login", "/api/login", "/api/v1/register",
    "/api/v1/admin", "/api/admin", "/api/v1/health",
    "/api/v1/status", "/api/v1/version", "/api/v1/config",
    "/api/v1/me", "/api/me", "/api/whoami",
]


def fetch_page(url: str, timeout: int = 10) -> str:
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        return r.text
    except Exception:
        return ""


def discover_js_apis(base: str, max_js: int = 30) -> dict:
    """
    Пройти по HTML, вытащить JS-файлы, в них найти API-URL'ы.
    """
    base = normalize_url(base).rstrip("/")
    html = fetch_page(base)
    if not html:
        return {"js_files": [], "endpoints": [], "errors": []}

    soup = BeautifulSoup(html, "html.parser")
    js_files: list[str] = []
    for s in soup.find_all("script", src=True):
        src = s["src"]
        if src.endswith(".js") or ".js?" in src:
            full = urljoin(base + "/", src)
            js_files.append(full)

    endpoints: set[str] = set()
    errors: list[str] = []

    # Эндпоинты из HTML
    for regex in API_URL_REGEXES:
        for m in regex.finditer(html):
            endpoints.add(m.group(1))

    # Из JS-файлов
    for js_url in js_files[:max_js]:
        content = fetch_page(js_url, timeout=8)
        if not content:
            errors.append(js_url)
            continue
        for regex in API_URL_REGEXES:
            for m in regex.finditer(content):
                endpoints.add(m.group(1))

    return {
        "js_files": js_files,
        "endpoints": sorted(endpoints),
        "errors": errors,
    }


def discover_swagger(base: str, threads: int = 20) -> list[dict]:
    """Проверить общие пути swagger / openapi."""
    base = normalize_url(base).rstrip("/")
    found: list[dict] = []

    def _one(path: str) -> dict | None:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = requests.get(url, timeout=8, verify=False,
                             headers={"User-Agent": config.USER_AGENT},
                             allow_redirects=True)
            if r.status_code != 200:
                return None
            text = r.text[:500]
            if (("swagger" in text.lower()) or ("openapi" in text.lower())
                    or ("API" in text and "version" in text.lower())):
                info = {"url": url, "status": r.status_code,
                        "size": len(r.content), "type": "?"}
                try:
                    data = r.json()
                    info["type"] = "json"
                    if "openapi" in data:
                        info["version"] = data["openapi"]
                    elif "swagger" in data:
                        info["version"] = data["swagger"]
                    paths = data.get("paths", {}) or {}
                    info["paths"] = len(paths)
                except Exception:
                    info["type"] = "yaml/html"
                return info
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_one, p) for p in SWAGGER_PATHS]
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)

    return found


def discover_rest(base: str, threads: int = 20) -> list[dict]:
    """Найти REST endpoints из COMMON_PATHS."""
    base = normalize_url(base).rstrip("/")
    found: list[dict] = []

    def _one(path: str) -> dict | None:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = requests.head(url, timeout=6, verify=False,
                              headers={"User-Agent": config.USER_AGENT},
                              allow_redirects=False)
            if r.status_code in (200, 401, 403, 405, 301, 302):
                return {"url": url, "status": r.status_code,
                        "content_type": r.headers.get("Content-Type", "")}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_one, p) for p in REST_COMMON_PATHS]
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
    return found


# ===========================================================================
# Высокоуровневые сценарии
# ===========================================================================

def full_scan(target: str) -> dict:
    """Полный скан: gql + swagger + rest + js."""
    if not confirm_external(target):
        return {}

    url = normalize_url(target)
    console.print(f"[cyan]🔎 API Discovery: {url}[/cyan]\n")

    # 1. GraphQL
    console.print("[cyan]→ Поиск GraphQL endpoints…[/cyan]")
    gql_eps = discover_gql(url)
    show_gql_endpoints(gql_eps)

    # Сохранение схем
    for ep in gql_eps:
        if ep.introspection and ep.schema:
            show_schema_summary(ep.schema)
            dump_schema(ep.schema, name=urlparse(ep.url).path
                        .replace("/", "_") or "root")

    # 2. Swagger
    console.print("\n[cyan]→ Поиск Swagger / OpenAPI…[/cyan]")
    swagger = discover_swagger(url)
    if swagger:
        t = Table(title=f"📚 Swagger/OpenAPI ({len(swagger)})")
        t.add_column("URL", style="cyan", max_width=50)
        t.add_column("Type")
        t.add_column("Version")
        t.add_column("Paths", width=6)
        for s in swagger:
            t.add_row(s["url"], s.get("type", "?"),
                      str(s.get("version", "—")),
                      str(s.get("paths", "—")))
        console.print(t)
    else:
        console.print("[dim]Не найдено.[/dim]")

    # 3. REST
    console.print("\n[cyan]→ REST endpoint'ы…[/cyan]")
    rest = discover_rest(url)
    if rest:
        t = Table(title=f"🌐 REST endpoints ({len(rest)})")
        t.add_column("URL", style="cyan", max_width=60)
        t.add_column("Status", width=6)
        t.add_column("Content-Type", max_width=25)
        for r in rest:
            t.add_row(r["url"], str(r["status"]),
                      r.get("content_type", "")[:25])
        console.print(t)
    else:
        console.print("[dim]Не найдено.[/dim]")

    # 4. JS endpoints
    console.print("\n[cyan]→ API в JS/HTML…[/cyan]")
    js = discover_js_apis(url)
    if js["endpoints"]:
        t = Table(title=f"📜 Endpoints в JS ({len(js['endpoints'])})")
        t.add_column("#", width=4)
        t.add_column("Endpoint", style="cyan", max_width=80)
        for i, e in enumerate(js["endpoints"][:40], 1):
            t.add_row(str(i), e)
        console.print(t)
    console.print(f"[dim]JS-файлов проанализировано: "
                  f"{len(js['js_files'])}[/dim]")

    result = {
        "url": url,
        "gql_endpoints": [asdict(e) for e in gql_eps],
        "swagger": swagger,
        "rest": rest,
        "js_files": js["js_files"],
        "js_endpoints": js["endpoints"],
    }

    db.save_scan("api_discovery", url, {
        "gql": len(gql_eps),
        "swagger": len(swagger),
        "rest": len(rest),
        "js_endpoints": len(js["endpoints"]),
    })

    # Экспорт JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = urlparse(url).hostname or "target"
    safe = safe.replace(".", "_")
    out = REPORT_DIR / f"api_{safe}_{ts}.json"
    try:
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False,
                                  default=str), encoding="utf-8")
        console.print(f"\n[green]✓ Отчёт: {out}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Ошибка экспорта: {exc}[/yellow]")

    return result


# ===========================================================================
# CLI-функции
# ===========================================================================

def cli_gql(target: str) -> None:
    """Только поиск GraphQL endpoint'ов."""
    if not confirm_external(target):
        return
    url = normalize_url(target)
    console.print(f"[cyan]🔎 GraphQL: {url}[/cyan]")
    eps = discover_gql(url)
    show_gql_endpoints(eps)
    for ep in eps:
        if ep.introspection and ep.schema:
            show_schema_summary(ep.schema)
            dump_schema(ep.schema)


def cli_gql_introspect(endpoint: str) -> None:
    """Introspection конкретного endpoint'а."""
    if not confirm_external(endpoint):
        return
    console.print(f"[cyan]🔎 Introspection: {endpoint}[/cyan]")
    ep = _gql_probe(normalize_url(endpoint))
    if not ep.introspection:
        console.print("[yellow]Introspection отключён или endpoint "
                      "не GraphQL.[/yellow]")
        # Попробуем suggestions
        if Confirm.ask("Попробовать suggestions attack?", default=False):
            fields = suggestions_attack(endpoint)
            console.print(f"[cyan]Найдено возможных полей: {len(fields)}[/cyan]")
            for f_ in fields[:50]:
                console.print(f"  • {f_}")
        return
    console.print("[green]✓ Introspection активен![/green]")
    show_schema_summary(ep.schema or {})
    dump_schema(ep.schema or {})


def cli_swagger(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    found = discover_swagger(url)
    if not found:
        console.print("[yellow]Swagger/OpenAPI не найден.[/yellow]")
        return
    t = Table(title=f"📚 Swagger/OpenAPI ({len(found)})")
    t.add_column("URL", style="cyan")
    t.add_column("Type")
    t.add_column("Version")
    t.add_column("Paths")
    for s in found:
        t.add_row(s["url"], s.get("type", "?"),
                  str(s.get("version", "—")),
                  str(s.get("paths", "—")))
    console.print(t)


def cli_rest(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    found = discover_rest(url)
    if not found:
        console.print("[yellow]REST endpoints не найдены.[/yellow]")
        return
    t = Table(title=f"🌐 REST endpoints ({len(found)})")
    t.add_column("URL", style="cyan")
    t.add_column("Status")
    t.add_column("Content-Type")
    for r in found:
        t.add_row(r["url"], str(r["status"]),
                  r.get("content_type", "")[:30])
    console.print(t)


def cli_js(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    js = discover_js_apis(url)
    console.print(f"[cyan]JS-файлов: {len(js['js_files'])}[/cyan]")
    for f_ in js["js_files"][:20]:
        console.print(f"  [dim]{f_}[/dim]")
    console.print(f"\n[cyan]Найдено endpoint'ов: "
                  f"{len(js['endpoints'])}[/cyan]")
    for e in js["endpoints"][:50]:
        console.print(f"  [green]{e}[/green]")


def cli_full(target: str) -> None:
    full_scan(target)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔎 GraphQL / API Discovery[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (GraphQL + Swagger + REST + JS)"),
        ("2", "Поиск GraphQL endpoints"),
        ("3", "Introspection конкретного endpoint'а"),
        ("4", "Поиск Swagger / OpenAPI"),
        ("5", "REST endpoint enumeration"),
        ("6", "Поиск API-URL'ов в JS/HTML"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_full(Prompt.ask("URL (например https://example.com)"))
    elif c == "2":
        cli_gql(Prompt.ask("URL"))
    elif c == "3":
        cli_gql_introspect(Prompt.ask("GraphQL endpoint"))
    elif c == "4":
        cli_swagger(Prompt.ask("URL"))
    elif c == "5":
        cli_rest(Prompt.ask("URL"))
    elif c == "6":
        cli_js(Prompt.ask("URL"))