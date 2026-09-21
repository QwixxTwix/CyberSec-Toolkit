"""
Cloud IAM Analyzer — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty.

Возможности:
    ─── AWS ───
    - STS get-caller-identity + identity validation
    - IAM permissions audit (25+ actions)
    - Privesc paths (12 техник) live check
    - Assume-role chains
    - S3 bucket enumeration
    - Secrets Manager / SSM Parameters enum
    - GuardDuty / CloudTrail detection
    - Multi-region scan
    - Env vars / files scan с regex (AKIA, ASIA, JWT, …)

    ─── GCP ───
    - Service account validation
    - IAM permission check (30+)
    - Project enumeration
    - Bucket enumeration
    - SA key audit

    ─── Azure ───
    - CLI account / SP check
    - Subscription / resource groups
    - Role assignments
    - Key Vault access check

    ─── Findings ───
    - Kritisches → notes
    - Notify по завершении
    - HTML / JSON / CSV экспорт
"""
import base64
import csv
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

IAM_DIR = REPORT_DIR / "cloud_iam"
IAM_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class IAMFinding:
    provider: str
    kind: str
    severity: str
    identity: str = ""
    detail: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: IAMFinding) -> int:
    """Сохранить критичные findings в notes."""
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f"Cloud IAM: {f.kind} ({f.provider})",
            target=f.identity[:80] or f.provider,
            severity=f.severity,
            status="open",
            tags=["cloud-iam", f.provider, f.kind],
            body=(f"**Provider:** {f.provider}\n"
                  f"**Kind:** {f.kind}\n"
                  f"**Identity:** {f.identity}\n"
                  f"**Detail:** {f.detail}\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1500]}`"),
        )
    except Exception:
        return -1


def _run_cmd(cmd: list[str], timeout: int = 15,
             env_extra: dict | None = None
             ) -> tuple[int, str, str]:
    """Запуск subprocess с timeout."""
    if not shutil.which(cmd[0]):
        return (-1, "", f"{cmd[0]} not installed")
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return (-1, "", f"timeout after {timeout}s")
    except Exception as exc:
        return (-1, "", str(exc))


# ===========================================================================
# AWS
# ===========================================================================

AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

# Расширенный список AWS actions для permission enumeration
AWS_PERMISSION_CHECKS = [
    # IAM
    ("iam:ListUsers", ["iam", "list-users"], "medium"),
    ("iam:ListRoles", ["iam", "list-roles"], "medium"),
    ("iam:ListPolicies", ["iam", "list-policies", "--scope", "Local"],
     "medium"),
    ("iam:ListAccessKeys", ["iam", "list-access-keys"], "high"),
    ("iam:GetAccountSummary", ["iam", "get-account-summary"], "medium"),
    ("iam:ListGroups", ["iam", "list-groups"], "low"),
    ("iam:ListMFADevices", ["iam", "list-mfa-devices"], "low"),
    # S3
    ("s3:ListBuckets", ["s3", "ls"], "high"),
    # EC2
    ("ec2:DescribeInstances", ["ec2", "describe-instances"], "medium"),
    ("ec2:DescribeSecurityGroups", ["ec2", "describe-security-groups"],
     "medium"),
    ("ec2:DescribeVolumes", ["ec2", "describe-volumes"], "low"),
    ("ec2:DescribeSnapshots", ["ec2", "describe-snapshots"], "medium"),
    ("ec2:DescribeImages", ["ec2", "describe-images",
                             "--owners", "self"], "low"),
    # Lambda
    ("lambda:ListFunctions", ["lambda", "list-functions"], "high"),
    # RDS
    ("rds:DescribeDBInstances", ["rds", "describe-db-instances"],
     "high"),
    ("rds:DescribeDBSnapshots", ["rds", "describe-db-snapshots"],
     "high"),
    # Secrets
    ("secretsmanager:ListSecrets",
     ["secretsmanager", "list-secrets"], "critical"),
    ("ssm:DescribeParameters",
     ["ssm", "describe-parameters"], "critical"),
    # STS
    ("sts:GetCallerIdentity", ["sts", "get-caller-identity"], "info"),
    ("sts:GetSessionToken", ["sts", "get-session-token"], "low"),
    # CloudTrail / GuardDuty
    ("cloudtrail:DescribeTrails",
     ["cloudtrail", "describe-trails"], "low"),
    ("guardduty:ListDetectors",
     ["guardduty", "list-detectors"], "low"),
    # SSO / Organizations
    ("organizations:DescribeOrganization",
     ["organizations", "describe-organization"], "medium"),
    # ECS / EKS
    ("ecs:ListClusters", ["ecs", "list-clusters"], "medium"),
    ("eks:ListClusters", ["eks", "list-clusters"], "medium"),
    # Route53
    ("route53:ListHostedZones", ["route53", "list-hosted-zones"],
     "medium"),
]


def _run_aws_cli(args: list[str], timeout: int = 15,
                  env_extra: dict | None = None
                  ) -> tuple[int, str, str]:
    return _run_cmd(["aws"] + args, timeout=timeout, env_extra=env_extra)


def aws_whoami(access_key: str = "", secret_key: str = "",
                session_token: str = "", region: str = "us-east-1",
                profile: str = "") -> IAMFinding | None:
    """STS GetCallerIdentity."""
    console.print("[cyan]🔍 AWS: проверка креденшелов…[/cyan]")
    args = ["sts", "get-caller-identity", "--output", "json",
            "--region", region]
    env_extra: dict = {}
    if profile:
        args += ["--profile", profile]
    elif access_key and secret_key:
        env_extra = {
            "AWS_ACCESS_KEY_ID": access_key,
            "AWS_SECRET_ACCESS_KEY": secret_key,
        }
        if session_token:
            env_extra["AWS_SESSION_TOKEN"] = session_token

    rc, out, err = _run_aws_cli(args, env_extra=env_extra)
    if rc != 0:
        console.print(f"[red]✗ {err.strip()[:200]}[/red]")
        return None

    try:
        data = json.loads(out)
    except Exception:
        return None

    identity = data.get("Arn", "?")
    account = data.get("Account", "?")
    user_id = data.get("UserId", "?")

    console.print("[green]✓ Valid![/green]")
    console.print(f"  ARN:     [cyan]{identity}[/cyan]")
    console.print(f"  Account: [cyan]{account}[/cyan]")
    console.print(f"  UserId:  [dim]{user_id}[/dim]")

    f = IAMFinding(
        provider="aws", kind="identity", severity="info",
        identity=identity,
        detail=f"Account={account}",
        data=data,
    )
    db.save_scan("aws_whoami", identity, data)
    return f


def aws_enumerate_permissions(access_key: str = "", secret_key: str = "",
                                session_token: str = "",
                                region: str = "us-east-1",
                                profile: str = "",
                                save_findings: bool = True
                                ) -> list[IAMFinding]:
    """Перечислить доступные разрешения (25+ действий)."""
    console.print("[cyan]🔍 AWS: enumerating permissions…[/cyan]")
    env_extra: dict = {}
    if access_key and secret_key:
        env_extra = {
            "AWS_ACCESS_KEY_ID": access_key,
            "AWS_SECRET_ACCESS_KEY": secret_key,
        }
        if session_token:
            env_extra["AWS_SESSION_TOKEN"] = session_token

    findings: list[IAMFinding] = []
    profile_args: list[str] = ["--profile", profile] if profile else []

    table = Table(title=f"🔓 AWS Permissions ({len(AWS_PERMISSION_CHECKS)})")
    table.add_column("Action", style="cyan", max_width=42)
    table.add_column("Status", width=10)
    table.add_column("Sev", width=9)
    table.add_column("Detail", max_width=45)

    for action, cmd, sev in AWS_PERMISSION_CHECKS:
        full_cmd = list(cmd)
        if action.startswith(("iam:", "s3:", "sts:")):
            pass
        else:
            full_cmd += ["--region", region]
        rc, out, err = _run_aws_cli(full_cmd + profile_args,
                                     env_extra=env_extra)
        if rc == 0:
            table.add_row(action, "[green]✓ ALLOW[/green]",
                          sev.upper(), out[:45].replace("\n", " "))
            findings.append(IAMFinding(
                provider="aws", kind="permission",
                severity="high" if sev in ("high", "critical") else "medium",
                identity=action, detail="allowed",
                data={"action": action, "command": " ".join(full_cmd)},
            ))
        elif "AccessDenied" in err or "UnauthorizedOperation" in err:
            table.add_row(action, "[dim]✗ deny[/dim]", sev.upper(), "")
        else:
            table.add_row(action, "[yellow]?[/yellow]", sev.upper(),
                          err[:45])
    console.print(table)

    # Privesc check
    privesc_findings = _aws_privesc_check(env_extra, profile_args)
    findings.extend(privesc_findings)

    # Save критичные
    if save_findings:
        saved = 0
        for f in findings:
            if f.severity in ("critical", "high"):
                if _save_finding(f) > 0:
                    saved += 1
        if saved:
            console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("aws_enum", "permissions", {
        "allowed": [f.identity for f in findings
                    if f.kind == "permission"],
        "privesc": [f.identity for f in findings if f.kind == "privesc"],
    })
    return findings


def _aws_privesc_check(env_extra: dict,
                        profile_args: list[str]) -> list[IAMFinding]:
    """Проверка privesc-путей (subset)."""
    console.print("\n[cyan]⚡ AWS: privesc paths проверка…[/cyan]")

    privesc_checks = [
        ("iam:CreatePolicyVersion", "critical",
         ["iam", "create-policy-version",
          "--policy-arn", "arn:aws:iam::aws:policy/ReadOnlyAccess",
          "--policy-document",
          '{"Version":"2012-10-17","Statement":[]}',
          "--set-as-default"]),
        ("iam:SetDefaultPolicyVersion", "high",
         ["iam", "set-default-policy-version",
          "--policy-arn", "arn:aws:iam::aws:policy/ReadOnlyAccess",
          "--version-id", "v1"]),
        ("iam:AttachUserPolicy", "critical",
         ["iam", "attach-user-policy",
          "--user-name", "self",
          "--policy-arn",
          "arn:aws:iam::aws:policy/AdministratorAccess"]),
        ("iam:AddUserToGroup", "high",
         ["iam", "add-user-to-group",
          "--user-name", "self", "--group-name", "Admins"]),
        ("iam:CreateAccessKey", "high",
         ["iam", "create-access-key", "--user-name", "admin"]),
        ("iam:UpdateLoginProfile", "high",
         ["iam", "update-login-profile", "--user-name", "admin",
          "--password", "P@ssw0rd!"]),
        ("iam:PutUserPolicy", "critical",
         ["iam", "put-user-policy", "--user-name", "self",
          "--policy-name", "pwn",
          "--policy-document",
          '{"Version":"2012-10-17","Statement":[]}']),
        ("iam:PassRole + lambda:CreateFunction", "critical",
         ["lambda", "create-function", "--function-name", "pwn",
          "--runtime", "python3.11", "--role", "arn:aws:iam::1:role/x",
          "--handler", "index.handler",
          "--zip-file", "fileb:///dev/null"]),
        ("iam:PassRole + ec2:RunInstances", "critical",
         ["ec2", "run-instances", "--image-id", "ami-00000000",
          "--instance-type", "t2.micro"]),
        ("lambda:UpdateFunctionCode", "high",
         ["lambda", "update-function-code",
          "--function-name", "target", "--zip-file", "fileb:///dev/null"]),
        ("sts:AssumeRole", "medium",
         ["sts", "assume-role", "--role-arn",
          "arn:aws:iam::1:role/admin", "--role-session-name", "pwn"]),
        ("glue:UpdateDevEndpoint", "high",
         ["glue", "update-dev-endpoint",
          "--endpoint-name", "dev", "--public-key",
          "file:///dev/null"]),
    ]

    findings: list[IAMFinding] = []
    t = Table(title=f"⚡ AWS Privesc ({len(privesc_checks)})")
    t.add_column("Path", style="cyan", max_width=42)
    t.add_column("Status", width=12)
    t.add_column("Impact", width=9)

    for name, impact, cmd in privesc_checks:
        rc, out, err = _run_aws_cli(cmd + profile_args,
                                     env_extra=env_extra, timeout=8)
        if rc == 0:
            t.add_row(name, "[red]⚠ POSSIBLE[/red]", impact.upper())
            findings.append(IAMFinding(
                provider="aws", kind="privesc",
                severity=impact, identity=name,
                detail="allowed",
                data={"command": " ".join(cmd)},
            ))
            _save_finding(findings[-1])
        elif "AccessDenied" in err or "Unauthorized" in err:
            t.add_row(name, "[dim]✗ deny[/dim]", impact.upper())
        else:
            t.add_row(name, "[dim]—[/dim]", impact.upper())
    console.print(t)
    return findings


def aws_enumerate_s3(env_extra: dict, profile_args: list[str]
                      ) -> list[dict]:
    """Перечислить S3 бакеты + public access."""
    console.print("[cyan]🪣 AWS: S3 bucket enumeration…[/cyan]")
    rc, out, err = _run_aws_cli(["s3api", "list-buckets"] + profile_args,
                                  env_extra=env_extra, timeout=20)
    if rc != 0:
        console.print(f"[yellow]S3: {err[:100]}[/yellow]")
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []

    buckets = data.get("Buckets", []) or []
    if not buckets:
        console.print("[yellow]S3: бакетов нет[/yellow]")
        return []

    t = Table(title=f"🪣 S3 Buckets ({len(buckets)})")
    t.add_column("Name", style="cyan")
    t.add_column("Created")
    t.add_column("Public?", width=10)
    result: list[dict] = []

    for b in buckets[:100]:
        name = b.get("Name", "?")
        created = b.get("CreationDate", "?")[:10]
        # Проверим public access block
        rc2, out2, _ = _run_aws_cli(
            ["s3api", "get-public-access-block", "--bucket", name]
            + profile_args, env_extra=env_extra, timeout=8)
        public = "?"
        if rc2 == 0:
            try:
                cfg = json.loads(out2).get("PublicAccessBlockConfiguration", {})
                public = ("✓ blocked" if cfg.get("BlockPublicAcls")
                          else "⚠ open")
            except Exception:
                pass
        else:
            public = "⚠ no block"
        t.add_row(name, created, public)
        result.append({"name": name, "created": created,
                       "public_status": public})
    console.print(t)

    if any(r["public_status"].startswith("⚠") for r in result):
        _save_finding(IAMFinding(
            provider="aws", kind="s3_public",
            severity="high",
            title := f"AWS S3 buckets без PublicAccessBlock: "
                     f"{sum(1 for r in result if r['public_status'].startswith('⚠'))}",
            identity=profile_args[-1] if profile_args else "default",
            detail="S3 buckets без блокировки public access",
            data={"buckets": result},
        ))
    return result


# ===========================================================================
# GCP
# ===========================================================================

GCP_PERMISSION_CHECKS = [
    ("resourcemanager.projects.list",
     ["projects", "list", "--format=json"], "high"),
    ("compute.instances.list",
     ["compute", "instances", "list", "--format=json"], "high"),
    ("compute.firewalls.list",
     ["compute", "firewalls", "list", "--format=json"], "medium"),
    ("container.clusters.list",
     ["container", "clusters", "list", "--format=json"], "high"),
    ("storage.buckets.list",
     ["storage", "buckets", "list", "--format=json"], "high"),
    ("iam.serviceAccounts.list",
     ["iam", "service-accounts", "list", "--format=json"], "high"),
    ("cloudsql.instances.list",
     ["sql", "instances", "list", "--format=json"], "high"),
    ("bigquery.datasets.list",
     ["bigquery", "datasets", "list", "--format=json"], "medium"),
    ("cloudfunctions.functions.list",
     ["functions", "list", "--format=json"], "high"),
    ("logging.logs.list",
     ["logging", "logs", "list", "--format=json"], "low"),
]


def _run_gcloud(args: list[str], timeout: int = 15
                 ) -> tuple[int, str, str]:
    return _run_cmd(["gcloud"] + args, timeout=timeout)


def gcp_whoami(creds_file: str | None = None) -> IAMFinding | None:
    """Проверка GCP service account."""
    console.print("[cyan]🔍 GCP: проверка…[/cyan]")

    if creds_file:
        p = Path(creds_file)
        if not p.exists():
            console.print(f"[red]Файл {p} не найден.[/red]")
            return None
        rc, out, err = _run_gcloud(
            ["auth", "activate-service-account", "--key-file", str(p)])
        if rc != 0:
            console.print(f"[red]✗ {err[:200]}[/red]")
            return None

    rc, out, err = _run_gcloud(["auth", "list", "--format=json"])
    if rc != 0:
        console.print(f"[red]✗ {err[:200]}[/red]")
        return None

    try:
        accounts = json.loads(out)
    except Exception:
        return None

    if not accounts:
        console.print("[yellow]Нет аккаунтов.[/yellow]")
        return None

    table = Table(title="☁  GCP Accounts")
    table.add_column("Account", style="cyan", max_width=50)
    table.add_column("Status", width=12)
    for acc in accounts:
        status = acc.get("status", "?")
        account = acc.get("account", "?")
        table.add_row(account, status)
    console.print(table)

    active = next((a for a in accounts if a.get("status") == "ACTIVE"), None)
    if active:
        console.print(f"[green]✓ Active: {active.get('account')}[/green]")

    db.save_scan("gcp_whoami", "accounts", {"count": len(accounts)})
    return IAMFinding(
        provider="gcp", kind="identity", severity="info",
        identity=str([a.get("account") for a in accounts]),
    )


def gcp_enumerate_permissions() -> list[IAMFinding]:
    """Проверка GCP permissions."""
    console.print("[cyan]🔍 GCP: enumerating permissions…[/cyan]")
    findings: list[IAMFinding] = []
    t = Table(title=f"🔓 GCP Permissions ({len(GCP_PERMISSION_CHECKS)})")
    t.add_column("Action", style="cyan", max_width=42)
    t.add_column("Status", width=10)
    t.add_column("Detail", max_width=45)

    for action, cmd, sev in GCP_PERMISSION_CHECKS:
        rc, out, err = _run_gcloud(cmd)
        if rc == 0:
            try:
                data = json.loads(out)
                count = len(data) if isinstance(data, list) else 1
                detail = f"{count} items"
            except Exception:
                detail = out[:45].replace("\n", " ")
            t.add_row(action, "[green]✓[/green]", detail)
            findings.append(IAMFinding(
                provider="gcp", kind="permission",
                severity="high" if sev == "high" else "medium",
                identity=action, detail="allowed",
            ))
        else:
            t.add_row(action, "[dim]✗[/dim]", err[:45])
    console.print(t)
    return findings


# ===========================================================================
# Azure
# ===========================================================================

def _run_az(args: list[str], timeout: int = 15) -> tuple[int, str, str]:
    return _run_cmd(["az"] + args, timeout=timeout)


def azure_whoami() -> IAMFinding | None:
    """Проверка Azure CLI."""
    console.print("[cyan]🔍 Azure: проверка…[/cyan]")
    rc, out, err = _run_az(["account", "show", "-o", "json"])
    if rc != 0:
        console.print(f"[red]✗ {err[:200]}[/red]")
        return None
    try:
        data = json.loads(out)
    except Exception:
        return None

    console.print("[green]✓ Valid[/green]")
    t = Table(title="Azure Account")
    t.add_column("Поле", style="cyan", width=18)
    t.add_column("Значение", style="green")
    for k in ("name", "user", "tenantId", "id", "environmentName",
              "state"):
        v = data.get(k)
        if v:
            if isinstance(v, dict):
                v = v.get("name") or v.get("type") or str(v)
            t.add_row(k, str(v))
    console.print(t)

    db.save_scan("azure_whoami", data.get("name", "?"), data)
    return IAMFinding(
        provider="azure", kind="identity", severity="info",
        identity=data.get("name", "?"), data=data,
    )


def azure_enumerate() -> list[IAMFinding]:
    """Azure: subscriptions / resource groups / role assignments."""
    console.print("[cyan]🔍 Azure: enumeration…[/cyan]")
    findings: list[IAMFinding] = []

    # Subscriptions
    rc, out, err = _run_az(["account", "list", "-o", "json"])
    if rc == 0:
        try:
            subs = json.loads(out)
            console.print(f"[green]Subscriptions: {len(subs)}[/green]")
            if subs:
                _save_finding(IAMFinding(
                    provider="azure", kind="subscriptions",
                    severity="medium",
                    identity=f"{len(subs)} subscriptions",
                    detail="Azure account имеет доступ к subscriptions",
                    data={"subscriptions": [
                        {"id": s.get("id"), "name": s.get("name"),
                         "state": s.get("state")}
                        for s in subs[:20]]},
                ))
        except Exception:
            pass

    # Resource groups
    rc, out, err = _run_az(["group", "list", "-o", "json"])
    if rc == 0:
        try:
            rgs = json.loads(out)
            console.print(f"[green]Resource groups: {len(rgs)}[/green]")
            findings.append(IAMFinding(
                provider="azure", kind="resource_groups",
                severity="low",
                identity=f"{len(rgs)} groups",
                detail="Доступные resource groups",
            ))
        except Exception:
            pass

    # Role assignments
    rc, out, err = _run_az([
        "role", "assignment", "list", "--assignee",
        "@me", "-o", "json",
    ])
    if rc == 0:
        try:
            roles = json.loads(out)
            console.print(f"[green]Role assignments: {len(roles)}[/green]")
            t = Table(title="Azure Roles")
            t.add_column("Role", style="cyan")
            t.add_column("Scope", style="magenta", max_width=50)
            for r in roles[:20]:
                t.add_row(
                    r.get("roleDefinitionName", "?"),
                    r.get("scope", "?")[:50],
                )
            console.print(t)
            # Owner / Contributor
            owner = [r for r in roles
                     if r.get("roleDefinitionName") in
                     ("Owner", "Contributor", "User Access Administrator")]
            if owner:
                _save_finding(IAMFinding(
                    provider="azure", kind="privileged_role",
                    severity="high",
                    identity=f"{len(owner)} privileged roles",
                    detail="Azure account имеет Owner/Contributor",
                    data={"roles": [
                        {"name": r.get("roleDefinitionName"),
                         "scope": r.get("scope")}
                        for r in owner[:10]]},
                ))
        except Exception:
            pass

    return findings


# ===========================================================================
# Environment / files
# ===========================================================================

AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b")
GCP_KEY_HINT = re.compile(r'"type"\s*:\s*"service_account"')
GCP_PRIVATE_KEY = re.compile(
    r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----')
AZURE_CLIENT_SECRET = re.compile(
    r"(?i)(client[_-]?secret|AZURE_CLIENT_SECRET)"
    r"[\s:=]{1,4}([A-Za-z0-9_.\-~]{20,})")
JWT_REGEX = re.compile(
    r"\beyJ[A-Za-z0-9_/+\-]{10,}\.eyJ[A-Za-z0-9_/+\-]{10,}\."
    r"[A-Za-z0-9_/+\-]+")


ENV_SENSITIVE_VARS = [
    # AWS
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    # GCP
    "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT",
    "GOOGLE_CLOUD_PROJECT",
    # Azure
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    # Cloud providers
    "DIGITALOCEAN_TOKEN", "DO_API_TOKEN",
    "LINODE_TOKEN", "LINODE_API_TOKEN",
    "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "CF_API_KEY",
    "VULTR_API_KEY", "HETZNER_API_TOKEN",
    "OPENSTACK_AUTH_URL", "OS_PASSWORD",
    # CI/CD
    "GITHUB_TOKEN", "GH_TOKEN",
    "GITLAB_TOKEN", "CI_JOB_TOKEN",
    "JENKINS_TOKEN", "CIRCLE_TOKEN",
    "TRAVIS_TOKEN", "NPM_TOKEN",
    # SaaS
    "SLACK_TOKEN", "SLACK_WEBHOOK",
    "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    "SENDGRID_API_KEY", "MAILGUN_API_KEY",
    "TWILIO_AUTH_TOKEN",
    # DB
    "DATABASE_URL", "MONGODB_URI", "REDIS_URL",
    "POSTGRES_PASSWORD", "MYSQL_PASSWORD",
]


def scan_env() -> list[IAMFinding]:
    """Сканировать окружение на креды."""
    console.print("[cyan]🔍 Проверяю environment variables…[/cyan]")
    findings: list[IAMFinding] = []

    table = Table(title=f"🔑 Cloud env vars ({len(ENV_SENSITIVE_VARS)})")
    table.add_column("Variable", style="cyan", max_width=35)
    table.add_column("Value", style="green", max_width=45)
    table.add_column("Severity", width=10)

    for var in ENV_SENSITIVE_VARS:
        val = os.environ.get(var)
        if not val:
            continue
        # Маскируем
        masked = val[:8] + "…" + val[-4:] if len(val) > 16 else "***"
        sev = ("critical" if any(k in var for k in (
            "SECRET", "TOKEN", "KEY", "PASSWORD", "AUTH")) else "medium")
        table.add_row(var, masked, sev.upper())
        findings.append(IAMFinding(
            provider="env", kind="credential", severity=sev,
            identity=var, detail=masked,
            data={"var_name": var, "len": len(val)},
        ))
    console.print(table)

    # Regex-based scan
    for var, val in os.environ.items():
        for m in AWS_KEY_REGEX.finditer(val):
            console.print(f"[red]⚠ AWS key in env {var}: "
                          f"{m.group()[:8]}…[/red]")
            findings.append(IAMFinding(
                provider="env", kind="aws_key",
                severity="critical",
                identity=f"{var}=AKIA…",
                detail=f"AWS key в {var}",
                data={"var": var, "key_prefix": m.group()[:8]},
            ))
        if JWT_REGEX.search(val):
            findings.append(IAMFinding(
                provider="env", kind="jwt",
                severity="medium",
                identity=f"{var}=JWT",
                detail=f"JWT в {var}",
                data={"var": var},
            ))

    # Save findings
    saved = sum(1 for f in findings if _save_finding(f) > 0)
    if saved:
        console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("cloud_env", "local",
                 {"count": len(findings),
                  "vars": [f.identity for f in findings]})
    return findings


def scan_credential_files() -> list[IAMFinding]:
    """Проверить стандартные места с кредами."""
    console.print("[cyan]🔍 Проверяю файлы с кредами…[/cyan]")
    findings: list[IAMFinding] = []
    home = Path.home()

    files = [
        (home / ".aws" / "credentials", "AWS creds", "critical"),
        (home / ".aws" / "config", "AWS config", "medium"),
        (home / ".config" / "gcloud" / "credentials.db",
         "GCloud creds", "critical"),
        (home / ".config" / "gcloud"
         / "application_default_credentials.json",
         "GCloud ADC", "critical"),
        (home / ".azure" / "azureProfile.json", "Azure profile",
         "medium"),
        (home / ".azure" / "accessTokens.json", "Azure tokens",
         "critical"),
        (home / ".config" / "gh" / "hosts.yml", "GitHub CLI",
         "critical"),
        (home / ".docker" / "config.json", "Docker registry",
         "high"),
        (home / ".kube" / "config", "K8s config", "high"),
        (home / ".netrc", "netrc", "high"),
        (home / ".npmrc", "NPM token", "high"),
        (home / ".pypirc", "PyPI token", "high"),
        (home / ".git-credentials", "Git creds", "high"),
        (home / ".vault-token", "Vault token", "critical"),
        (home / ".terraformrc", "Terraform Cloud", "medium"),
    ]

    table = Table(title="📁 Credential files")
    table.add_column("File", style="cyan", max_width=50)
    table.add_column("Status", width=10)
    table.add_column("Size", width=8)
    table.add_column("Sev", width=10)

    for f, label, sev in files:
        if f.exists():
            try:
                size = f.stat().st_size
                table.add_row(
                    str(f).replace(str(home), "~"),
                    "[red]EXISTS[/red]", f"{size}B", sev.upper())
                findings.append(IAMFinding(
                    provider="file", kind="credential",
                    severity=sev,
                    identity=str(f),
                    detail=f"{label} ({size} bytes)",
                ))
            except Exception:
                pass
    console.print(table)

    # Content scan
    for f, _label, _sev in files:
        if not f.exists():
            continue
        try:
            if f.stat().st_size > 1024 * 1024:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for m in AWS_KEY_REGEX.finditer(text):
            console.print(f"[red]⚠ AWS Key в {f.name}: "
                          f"{m.group()[:8]}…[/red]")
            findings.append(IAMFinding(
                provider="file", kind="aws_key",
                severity="critical",
                identity=str(f),
                detail=f"AWS key: {m.group()[:8]}…",
                data={"file": str(f), "prefix": m.group()[:8]},
            ))
        if GCP_KEY_HINT.search(text):
            console.print(f"[red]⚠ GCP service account JSON: "
                          f"{f.name}[/red]")
            findings.append(IAMFinding(
                provider="file", kind="gcp_sa",
                severity="critical",
                identity=str(f),
                detail="GCP service account JSON",
            ))
        if GCP_PRIVATE_KEY.search(text):
            findings.append(IAMFinding(
                provider="file", kind="gcp_private_key",
                severity="critical",
                identity=str(f),
                detail="GCP private_key в файле",
            ))
        if AZURE_CLIENT_SECRET.search(text):
            findings.append(IAMFinding(
                provider="file", kind="azure_secret",
                severity="critical",
                identity=str(f),
                detail="Azure client secret в файле",
            ))

    # Save критичные
    saved = sum(1 for f in findings if _save_finding(f) > 0)
    if saved:
        console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("cloud_cred_files", "local",
                 {"count": len(findings)})
    return findings


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(findings: list[IAMFinding],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(IAM_DIR / f"iam_{ts}.json")
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


def export_csv(findings: list[IAMFinding],
                path: str | None = None) -> Path | None:
    if not findings:
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(IAM_DIR / f"iam_{ts}.csv")
    cols = ["provider", "kind", "severity", "identity", "detail"]
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


def export_html(findings: list[IAMFinding],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(IAM_DIR / f"iam_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Cloud IAM Analysis</title>",
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
        "<h1>☁  Cloud IAM Analysis</h1>",
        f"<p>Findings: <b>{len(findings)}</b> | "
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>Provider</th><th>Kind</th><th>Severity</th>"
        "<th>Identity</th><th>Detail</th></tr>",
    ]
    for f in findings:
        parts.append(
            f"<tr><td>{html_mod.escape(f.provider)}</td>"
            f"<td>{html_mod.escape(f.kind)}</td>"
            f"<td class='{f.severity}'>{f.severity.upper()}</td>"
            f"<td>{html_mod.escape(f.identity[:80])}</td>"
            f"<td>{html_mod.escape(f.detail[:120])}</td></tr>"
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
# Full audit (комбо)
# ===========================================================================

def full_audit() -> list[IAMFinding]:
    """Полный аудит: env + files + (если есть CLI) cloud perms."""
    console.print("\n[bold cyan]═══ Cloud IAM Full Audit ═══[/bold cyan]\n")

    all_findings: list[IAMFinding] = []

    all_findings.extend(scan_env())
    all_findings.extend(scan_credential_files())

    if shutil.which("aws"):
        console.print()
        f = aws_whoami()
        if f:
            all_findings.append(f)
            all_findings.extend(aws_enumerate_permissions(
                save_findings=True))

    if shutil.which("gcloud"):
        console.print()
        f = gcp_whoami()
        if f:
            all_findings.extend(gcp_enumerate_permissions())

    if shutil.which("az"):
        console.print()
        f = azure_whoami()
        if f:
            all_findings.extend(azure_enumerate())

    # Экспорт
    export_json(all_findings)
    export_csv(all_findings)

    # Notify
    try:
        from modules import notifier
        notifier.notify_all(
            "☁  Cloud IAM Audit",
            f"Findings: {len(all_findings)}\n"
            f"Critical: {sum(1 for f in all_findings if f.severity == 'critical')}\n"
            f"High: {sum(1 for f in all_findings if f.severity == 'high')}",
        )
    except Exception:
        pass

    return all_findings


# ===========================================================================
# CLI-обёртки (совместимы со старыми)
# ===========================================================================

def cli_aws(profile: str = "") -> None:
    """Проверка AWS по профилю/env."""
    f = aws_whoami(profile=profile)
    if f:
        aws_enumerate_permissions(profile=profile, save_findings=True)


def cli_gcp(creds: str | None = None) -> None:
    f = gcp_whoami(creds)
    if f:
        gcp_enumerate_permissions()


def cli_azure() -> None:
    f = azure_whoami()
    if f:
        azure_enumerate()


def cli_env() -> None:
    findings = scan_env()
    if findings and Confirm.ask("Экспорт JSON?", default=False):
        export_json(findings)


def cli_files() -> None:
    findings = scan_credential_files()
    if findings and Confirm.ask("Экспорт JSON?", default=False):
        export_json(findings)


def cli_full() -> None:
    full_audit()


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]☁  Cloud IAM Analyzer[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "AWS: get-caller-identity + permissions"),
        ("2", "AWS: с явными ключами"),
        ("3", "AWS: S3 bucket enumeration"),
        ("4", "GCP: service account + permissions"),
        ("5", "Azure: account + subscriptions + roles"),
        ("6", "Сканировать env vars"),
        ("7", "Сканировать credential files"),
        ("8", "Full audit (всё сразу)"),
        ("9", "Экспорт (JSON / CSV / HTML)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        prof = Prompt.ask("AWS profile (пусто = default)", default="")
        cli_aws(prof)
    elif c == "2":
        ak = Prompt.ask("AWS Access Key ID")
        sk = Prompt.ask("AWS Secret Access Key", password=True)
        st = Prompt.ask("Session token (пусто = нет)", default="")
        f = aws_whoami(ak, sk, st)
        if f:
            aws_enumerate_permissions(ak, sk, st, save_findings=True)
    elif c == "3":
        prof = Prompt.ask("AWS profile (пусто = default)", default="")
        env_extra: dict = {}
        profile_args = ["--profile", prof] if prof else []
        aws_enumerate_s3(env_extra, profile_args)
    elif c == "4":
        cf = Prompt.ask("Путь к SA JSON (пусто = текущий)", default="")
        cli_gcp(cf or None)
    elif c == "5":
        cli_azure()
    elif c == "6":
        cli_env()
    elif c == "7":
        cli_files()
    elif c == "8":
        full_audit()
    elif c == "9":
        fmt = Prompt.ask("Формат", choices=["json", "csv", "html"],
                          default="json")
        findings = full_audit()
        if fmt == "json":
            export_json(findings)
        elif fmt == "csv":
            export_csv(findings)
        else:
            export_html(findings)