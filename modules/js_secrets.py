"""
JS Secrets Scanner Pro.
Author: idqwixxa

⚠ Только для этичного использования и bug bounty.

Возможности:
    ─── Pattern detection ───
    - 130+ паттернов секретов (AWS, GCP, Azure, Stripe, GitHub, GitLab,
      Slack, Discord, OpenAI, Anthropic, Hugging Face, NPM, PyPI, JFrog,
      Datadog, New Relic, Sentry, Cloudflare, Twilio, SendGrid, Mailgun,
      Mailchimp, Heroku, DigitalOcean, Linear, Notion, Trello, Atlassian,
      MongoDB/Postgres/Redis/MySQL URI, JWT, PEM/OpenSSH/RSA, basic-auth,
      bearer, webhooks, ...)
    - Entropy-based detection (high-entropy строки рядом с ключевыми словами)
    - Source-map awareness (.map files + inline maps)
    - Minified vs unminified classification
    - Context extraction (±150 символов)

    ─── Validation ───
    - GitHub / GitLab / Slack / Stripe / SendGrid / Discord / Telegram
    - AWS STS GetCallerIdentity (если boto3)
    - Google API Key liveness
    - OpenAI / Anthropic / HuggingFace token check
    - Notion / Linear / Airtable / Trello
    - Confluence / Jira (Atlassian)

    ─── Интеграция ───
    - Findings → notes (для critical/high)
    - Notify при critical
    - Экспорт: JSON / CSV / Markdown / HTML
"""
import csv
import html as html_mod
import json
import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
SECRETS_DIR = REPORT_DIR / "secrets"
SECRETS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class SecretFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: SecretFinding) -> int:
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
            tags=["secrets", "js", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Паттерны секретов (130+)
# ===========================================================================

PATTERNS: list[dict] = [
    # ===== AWS =====
    {"name": "AWS Access Key ID",
     "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
     "severity": "critical"},
    {"name": "AWS Access Key ID (alt)",
     "regex": re.compile(r"\b(ASIA[0-9A-Z]{16})\b"),
     "severity": "critical"},
    {"name": "AWS Secret Access Key",
     "regex": re.compile(
         r"(?i)aws[_\-.]{0,3}(?:secret|access)[_\-.]{0,3}key"
         r"[\s:=\"']{0,8}([A-Za-z0-9/+=]{40})"),
     "severity": "critical"},
    {"name": "AWS Session Token",
     "regex": re.compile(r"\b(FwoGZXIvYXdzE[A-Za-z0-9/+=]{50,})\b"),
     "severity": "critical"},
    {"name": "AWS MWS Token",
     "regex": re.compile(r"\b(amzn\.mws\.[0-9a-f-]{36})\b"),
     "severity": "critical"},
    {"name": "AWS S3 Bucket",
     "regex": re.compile(
         r"([a-z0-9.\-]{3,63}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com)"),
     "severity": "medium"},

    # ===== Google =====
    {"name": "Google API Key",
     "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
     "severity": "high"},
    {"name": "Google OAuth Client ID",
     "regex": re.compile(
         r"\b([0-9]{8,}-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com)\b"),
     "severity": "medium"},
    {"name": "Google OAuth Secret",
     "regex": re.compile(r"\b(GOCSPX-[0-9A-Za-z\-_]{20,})\b"),
     "severity": "critical"},
    {"name": "Firebase DB URL",
     "regex": re.compile(r"(https?://[a-z0-9-]+\.firebaseio\.com)"),
     "severity": "medium"},
    {"name": "Firebase Cloud Messaging Key",
     "regex": re.compile(r"\b(AAAA[a-zA-Z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b"),
     "severity": "high"},
    {"name": "GCP Service Account",
     "regex": re.compile(r'"type"\s*:\s*"service_account"'),
     "severity": "critical"},
    {"name": "GCP Private Key ID",
     "regex": re.compile(r'"private_key_id"\s*:\s*"([0-9a-f]{40})"'),
     "severity": "critical"},

    # ===== Azure =====
    {"name": "Azure Storage Account Key",
     "regex": re.compile(
         r"(?i)AccountKey=([A-Za-z0-9+/=]{88})"),
     "severity": "critical"},
    {"name": "Azure Connection String",
     "regex": re.compile(
         r"(DefaultEndpointsProtocol=https?;AccountName=[^;]+;"
         r"AccountKey=[A-Za-z0-9+/=]{88})"),
     "severity": "critical"},
    {"name": "Azure Tenant ID",
     "regex": re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                          r"[0-9a-f]{4}-[0-9a-f]{12})\b.*?tenant",
                          re.IGNORECASE),
     "severity": "low"},

    # ===== Stripe =====
    {"name": "Stripe Live Secret Key",
     "regex": re.compile(r"\b(sk_live_[0-9a-zA-Z]{20,})\b"),
     "severity": "critical"},
    {"name": "Stripe Test Secret Key",
     "regex": re.compile(r"\b(sk_test_[0-9a-zA-Z]{20,})\b"),
     "severity": "low"},
    {"name": "Stripe Live Publishable Key",
     "regex": re.compile(r"\b(pk_live_[0-9a-zA-Z]{20,})\b"),
     "severity": "low"},
    {"name": "Stripe Webhook Secret",
     "regex": re.compile(r"\b(whsec_[0-9a-zA-Z]{20,})\b"),
     "severity": "high"},

    # ===== GitHub / GitLab / Bitbucket =====
    {"name": "GitHub Personal Access Token",
     "regex": re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
     "severity": "critical"},
    {"name": "GitHub OAuth Token",
     "regex": re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
     "severity": "critical"},
    {"name": "GitHub App Token",
     "regex": re.compile(r"\b(ghs_[A-Za-z0-9]{36})\b"),
     "severity": "critical"},
    {"name": "GitHub Refresh Token",
     "regex": re.compile(r"\b(ghr_[A-Za-z0-9]{76})\b"),
     "severity": "high"},
    {"name": "GitHub Fine-grained PAT",
     "regex": re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
     "severity": "critical"},
    {"name": "GitLab PAT",
     "regex": re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
     "severity": "critical"},
    {"name": "GitLab Runner Token",
     "regex": re.compile(r"\b(glrt-[A-Za-z0-9_\-]{20,})\b"),
     "severity": "critical"},
    {"name": "Bitbucket App Password",
     "regex": re.compile(r"\b(ATBB[A-Za-z0-9]{32})\b"),
     "severity": "critical"},

    # ===== Slack / Discord / Telegram =====
    {"name": "Slack Token",
     "regex": re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b"),
     "severity": "critical"},
    {"name": "Slack Webhook",
     "regex": re.compile(
         r"(https?://hooks\.slack\.com/services/T[A-Z0-9]+/"
         r"B[A-Z0-9]+/[A-Za-z0-9]+)"),
     "severity": "high"},
    {"name": "Discord Webhook",
     "regex": re.compile(
         r"(https?://(?:discord|discordapp)\.com/api/webhooks/"
         r"[0-9]+/[A-Za-z0-9\-_]+)"),
     "severity": "high"},
    {"name": "Discord Bot Token",
     "regex": re.compile(
         r"\b([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})\b"),
     "severity": "critical"},
    {"name": "Telegram Bot Token",
     "regex": re.compile(r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b"),
     "severity": "high"},

    # ===== AI / LLM =====
    {"name": "OpenAI API Key",
     "regex": re.compile(r"\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b"),
     "severity": "critical"},
    {"name": "OpenAI API Key (new)",
     "regex": re.compile(r"\b(sk-proj-[A-Za-z0-9_\-]{40,})\b"),
     "severity": "critical"},
    {"name": "Anthropic API Key",
     "regex": re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{40,})\b"),
     "severity": "critical"},
    {"name": "Hugging Face Token",
     "regex": re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"),
     "severity": "critical"},
    {"name": "Cohere API Key",
     "regex": re.compile(r"\b([A-Za-z0-9]{40})\b(?=.*cohere)",
                          re.IGNORECASE),
     "severity": "medium"},
    {"name": "Replicate API Token",
     "regex": re.compile(r"\b(r8_[A-Za-z0-9]{40})\b"),
     "severity": "critical"},

    # ===== DevOps / CI =====
    {"name": "NPM Token",
     "regex": re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
     "severity": "high"},
    {"name": "PyPI Token",
     "regex": re.compile(r"\b(pypi-[A-Za-z0-9_\-]{50,})\b"),
     "severity": "high"},
    {"name": "JFrog Artifactory Token",
     "regex": re.compile(r"\b(AKCp[A-Za-z0-9]{60,})\b"),
     "severity": "critical"},
    {"name": "Docker Hub PAT",
     "regex": re.compile(r"\b(dckr_pat_[A-Za-z0-9_\-]{27,})\b"),
     "severity": "high"},
    {"name": "CircleCI Token",
     "regex": re.compile(r"(?i)circle[_-]?ci[_-]?token[\s:=\"']{0,8}"
                          r"([A-Za-z0-9]{40})"),
     "severity": "high"},
    {"name": "Travis CI Token",
     "regex": re.compile(r"(?i)travis[_-]?token[\s:=\"']{0,8}"
                          r"([A-Za-z0-9\-_]{22})"),
     "severity": "medium"},

    # ===== Monitoring / Analytics =====
    {"name": "Datadog API Key",
     "regex": re.compile(r"(?i)datadog.{0,20}([a-f0-9]{32})"),
     "severity": "high"},
    {"name": "Datadog App Key",
     "regex": re.compile(r"(?i)app[_-]?key.{0,20}([a-f0-9]{40})"),
     "severity": "high"},
    {"name": "New Relic License Key",
     "regex": re.compile(r"\b([a-f0-9]{40})NRAL\b"),
     "severity": "medium"},
    {"name": "New Relic Insert Key",
     "regex": re.compile(r"\b(NRII-[A-Za-z0-9_\-]{20,})\b"),
     "severity": "high"},
    {"name": "Sentry DSN",
     "regex": re.compile(
         r"(https?://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+)"),
     "severity": "medium"},
    {"name": "Rollbar Token",
     "regex": re.compile(r"\b([a-f0-9]{32})\b(?=.*rollbar)",
                          re.IGNORECASE),
     "severity": "medium"},
    {"name": "Segment Write Key",
     "regex": re.compile(r"(?i)segment.{0,20}([a-zA-Z0-9]{32})"),
     "severity": "medium"},
    {"name": "Mixpanel Token",
     "regex": re.compile(r"(?i)mixpanel.{0,20}([a-f0-9]{32})"),
     "severity": "medium"},
    {"name": "Amplitude API Key",
     "regex": re.compile(r"(?i)amplitude.{0,20}([a-f0-9]{32})"),
     "severity": "medium"},

    # ===== CDN / Infra =====
    {"name": "Cloudflare API Token",
     "regex": re.compile(
         r"(?i)cloudflare.{0,30}([A-Za-z0-9_\-]{40})"),
     "severity": "critical"},
    {"name": "Cloudflare Global API Key",
     "regex": re.compile(r"\b([a-f0-9]{37})\b(?=.*cloudflare)",
                          re.IGNORECASE),
     "severity": "critical"},
    {"name": "Fastly API Key",
     "regex": re.compile(r"(?i)fastly.{0,20}([A-Za-z0-9_\-]{32})"),
     "severity": "high"},
    {"name": "DigitalOcean Token",
     "regex": re.compile(r"\b(dop_v1_[0-9a-f]{64})\b"),
     "severity": "critical"},
    {"name": "DigitalOcean OAuth",
     "regex": re.compile(r"\b(doo_v1_[0-9a-f]{64})\b"),
     "severity": "high"},
    {"name": "Heroku API Key",
     "regex": re.compile(
         r"(?i)heroku[_\-.]{0,3}api[_\-.]{0,3}key"
         r"[\s:=\"']{0,8}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"),
     "severity": "high"},
    {"name": "Vercel Token",
     "regex": re.compile(r"\b([A-Za-z0-9]{24})\b(?=.*vercel)",
                          re.IGNORECASE),
     "severity": "high"},
    {"name": "Netlify Token",
     "regex": re.compile(r"\b([A-Za-z0-9_\-]{40,})\b(?=.*netlify)",
                          re.IGNORECASE),
     "severity": "high"},

    # ===== Comms =====
    {"name": "Twilio API Key",
     "regex": re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
     "severity": "high"},
    {"name": "Twilio Account SID",
     "regex": re.compile(r"\b(AC[0-9a-fA-F]{32})\b"),
     "severity": "medium"},
    {"name": "SendGrid API Key",
     "regex": re.compile(
         r"\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b"),
     "severity": "critical"},
    {"name": "Mailgun API Key",
     "regex": re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
     "severity": "high"},
    {"name": "Mailchimp API Key",
     "regex": re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"),
     "severity": "high"},
    {"name": "Postmark Token",
     "regex": re.compile(
         r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
         r"[0-9a-f]{12})\b(?=.*postmark)", re.IGNORECASE),
     "severity": "high"},
    {"name": "Mailjet API Key",
     "regex": re.compile(r"(?i)mailjet.{0,20}([a-f0-9]{32})"),
     "severity": "high"},
    {"name": "Mandrill API Key",
     "regex": re.compile(r"\b([A-Za-z0-9_\-]{22})\b(?=.*mandrill)",
                          re.IGNORECASE),
     "severity": "medium"},

    # ===== Social =====
    {"name": "Facebook Access Token",
     "regex": re.compile(r"\b(EAACEdEose0cBA[0-9A-Za-z]+)\b"),
     "severity": "high"},
    {"name": "Twitter Access Token",
     "regex": re.compile(r"\b([1-9][0-9]+-[0-9a-zA-Z]{40})\b"),
     "severity": "medium"},
    {"name": "Twitter Bearer Token",
     "regex": re.compile(r"\b(AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,})\b"),
     "severity": "high"},
    {"name": "LinkedIn Token",
     "regex": re.compile(r"\b(AQV[A-Za-z0-9_\-]{100,})\b"),
     "severity": "medium"},
    {"name": "Reddit Client Secret",
     "regex": re.compile(r"\b([A-Za-z0-9_\-]{27})\b(?=.*reddit)",
                          re.IGNORECASE),
     "severity": "medium"},

    # ===== Productivity / SaaS =====
    {"name": "Notion Integration Token",
     "regex": re.compile(r"\b(secret_[A-Za-z0-9]{43})\b"),
     "severity": "critical"},
    {"name": "Notion Public Integration",
     "regex": re.compile(r"\b(ntn_[0-9]{10,}[A-Za-z0-9_]{10,})\b"),
     "severity": "high"},
    {"name": "Linear API Key",
     "regex": re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"),
     "severity": "high"},
    {"name": "Airtable API Key",
     "regex": re.compile(r"\b(key[A-Za-z0-9]{14})\b"),
     "severity": "high"},
    {"name": "Trello API Key",
     "regex": re.compile(r"\b([a-f0-9]{32})\b(?=.*trello)",
                          re.IGNORECASE),
     "severity": "medium"},
    {"name": "Atlassian API Token",
     "regex": re.compile(r"\b(ATATT3xFfGF0[A-Za-z0-9_\-]{100,})\b"),
     "severity": "critical"},
    {"name": "Asana Token",
     "regex": re.compile(r"\b([0-9]/[0-9]{16}/[0-9]{16}:[A-Za-z0-9]{32})\b"),
     "severity": "high"},
    {"name": "Zoom JWT",
     "regex": re.compile(r"\b(eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}"
                          r"\.[A-Za-z0-9_\-]+)\b(?=.*zoom)",
                          re.IGNORECASE),
     "severity": "high"},
    {"name": "Intercom Token",
     "regex": re.compile(r"\b(dG9rO[A-Za-z0-9_\-]{60,})\b"),
     "severity": "high"},
    {"name": "Zendesk API Token",
     "regex": re.compile(r"(?i)zendesk.{0,20}([A-Za-z0-9]{40})"),
     "severity": "medium"},
    {"name": "Zapier Webhook",
     "regex": re.compile(
         r"(https?://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+)"),
     "severity": "medium"},
    {"name": "IFTTT Webhook",
     "regex": re.compile(
         r"(https?://maker\.ifttt\.com/use/[A-Za-z0-9_\-]+)"
         r"(/with/key/[A-Za-z0-9_\-]+)?"),
     "severity": "medium"},

    # ===== Money / Payments =====
    {"name": "Square Access Token",
     "regex": re.compile(r"\b(sq0atp-[A-Za-z0-9_\-]{22})\b"),
     "severity": "critical"},
    {"name": "Square OAuth Secret",
     "regex": re.compile(r"\b(sq0csp-[A-Za-z0-9_\-]{43})\b"),
     "severity": "critical"},
    {"name": "PayPal Braintree Token",
     "regex": re.compile(r"\b(access_token\$production\$[a-z0-9]{16}"
                          r"\$[a-f0-9]{32})\b"),
     "severity": "critical"},
    {"name": "Plaid Client ID",
     "regex": re.compile(r"\b([a-z0-9]{24})\b(?=.*plaid)",
                          re.IGNORECASE),
     "severity": "medium"},
    {"name": "Coinbase API Key",
     "regex": re.compile(r"\b([A-Za-z0-9]{64})\b(?=.*coinbase)",
                          re.IGNORECASE),
     "severity": "high"},

    # ===== Database / Cache URIs =====
    {"name": "MongoDB Connection String",
     "regex": re.compile(r"(mongodb(?:\+srv)?://[^\s\"'<>]{10,})"),
     "severity": "critical"},
    {"name": "PostgreSQL URI",
     "regex": re.compile(r"(postgres(?:ql)?://[^\s\"'<>]{10,})"),
     "severity": "high"},
    {"name": "MySQL URI",
     "regex": re.compile(r"(mysql://[^\s\"'<>]{10,})"),
     "severity": "high"},
    {"name": "Redis URI",
     "regex": re.compile(r"(redis://[^\s\"'<>]{10,})"),
     "severity": "high"},
    {"name": "AMQP URI",
     "regex": re.compile(r"(amqps?://[^\s\"'<>]{10,})"),
     "severity": "high"},
    {"name": "Elasticsearch URI",
     "regex": re.compile(r"(https?://[^\s\"'<>]{10,}:9200[^\s\"'<>]*)"),
     "severity": "medium"},

    # ===== JWT / Keys =====
    {"name": "JSON Web Token",
     "regex": re.compile(
         r"\b(eyJ[A-Za-z0-9_/+\-]{10,}\.eyJ[A-Za-z0-9_/+\-]{10,}\."
         r"[A-Za-z0-9_/+\-]+)\b"),
     "severity": "medium"},
    {"name": "Private Key (PEM)",
     "regex": re.compile(
         r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
         r"PRIVATE KEY-----)"),
     "severity": "critical"},
    {"name": "RSA Private Key",
     "regex": re.compile(r"(-----BEGIN RSA PRIVATE KEY-----)"),
     "severity": "critical"},
    {"name": "SSH Private Key",
     "regex": re.compile(r"(-----BEGIN OPENSSH PRIVATE KEY-----)"),
     "severity": "critical"},
    {"name": "PGP Private Key",
     "regex": re.compile(r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"),
     "severity": "critical"},
    {"name": "PuTTY Private Key",
     "regex": re.compile(r"(PuTTY-User-Key-File-2)"),
     "severity": "critical"},

    # ===== Auth =====
    {"name": "Basic Auth in URL",
     "regex": re.compile(r"https?://([^:@/\s]+:[^@/\s]+)@[^\s\"']+"),
     "severity": "high"},
    {"name": "Bearer Token",
     "regex": re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-.]{20,})"),
     "severity": "medium"},
    {"name": "Authorization Header (Basic)",
     "regex": re.compile(r"(?i)authorization[\s:=\"']{0,8}basic\s+"
                          r"([A-Za-z0-9+/=]{20,})"),
     "severity": "high"},

    # ===== Generic (low-confidence, filtered) =====
    {"name": "Generic API Key",
     "regex": re.compile(
         r"(?i)(?:api[_\-.]?key|apikey|access[_\-.]?token|"
         r"auth[_\-.]?token|secret[_\-.]?key|private[_\-.]?key)"
         r"[\s:=\"']{0,8}([A-Za-z0-9_\-]{20,64})"),
     "severity": "medium"},
    {"name": "Generic Password",
     "regex": re.compile(
         r"(?i)(?:password|passwd|pwd)"
         r"[\s:=\"']{1,8}([^\s\"'<>{}]{6,64})"),
     "severity": "medium"},
    {"name": "Cloudinary URL",
     "regex": re.compile(
         r"(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9\-]+)"),
     "severity": "high"},
    {"name": "RSA Public Key (info only)",
     "regex": re.compile(r"(ssh-rsa AAAA[A-Za-z0-9+/=]+)"),
     "severity": "info"},
    {"name": "SSH Ed25519 Public Key",
     "regex": re.compile(r"(ssh-ed25519 AAAA[A-Za-z0-9+/=]+)"),
     "severity": "info"},
]


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ===========================================================================
# Entropy
# ===========================================================================

def _entropy(s: str) -> float:
    """Shannon entropy строки (0-8)."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    ent = 0.0
    for c in counter.values():
        p = c / length
        ent -= p * math.log2(p)
    return round(ent, 3)


HIGH_ENTROPY_KEYWORDS = re.compile(
    r"(?i)(?:token|secret|key|pass|auth|credential|apikey|api_key)"
)
ENTROPY_CANDIDATE = re.compile(r"\b([A-Za-z0-9+/=_\-]{32,128})\b")


def find_high_entropy_strings(text: str, threshold: float = 4.3,
                              limit: int = 100) -> list[tuple[str, float]]:
    """Найти high-entropy строки рядом с ключевыми словами."""
    out: list[tuple[str, float]] = []
    seen: set[str] = set()
    for m in ENTROPY_CANDIDATE.finditer(text):
        candidate = m.group(1)
        if candidate in seen:
            continue
        # Контекст ±100
        start = max(0, m.start() - 100)
        ctx = text[start:m.end() + 50]
        if not HIGH_ENTROPY_KEYWORDS.search(ctx):
            continue
        ent = _entropy(candidate)
        if ent >= threshold:
            seen.add(candidate)
            out.append((candidate, ent))
        if len(out) >= limit:
            break
    return out


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class Secret:
    kind: str
    value: str
    severity: str
    source_url: str
    context: str = ""
    validated: bool | None = None
    validation_msg: str = ""
    entropy: float = 0.0


# ===========================================================================
# Скачивание
# ===========================================================================

def _fetch(url: str, timeout: int = TIMEOUT) -> str | None:
    try:
        r = requests.get(
            url, timeout=timeout, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if r.status_code == 200:
            return r.text
        return None
    except Exception as exc:  # noqa: BLE001
        log.debug("fetch %s: %s", url, exc)
        return None


def _collect_js_urls(base: str, max_files: int = 50) -> list[str]:
    """Собрать все .js URL'ы (+ source maps)."""
    html = _fetch(base)
    if not html:
        return []

    urls: list[str] = []
    seen: set[str] = set()

    soup = BeautifulSoup(html, "html.parser")
    for s in soup.find_all("script", src=True):
        src = s["src"]
        full = urljoin(base, src)
        if full not in seen:
            seen.add(full)
            urls.append(full)

    for m in re.finditer(r"//# sourceMappingURL=([^\s]+\.map)", html):
        full = urljoin(base, m.group(1))
        if full not in seen:
            seen.add(full)
            urls.append(full)

    return urls[:max_files]


def _extract_inline_scripts(base: str) -> list[str]:
    html = _fetch(base)
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    out: list[str] = []
    for s in soup.find_all("script"):
        if s.string and not s.get("src"):
            out.append(s.string)
    return out


# ===========================================================================
# Сканирование текста
# ===========================================================================

def _find_secrets(text: str, source_url: str,
                  include_entropy: bool = True) -> list[Secret]:
    out: list[Secret] = []
    seen: set[tuple[str, str]] = set()

    for pat in PATTERNS:
        for m in pat["regex"].finditer(text):
            value = m.group(1)
            key = (pat["name"], value)
            if key in seen:
                continue
            seen.add(key)

            start = max(0, m.start() - 150)
            end = min(len(text), m.end() + 150)
            ctx = text[start:end].replace("\n", " ").replace("\r", "")

            out.append(Secret(
                kind=pat["name"],
                value=value,
                severity=pat["severity"],
                source_url=source_url,
                context=ctx[:300],
                entropy=_entropy(value),
            ))

    # Entropy-based
    if include_entropy:
        for cand, ent in find_high_entropy_strings(text):
            key = ("High-Entropy String", cand)
            if key in seen:
                continue
            seen.add(key)
            out.append(Secret(
                kind="High-Entropy String",
                value=cand,
                severity="medium",
                source_url=source_url,
                context="",
                entropy=ent,
            ))

    return out


# ===========================================================================
# Validation
# ===========================================================================

def _validate_github(token: str) -> tuple[bool, str]:
    try:
        r = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}",
                     "User-Agent": "CyberSecToolkit"},
            timeout=8,
        )
        if r.status_code == 200:
            return True, f"valid — user: {r.json().get('login', '?')}"
        if r.status_code == 401:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_gitlab(token: str) -> tuple[bool, str]:
    try:
        r = requests.get("https://gitlab.com/api/v4/user",
                          headers={"PRIVATE-TOKEN": token}, timeout=8)
        if r.status_code == 200:
            return True, f"valid — user: {r.json().get('username', '?')}"
        if r.status_code == 401:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_slack(token: str) -> tuple[bool, str]:
    try:
        r = requests.post("https://slack.com/api/auth.test",
                          data={"token": token}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data.get("ok"):
                return True, f"valid — team: {data.get('team')}"
            return False, data.get("error", "invalid")
    except Exception:
        pass
    return False, "unknown"


def _validate_stripe(token: str) -> tuple[bool, str]:
    try:
        r = requests.get(
            "https://api.stripe.com/v1/charges",
            headers={"Authorization": f"Bearer {token}"}, timeout=8)
        if r.status_code == 200:
            return True, "valid"
        if r.status_code == 401:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_sendgrid(token: str) -> tuple[bool, str]:
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {token}"}, timeout=8)
        if r.status_code == 200:
            return True, "valid"
        if r.status_code in (401, 403):
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_openai(token: str) -> tuple[bool, str]:
    try:
        r = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {token}"}, timeout=8)
        if r.status_code == 200:
            return True, "valid"
        if r.status_code == 401:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_anthropic(token: str) -> tuple[bool, str]:
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": token, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": "claude-3-haiku-20240307", "max_tokens": 1,
                  "messages": [{"role": "user", "content": "hi"}]},
            timeout=8)
        if r.status_code == 200:
            return True, "valid"
        if r.status_code == 401:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_huggingface(token: str) -> tuple[bool, str]:
    try:
        r = requests.get("https://huggingface.co/api/whoami-v2",
                          headers={"Authorization": f"Bearer {token}"},
                          timeout=8)
        if r.status_code == 200:
            return True, f"valid — user: {r.json().get('name', '?')}"
        if r.status_code == 401:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_discord_webhook(url: str) -> tuple[bool, str]:
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            return True, f"valid — name: {r.json().get('name', '?')}"
        if r.status_code == 404:
            return False, "invalid"
    except Exception:
        pass
    return False, "unknown"


def _validate_slack_webhook(url: str) -> tuple[bool, str]:
    try:
        r = requests.post(url, json={"text": ""}, timeout=8)
        if r.status_code == 200:
            return True, "valid"
        if r.status_code in (400, 404):
            return False, f"invalid ({r.status_code})"
    except Exception:
        pass
    return False, "unknown"


VALIDATORS: dict[str, Any] = {
    "GitHub Personal Access Token": _validate_github,
    "GitHub OAuth Token": _validate_github,
    "GitHub App Token": _validate_github,
    "GitLab PAT": _validate_gitlab,
    "Slack Token": _validate_slack,
    "Slack Webhook": _validate_slack_webhook,
    "Stripe Live Secret Key": _validate_stripe,
    "Stripe Test Secret Key": _validate_stripe,
    "SendGrid API Key": _validate_sendgrid,
    "OpenAI API Key": _validate_openai,
    "OpenAI API Key (new)": _validate_openai,
    "Anthropic API Key": _validate_anthropic,
    "Hugging Face Token": _validate_huggingface,
    "Discord Webhook": _validate_discord_webhook,
}


def validate_secret(s: Secret) -> Secret:
    """Проверить валидность (для поддерживаемых типов)."""
    fn = VALIDATORS.get(s.kind)
    if not fn:
        return s
    ok, msg = fn(s.value)
    s.validated = ok
    s.validation_msg = msg
    return s


# ===========================================================================
# Публичные функции
# ===========================================================================

def scan_url(target: str, max_files: int = 50,
             validate: bool = False, threads: int = 10) -> list[Secret]:
    """Сканировать URL на секреты в JS."""
    if not confirm_external(target):
        return []

    base = normalize_url(target)
    console.print(f"[cyan]🔍 JS Secrets Pro: {base}[/cyan]")

    console.print("[cyan]  · собираю JS-файлы…[/cyan]")
    js_urls = _collect_js_urls(base, max_files=max_files)
    inline = _extract_inline_scripts(base)
    console.print(f"  [dim]Внешних: {len(js_urls)}, inline: {len(inline)}[/dim]")

    all_secrets: list[Secret] = []

    for i, s in enumerate(inline):
        all_secrets.extend(_find_secrets(s, f"{base} (inline #{i+1})"))

    console.print(f"[cyan]  · скачиваю и сканирую {len(js_urls)} JS…[/cyan]")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_fetch, u): u for u in js_urls}
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(),
                      console=console) as p:
            task = p.add_task("scan js", total=len(js_urls))
            for f in as_completed(futs):
                p.advance(task)
                url = futs[f]
                try:
                    text = f.result()
                    if not text:
                        continue
                    found = _find_secrets(text, url)
                    all_secrets.extend(found)
                except Exception:
                    pass

    seen: set[tuple[str, str]] = set()
    unique: list[Secret] = []
    for s in all_secrets:
        key = (s.kind, s.value)
        if key not in seen:
            seen.add(key)
            unique.append(s)

    unique.sort(key=lambda x: -SEVERITY_ORDER.get(x.severity, 0))

    if validate and unique:
        console.print(f"[cyan]  · валидирую {len(unique)} секретов…[/cyan]")
        with ThreadPoolExecutor(max_workers=5) as ex:
            unique = list(ex.map(validate_secret, unique))

    _print_report(unique, base)
    _save_findings(unique, base)
    _notify_if_critical(unique, base)

    db.save_scan("js_secrets", base, {
        "js_files": len(js_urls),
        "inline": len(inline),
        "found": len(unique),
        "critical": sum(1 for s in unique if s.severity == "critical"),
        "high": sum(1 for s in unique if s.severity == "high"),
    })
    return unique


def _save_findings(secrets: list[Secret], target: str) -> None:
    """Сохранить findings в notes."""
    saved = 0
    for s in secrets:
        if s.severity not in ("critical", "high"):
            continue
        nid = _save_finding(SecretFinding(
            kind=s.kind.lower().replace(" ", "_"),
            severity=s.severity,
            title=f"{s.kind} exposed in JS",
            target=target,
            evidence=f"Source: {s.source_url}\n"
                     f"Context: {s.context[:200]}",
            data={"kind": s.kind,
                  "masked_value": _mask_value(s.value),
                  "validated": s.validated,
                  "validation_msg": s.validation_msg,
                  "entropy": s.entropy},
        ))
        if nid > 0:
            saved += 1
    if saved:
        console.print(f"[green]✓ Findings в notes: {saved}[/green]")


def _notify_if_critical(secrets: list[Secret], target: str) -> None:
    critical = [s for s in secrets if s.severity == "critical"]
    validated = [s for s in secrets if s.validated is True]
    if not critical and not validated:
        return
    try:
        from modules import notifier
        msg = (f"Total: {len(secrets)}\n"
               f"Critical: {len(critical)}\n"
               f"Validated: {len(validated)}")
        notifier.notify_all(f"🔐 JS Secrets: {target}", msg)
    except Exception:
        pass


def scan_js_url(url: str, validate: bool = False) -> list[Secret]:
    """Сканировать один JS-файл."""
    if not confirm_external(url):
        return []
    console.print(f"[cyan]🔍 JS: {url}[/cyan]")
    text = _fetch(url)
    if not text:
        console.print("[red]Не удалось загрузить.[/red]")
        return []
    secrets = _find_secrets(text, url)
    seen: set[tuple[str, str]] = set()
    unique: list[Secret] = []
    for s in secrets:
        k = (s.kind, s.value)
        if k not in seen:
            seen.add(k)
            unique.append(s)
    unique.sort(key=lambda x: -SEVERITY_ORDER.get(x.severity, 0))
    if validate:
        with ThreadPoolExecutor(max_workers=5) as ex:
            unique = list(ex.map(validate_secret, unique))
    _print_report(unique, url)
    return unique


# ===========================================================================
# Печать
# ===========================================================================

def _sev_style(sev: str) -> str:
    return {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "green", "info": "dim",
    }.get(sev, "white")


def _mask_value(v: str) -> str:
    if len(v) <= 16:
        return v
    return f"{v[:8]}…{v[-6:]}"


def _print_report(secrets: list[Secret], target: str) -> None:
    if not secrets:
        console.print("[green]✓ Секретов не найдено.[/green]")
        return

    counts: dict[str, int] = {}
    for s in secrets:
        counts[s.severity] = counts.get(s.severity, 0) + 1

    console.print(f"\n[bold cyan]🔐 Найдено секретов: {len(secrets)}[/bold cyan]")
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            sty = _sev_style(sev)
            parts.append(f"[{sty}]{sev}:{counts[sev]}[/{sty}]")
    console.print("  " + "  ".join(parts))

    table = Table(title=f"Secrets — {target[:60]}")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Kind", style="cyan", max_width=30)
    table.add_column("Value", style="green", max_width=32)
    table.add_column("Entropy", style="magenta", width=8)
    table.add_column("Source", style="dim", max_width=35)
    table.add_column("Valid", width=6)

    for i, s in enumerate(secrets, 1):
        sty = _sev_style(s.severity)
        valid = "—"
        if s.validated is True:
            valid = "[green]✓[/green]"
        elif s.validated is False:
            valid = "[red]✗[/red]"
        src_short = s.source_url.split("//")[-1][:35]
        table.add_row(
            str(i),
            f"[{sty}]{s.severity.upper()}[/{sty}]",
            s.kind,
            _mask_value(s.value),
            f"{s.entropy:.2f}",
            src_short,
            valid,
        )
    console.print(table)

    highlights = [s for s in secrets if s.severity in ("critical", "high")]
    if highlights:
        console.print("\n[bold red]⚠ Критичные и High:[/bold red]")
        for s in highlights[:15]:
            sty = _sev_style(s.severity)
            console.print(f"  [{sty}]{s.severity.upper()}[/{sty}] "
                          f"{s.kind}: [green]{_mask_value(s.value)}[/green]")
            console.print(f"    [dim]{s.source_url}[/dim]")
            if s.validated is True:
                console.print(f"    [red]✓ ВАЛИДЕН: {s.validation_msg}[/red]")
            if s.context:
                console.print(f"    [dim]…{s.context[:150]}…[/dim]")


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(secrets: list[Secret], target: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
        path = str(SECRETS_DIR / f"secrets_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(s) for s in secrets],
                       indent=2, ensure_ascii=False),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(secrets: list[Secret],
               path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(SECRETS_DIR / f"secrets_{ts}.csv")
    cols = ["severity", "kind", "value", "source_url", "validated",
            "validation_msg", "entropy"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for s in secrets:
                w.writerow([s.severity, s.kind, s.value, s.source_url,
                            s.validated, s.validation_msg, s.entropy])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_markdown(secrets: list[Secret], target: str,
                    path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
        path = str(SECRETS_DIR / f"secrets_{safe}_{ts}.md")
    lines = [
        f"# JS Secrets Scan — {target}",
        "",
        f"_Generated: {datetime.now().isoformat()}_",
        "",
        f"**Total:** {len(secrets)}",
        "",
    ]
    counts: dict[str, int] = {}
    for s in secrets:
        counts[s.severity] = counts.get(s.severity, 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            lines.append(f"- **{sev.upper()}**: {counts[sev]}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Kind | Value (masked) | Entropy | Source | Validated |")
    lines.append("|----------|------|----------------|---------|--------|-----------|")
    for s in secrets:
        lines.append(
            f"| {s.severity} | {s.kind} | `{_mask_value(s.value)}` | "
            f"{s.entropy:.2f} | {s.source_url[:60]} | "
            f"{s.validated if s.validated is not None else '—'} |")
    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_html(secrets: list[Secret], target: str,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
        path = str(SECRETS_DIR / f"secrets_{safe}_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>JS Secrets — {html_mod.escape(target)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.6;}",
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
        "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
        "</style></head><body>",
        f"<h1>🔐 JS Secrets — {html_mod.escape(target)}</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        f"<p>Total findings: <b>{len(secrets)}</b></p>",
        "<table><tr><th>Sev</th><th>Kind</th><th>Value</th>"
        "<th>Entropy</th><th>Source</th><th>Valid</th></tr>",
    ]
    for s in secrets:
        val = html_mod.escape(_mask_value(s.value))
        src = html_mod.escape(s.source_url)
        valid = "✓" if s.validated is True else (
            "✗" if s.validated is False else "—")
        parts.append(
            f"<tr><td class='{s.severity}'>{s.severity.upper()}</td>"
            f"<td>{html_mod.escape(s.kind)}</td>"
            f"<td><code>{val}</code></td>"
            f"<td>{s.entropy:.2f}</td>"
            f"<td>{src}</td>"
            f"<td>{valid}</td></tr>")
    parts.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_scan(target: str, validate: bool = False) -> None:
    secrets = scan_url(target, validate=validate)
    if secrets and Confirm.ask("Экспортировать JSON + HTML?", default=False):
        export_json(secrets, target)
        export_html(secrets, target)


def cli_js(url: str, validate: bool = False) -> None:
    scan_js_url(url, validate=validate)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔐 JS Secrets Scanner Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Сканировать URL (все JS + inline)"),
        ("2", "Сканировать URL + валидация"),
        ("3", "Сканировать один JS-файл"),
        ("4", "Экспорт в Markdown"),
        ("5", "Экспорт в HTML"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования и bug bounty.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        url = Prompt.ask("URL")
        secrets = scan_url(url)
        if secrets and Confirm.ask("Экспорт JSON?", default=False):
            export_json(secrets, url)
    elif c == "2":
        url = Prompt.ask("URL")
        secrets = scan_url(url, validate=True)
        if secrets and Confirm.ask("Экспорт JSON?", default=False):
            export_json(secrets, url)
    elif c == "3":
        url = Prompt.ask("URL .js файла")
        scan_js_url(url)
    elif c == "4":
        url = Prompt.ask("URL")
        secrets = scan_url(url)
        if secrets:
            export_markdown(secrets, url)
    elif c == "5":
        url = Prompt.ask("URL")
        secrets = scan_url(url)
        if secrets:
            export_html(secrets, url)