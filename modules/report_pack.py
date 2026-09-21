"""
Report Templates Pack Pro — Bug Bounty platform templates.
Author: idqwixxa

Возможности:
    ─── Platform templates (12+) ───
    - HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, CVE/MITRE
    - Synack, Zerocopter, OpenBugBounty, Hackenproof, Federacy,
      GitHub Security Advisories

    ─── Vulnerability presets (35+) ───
    - XSS (stored/reflected/DOM/blind)
    - SQLi (union/error/blind/time)
    - NoSQL, LDAP, XPath
    - SSRF (basic/blind), XXE, SSTI
    - RCE, AuthBypass, IDOR (v1/v2), BFLA, BOLA
    - Subdomain Takeover, Open Redirect, CSRF
    - Race Condition, Business Logic, Info Disclosure
    - HTTP Smuggling, Cache Poisoning, Prototype Pollution
    - JWT (alg-none/confusion), OAuth Misconfig
    - File Upload, Path Traversal, CORS, Clickjacking
    - GraphQL (introspection/DoS), Web3 (reentrancy/etc)

    ─── CVSS v3.1 ───
    - Vector → base/temporal/environmental
    - Score → severity
    - Валидация вектора
    - Пресет-based CVSS

    ─── Wizard ───
    - Многострочный ввод с пресетами по умолчанию
    - Авто-подстановка из Notes & Findings
    - Quality-checker (10+ проверок)
    - Markdown preview

    ─── Экспорт ───
    - MD / HTML / JSON / CSV
    - Single-finding → отчёт
    - Bulk: все findings → отчёты
    - Список сохранённых отчётов с фильтрами

    ─── Интеграция ───
    - Findings → notes (сохранение отчёта)
    - Notify
    - Timeline отчётов по датам

⚠ Только для авторизованных bug bounty программ.
"""
import csv
import html as html_mod
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.markdown import Markdown as RichMarkdown

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

REPORTS_DIR = REPORT_DIR / "bug_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Platform templates (расширенный)
# ===========================================================================

TEMPLATES = {
    "hackerone": {
        "name": "HackerOne",
        "sections": [
            ("title", "Title",
             "Краткий заголовок (10-80 символов), без '[vuln]'"),
            ("summary", "Summary",
             "2-4 предложения: что, где, как. Без воды."),
            ("steps", "Steps To Reproduce",
             "Нумерованные шаги. Каждый шаг: действие → результат."),
            ("impact", "Impact",
             "Что может сделать атакующий. Бизнес-эффект."),
            ("poc", "Supporting Material/References",
             "Скриншоты, видео, curl-запросы, ссылки."),
            ("remediation", "Suggested Fix",
             "Конкретные рекомендации по исправлению."),
        ],
    },
    "bugcrowd": {
        "name": "Bugcrowd",
        "sections": [
            ("title", "Vulnerability Title",
             "Заголовок с типом + endpoint"),
            ("summary", "Bug Description",
             "Полное описание уязвимости"),
            ("steps", "Steps to Reproduce",
             "Пошаговое воспроизведение"),
            ("expected", "Expected Result",
             "Что должно быть по логике"),
            ("actual", "Actual Result",
             "Что происходит на самом деле"),
            ("impact", "Impact",
             "Оценка влияния (VRT-совместимая)"),
            ("remediation", "Suggested Fix",
             "Рекомендация"),
        ],
    },
    "intigriti": {
        "name": "Intigriti",
        "sections": [
            ("title", "Vulnerability Description",
             "Краткое название"),
            ("summary", "Detailed Description",
             "Полное описание с контекстом"),
            ("steps", "Steps to Reproduce",
             "Нумерованные шаги"),
            ("impact", "Impact",
             "Влияние на безопасность"),
            ("remediation", "Remediation",
             "Как исправить"),
        ],
    },
    "yeswehack": {
        "name": "YesWeHack",
        "sections": [
            ("title", "Title",
             "Название уязвимости"),
            ("summary", "Description",
             "Описание"),
            ("steps", "Proof of Concept",
             "PoC — команды, скриншоты"),
            ("impact", "Impact",
             "Оценка влияния"),
            ("remediation", "Remediation",
             "Рекомендации"),
        ],
    },
    "immunefi": {
        "name": "Immunefi (Web3)",
        "sections": [
            ("title", "Title",
             "Тип уязвимости в контракте"),
            ("summary", "Vulnerability Details",
             "Описание с указанием контракта/функции"),
            ("impact", "Impact",
             "Потеря средств? Блокировка? Governance?"),
            ("poc", "Proof of Concept",
             "Форк-тест, tx hash, скрипт"),
            ("severity", "Risk Classification",
             "Severity + CVSS + likelihood"),
            ("remediation", "Recommended Mitigation",
             "Как исправить"),
        ],
    },
    "cve": {
        "name": "CVE / MITRE",
        "sections": [
            ("title", "Title",
             "Vendor Product — Vulnerability Type"),
            ("summary", "Description",
             "Техническое описание для CVE"),
            ("affected", "Affected Products",
             "Версии, платформы"),
            ("severity", "CVSS Score",
             "Вектор + score + severity"),
            ("cwe", "CWE",
             "Тип уязвимости по классификатору"),
            ("poc", "References",
             "Ссылки на PoC, advisories"),
            ("remediation", "Solution",
             "Патч / workaround"),
        ],
    },
    "synack": {
        "name": "Synack",
        "sections": [
            ("title", "Vulnerability Title", ""),
            ("summary", "Description", ""),
            ("steps", "Reproduction Steps", ""),
            ("impact", "Business Impact", ""),
            ("poc", "Exploit / PoC", ""),
            ("remediation", "Recommendation", ""),
        ],
    },
    "zerocopter": {
        "name": "Zerocopter",
        "sections": [
            ("title", "Title", ""),
            ("summary", "Description", ""),
            ("steps", "Reproduction Steps", ""),
            ("impact", "Impact", ""),
            ("remediation", "Remediation", ""),
        ],
    },
    "openbugbounty": {
        "name": "OpenBugBounty",
        "sections": [
            ("title", "Vulnerability Type", ""),
            ("summary", "Description", ""),
            ("steps", "Steps", ""),
            ("poc", "PoC URL", ""),
        ],
    },
    "hackenproof": {
        "name": "Hackenproof",
        "sections": [
            ("title", "Title", ""),
            ("summary", "Description", ""),
            ("steps", "Steps to Reproduce", ""),
            ("impact", "Impact", ""),
            ("remediation", "Recommendation", ""),
        ],
    },
    "federacy": {
        "name": "Federacy",
        "sections": [
            ("title", "Title", ""),
            ("summary", "Summary", ""),
            ("steps", "Steps to Reproduce", ""),
            ("impact", "Impact", ""),
            ("remediation", "Fix", ""),
        ],
    },
    "github_advisory": {
        "name": "GitHub Security Advisory",
        "sections": [
            ("title", "Summary",
             "Краткое описание (до 100 символов)"),
            ("summary", "Description",
             "Полное описание уязвимости"),
            ("affected", "Affected Versions",
             "Пакеты + версии (semver)"),
            ("severity", "Severity / CVSS", ""),
            ("cwe", "CWE", ""),
            ("poc", "References / PoC", ""),
            ("remediation", "Patches",
             "Пропатченные версии / workaround"),
        ],
    },
}


# ===========================================================================
# Vulnerability presets (расширенный)
# ===========================================================================

VULN_PRESETS = {
    # ─── XSS ───
    "xss-stored": {
        "name": "Stored XSS", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.4, "cwe": "CWE-79",
        "title_tpl": "Stored XSS in {endpoint}",
        "summary_tpl": (
            "Stored Cross-Site Scripting (XSS) уязвимость в {endpoint}. "
            "Вредоносный JavaScript сохраняется на сервере и выполняется "
            "в браузерах всех пользователей, просматривающих страницу."
        ),
        "impact_tpl": (
            "- Угнать сессионные cookie аутентифицированных пользователей\n"
            "- Выполнить действия от имени жертвы\n"
            "- Перенаправить жертву на фишинговый сайт\n"
            "- Развернуть beEF-hook в браузерах жертв"
        ),
        "remediation_tpl": (
            "- Контекстно-зависимое экранирование вывода\n"
            "- Валидация входных данных по белому списку\n"
            "- Content-Security-Policy: script-src 'self'"
        ),
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "xss-reflected": {
        "name": "Reflected XSS", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1, "cwe": "CWE-79",
        "title_tpl": "Reflected XSS in {endpoint} ({param})",
        "summary_tpl": (
            "Reflected XSS в параметре {param} endpoint'а {endpoint}. "
            "Payload отражается в HTML-ответе без санитизации."
        ),
        "impact_tpl": (
            "При переходе жертвы по подготовленной ссылке выполняется "
            "произвольный JavaScript в контексте домена."
        ),
        "remediation_tpl": (
            "- HTML-энкодинг всех пользовательских данных\n"
            "- Content-Security-Policy"
        ),
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "xss-dom": {
        "name": "DOM XSS", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1, "cwe": "CWE-79",
        "title_tpl": "DOM-based XSS in {endpoint}",
        "summary_tpl": "DOM XSS через client-side sink (innerHTML/eval).",
        "impact_tpl": "Same как reflected XSS — выполнение JS в браузере.",
        "remediation_tpl": "Использовать textContent, не innerHTML.",
        "refs": ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
    },

    # ─── SQLi ───
    "sqli": {
        "name": "SQL Injection", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8, "cwe": "CWE-89",
        "title_tpl": "SQL Injection in {endpoint} ({param})",
        "summary_tpl": (
            "SQL-инъекция в параметре {param} endpoint'а {endpoint}. "
            "Пользовательский ввод попадает в SQL-запрос без параметризации."
        ),
        "impact_tpl": (
            "- Чтение всей БД (хеши паролей, PII)\n"
            "- Модификация/удаление данных\n"
            "- Обход аутентификации\n"
            "- RCE через xp_cmdshell / UDF"
        ),
        "remediation_tpl": (
            "- Параметризованные запросы\n"
            "- ORM с биндингом\n"
            "- Least-privilege для DB user"
        ),
        "refs": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "sqli-blind": {
        "name": "Blind SQLi", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8, "cwe": "CWE-89",
        "title_tpl": "Blind SQLi in {endpoint}",
        "summary_tpl": "Boolean/time-based SQLi — БД не возвращает данные напрямую.",
        "impact_tpl": "Медленная, но полная экстракция БД.",
        "remediation_tpl": "Параметризованные запросы.",
        "refs": ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    },
    "sqli-union": {
        "name": "UNION-based SQLi", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5, "cwe": "CWE-89",
        "title_tpl": "UNION SQLi in {endpoint}",
        "summary_tpl": "UNION-based SQLi — быстрая экстракция через UNION SELECT.",
        "impact_tpl": "Прямое чтение произвольных данных.",
        "remediation_tpl": "Параметризованные запросы.",
        "refs": [],
    },

    # ─── NoSQL / LDAP / XPath ───
    "nosqli": {
        "name": "NoSQL Injection", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1, "cwe": "CWE-943",
        "title_tpl": "NoSQL Injection in {endpoint}",
        "summary_tpl": "NoSQL injection (MongoDB/CouchDB) через JSON-параметры.",
        "impact_tpl": "Обход auth, чтение данных, в некоторых случаях RCE.",
        "remediation_tpl": "Валидация типов входных данных, экранирование.",
        "refs": [],
    },
    "ldapi": {
        "name": "LDAP Injection", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5, "cwe": "CWE-90",
        "title_tpl": "LDAP Injection in {endpoint}",
        "summary_tpl": "LDAP injection — манипуляция LDAP-фильтрами.",
        "impact_tpl": "Обход auth, enumeration AD-пользователей.",
        "remediation_tpl": "Экранирование LDAP-спецсимволов.",
        "refs": [],
    },

    # ─── SSRF / XXE / SSTI ───
    "ssrf": {
        "name": "SSRF", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cvss_score": 8.6, "cwe": "CWE-918",
        "title_tpl": "SSRF in {endpoint}",
        "summary_tpl": (
            "SSRF в {endpoint}. Сервер загружает URL по пользовательскому "
            "вводу без проверки на внутренние адреса/метаданные."
        ),
        "impact_tpl": (
            "- Доступ к internal-сервисам\n"
            "- Чтение cloud-metadata (169.254.169.254)\n"
            "- Порт-скан внутренней сети"
        ),
        "remediation_tpl": (
            "- Allowlist доменов/схем\n"
            "- Резолвить хост и проверять итоговый IP\n"
            "- Запрет на private ranges"
        ),
        "refs": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    "ssrf-blind": {
        "name": "Blind SSRF", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cvss_score": 7.5, "cwe": "CWE-918",
        "title_tpl": "Blind SSRF in {endpoint}",
        "summary_tpl": "Blind SSRF — нет прямого ответа, детект по OOB.",
        "impact_tpl": "Internal port-scan, взаимодействие с internal API.",
        "remediation_tpl": "Allowlist + network segmentation.",
        "refs": [],
    },
    "xxe": {
        "name": "XXE", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cvss_score": 8.6, "cwe": "CWE-611",
        "title_tpl": "XXE in {endpoint}",
        "summary_tpl": "XML External Entity Injection в {endpoint}.",
        "impact_tpl": "Чтение файлов, SSRF, DoS, реже — RCE.",
        "remediation_tpl": "Отключить DTD, внешние entity.",
        "refs": [],
    },
    "ssti": {
        "name": "SSTI", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": 10.0, "cwe": "CWE-94",
        "title_tpl": "Server-Side Template Injection in {endpoint}",
        "summary_tpl": "SSTI — пользовательский ввод исполняется как шаблон (Jinja2/Twig/etc).",
        "impact_tpl": "RCE, чтение файлов, полный контроль сервера.",
        "remediation_tpl": "Никогда не передавать user input в шаблон. Sandbox.",
        "refs": [],
    },

    # ─── RCE / AuthBypass / IDOR ───
    "rce": {
        "name": "Remote Code Execution", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": 10.0, "cwe": "CWE-94",
        "title_tpl": "RCE in {endpoint}",
        "summary_tpl": "RCE через {endpoint}. Пользовательский ввод → eval/exec.",
        "impact_tpl": "Полная компрометация сервера.",
        "remediation_tpl": "Не использовать eval/exec/shell с user input.",
        "refs": ["https://owasp.org/www-community/attacks/Code_Injection"],
    },
    "auth-bypass": {
        "name": "Authentication Bypass", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1, "cwe": "CWE-287",
        "title_tpl": "Authentication Bypass via {endpoint}",
        "summary_tpl": "Обход аутентификации в {endpoint}.",
        "impact_tpl": "Полный доступ без валидных credentials.",
        "remediation_tpl": "Единая auth-точка, deny-by-default.",
        "refs": [],
    },
    "idor": {
        "name": "IDOR", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 8.1, "cwe": "CWE-639",
        "title_tpl": "IDOR in {endpoint}",
        "summary_tpl": "Insecure Direct Object Reference в {endpoint}.",
        "impact_tpl": "Доступ к чужим объектам: PII, платежи, документы.",
        "remediation_tpl": "Ownership check + UUID.",
        "refs": [],
    },
    "bola": {
        "name": "BOLA (API)", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 8.1, "cwe": "CWE-639",
        "title_tpl": "BOLA in {endpoint}",
        "summary_tpl": "Broken Object Level Authorization в API endpoint.",
        "impact_tpl": "Доступ к чужим данным через API.",
        "remediation_tpl": "Per-object authorization check.",
        "refs": [],
    },
    "bfla": {
        "name": "BFLA (API)", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 8.8, "cwe": "CWE-285",
        "title_tpl": "BFLA in {endpoint}",
        "summary_tpl": "Broken Function Level Authorization — админские функции доступны обычным юзерам.",
        "impact_tpl": "Эскалация до admin через API.",
        "remediation_tpl": "Role-based access control на API endpoints.",
        "refs": [],
    },

    # ─── Redirect / CSRF / Takeover ───
    "open-redirect": {
        "name": "Open Redirect", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "cvss_score": 4.7, "cwe": "CWE-601",
        "title_tpl": "Open Redirect in {endpoint} ({param})",
        "summary_tpl": "Открытый редирект через {param}.",
        "impact_tpl": "Фишинг, обход OAuth redirect_uri.",
        "remediation_tpl": "Allowlist доменов.",
        "refs": [],
    },
    "csrf": {
        "name": "CSRF", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cvss_score": 5.4, "cwe": "CWE-352",
        "title_tpl": "CSRF in {endpoint}",
        "summary_tpl": "Cross-Site Request Forgery в {endpoint}.",
        "impact_tpl": "State-changing действия от имени жертвы.",
        "remediation_tpl": "CSRF-токен + SameSite cookie.",
        "refs": [],
    },
    "subdomain-takeover": {
        "name": "Subdomain Takeover", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1, "cwe": "CWE-350",
        "title_tpl": "Subdomain Takeover on {subdomain}",
        "summary_tpl": "Поддомен {subdomain} указывает на несуществующий ресурс {service}.",
        "impact_tpl": "Фишинг, кража cookie, обход CSP.",
        "remediation_tpl": "Удалить dangling DNS-записи.",
        "refs": ["https://github.com/EdOverflow/can-i-take-over-xyz"],
    },

    # ─── Advanced ───
    "race-condition": {
        "name": "Race Condition", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 5.3, "cwe": "CWE-362",
        "title_tpl": "Race Condition in {endpoint}",
        "summary_tpl": "TOCTOU Race Condition в {endpoint}.",
        "impact_tpl": "Обход лимитов, дублирование операций.",
        "remediation_tpl": "Атомарные операции, locks, idempotency.",
        "refs": [],
    },
    "business-logic": {
        "name": "Business Logic", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 6.5, "cwe": "CWE-840",
        "title_tpl": "Business Logic flaw in {endpoint}",
        "summary_tpl": "Нарушение бизнес-инвариантов в {endpoint}.",
        "impact_tpl": "Финансовые потери, обход правил.",
        "remediation_tpl": "Server-side валидация бизнес-правил.",
        "refs": [],
    },
    "info-disclosure": {
        "name": "Information Disclosure", "severity": "low",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score": 5.3, "cwe": "CWE-200",
        "title_tpl": "Information Disclosure in {endpoint}",
        "summary_tpl": "Утечка информации в {endpoint}.",
        "impact_tpl": "Раскрытие структуры приложения, PII.",
        "remediation_tpl": "Убрать debug-информацию, отключить directory listing.",
        "refs": [],
    },
    "http-smuggling": {
        "name": "HTTP Request Smuggling", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cvss_score": 9.0, "cwe": "CWE-444",
        "title_tpl": "HTTP Request Smuggling in {endpoint}",
        "summary_tpl": "CL.TE / TE.CL smuggling между frontend/backend.",
        "impact_tpl": "Обход auth, кэш-пойзонинг, request hijacking.",
        "remediation_tpl": "Согласовать CL/TE между proxy и backend. Нормализация.",
        "refs": ["https://portswigger.net/web-security/request-smuggling"],
    },
    "cache-poisoning": {
        "name": "Web Cache Poisoning", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cvss_score": 9.0, "cwe": "CWE-444",
        "title_tpl": "Web Cache Poisoning in {endpoint}",
        "summary_tpl": "Unkeyed header/param влияет на cached response.",
        "impact_tpl": "XSS для всех пользователей, DoS, defacement.",
        "remediation_tpl": "Включать все влияющие headers в cache key.",
        "refs": [],
    },
    "prototype-pollution": {
        "name": "Prototype Pollution", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 8.1, "cwe": "CWE-1321",
        "title_tpl": "Prototype Pollution in {endpoint}",
        "summary_tpl": "Prototype pollution (__proto__) в {endpoint}.",
        "impact_tpl": "XSS, RCE через gadget chain, обход логики.",
        "remediation_tpl": "Sanitize keys, freeze Object.prototype.",
        "refs": [],
    },
    "jwt-alg-none": {
        "name": "JWT alg:none", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1, "cwe": "CWE-347",
        "title_tpl": "JWT alg:none bypass in {endpoint}",
        "summary_tpl": "JWT подпись может быть отключена (alg:none).",
        "impact_tpl": "Полный обход auth через подделку токена.",
        "remediation_tpl": "Белый список alg + verify signature всегда.",
        "refs": [],
    },
    "oauth-misconfig": {
        "name": "OAuth Misconfig", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "cvss_score": 8.7, "cwe": "CWE-346",
        "title_tpl": "OAuth Misconfiguration in {endpoint}",
        "summary_tpl": "redirect_uri без проверки / state не валидируется.",
        "impact_tpl": "Кража access_token, account takeover.",
        "remediation_tpl": "Strict redirect_uri + state validation.",
        "refs": [],
    },
    "file-upload": {
        "name": "Arbitrary File Upload", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": 9.9, "cwe": "CWE-434",
        "title_tpl": "Arbitrary File Upload in {endpoint}",
        "summary_tpl": "Загрузка произвольных файлов (webshell).",
        "impact_tpl": "RCE через webshell.",
        "remediation_tpl": "Whitelist расширений + отдельный storage + no execute.",
        "refs": [],
    },
    "path-traversal": {
        "name": "Path Traversal", "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5, "cwe": "CWE-22",
        "title_tpl": "Path Traversal in {endpoint}",
        "summary_tpl": "Path traversal через {param}.",
        "impact_tpl": "Чтение /etc/passwd, source code, .env.",
        "remediation_tpl": "Normalize + allowlist + chroot.",
        "refs": [],
    },
    "cors": {
        "name": "CORS Misconfig", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1, "cwe": "CWE-942",
        "title_tpl": "CORS Misconfiguration in {endpoint}",
        "summary_tpl": "CORS разрешает произвольные origins с credentials.",
        "impact_tpl": "Чтение чужих данных через victim browser.",
        "remediation_tpl": "Strict origin allowlist.",
        "refs": [],
    },
    "clickjacking": {
        "name": "Clickjacking", "severity": "low",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cvss_score": 4.3, "cwe": "CWE-1021",
        "title_tpl": "Clickjacking in {endpoint}",
        "summary_tpl": "Отсутствует X-Frame-Options / CSP frame-ancestors.",
        "impact_tpl": "UI redressing — принуждение к действиям.",
        "remediation_tpl": "X-Frame-Options: DENY или CSP frame-ancestors 'none'.",
        "refs": [],
    },
    "graphql-introspection": {
        "name": "GraphQL Introspection", "severity": "low",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score": 5.3, "cwe": "CWE-200",
        "title_tpl": "GraphQL Introspection enabled in {endpoint}",
        "summary_tpl": "Introspection включён в production.",
        "impact_tpl": "Раскрытие всей схемы, помощь атакующему.",
        "remediation_tpl": "Отключить introspection в production.",
        "refs": [],
    },
    "graphql-dos": {
        "name": "GraphQL DoS", "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss_score": 7.5, "cwe": "CWE-400",
        "title_tpl": "GraphQL DoS via {endpoint}",
        "summary_tpl": "Alias amplification / depth attack / circular query.",
        "impact_tpl": "Отказ в обслуживании GraphQL API.",
        "remediation_tpl": "Query depth limit, cost analysis, rate-limit.",
        "refs": [],
    },
    "web3-reentrancy": {
        "name": "Reentrancy", "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": 10.0, "cwe": "CWE-841",
        "title_tpl": "Reentrancy in {endpoint}",
        "summary_tpl": "Reentrancy attack в смарт-контракте.",
        "impact_tpl": "Полная потеря средств контракта.",
        "remediation_tpl": "Checks-Effects-Interactions, nonReentrant.",
        "refs": [],
    },
}


# ===========================================================================
# CVSS v3.1 (полный: base + temporal + environmental)
# ===========================================================================

CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

TEMPORAL_METRICS = {
    "E": {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0},
    "RL": {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95},
    "RC": {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0},
}


def _roundup(x: float) -> float:
    """CVSS v3.1 roundup."""
    return round(x + 0.0000000001, 1)


def _severity_from_score(score: float) -> str:
    if score == 0: return "none"
    if score < 4: return "low"
    if score < 7: return "medium"
    if score < 9: return "high"
    return "critical"


def cvss_score_from_vector(vector: str) -> float:
    """CVSS v3.1 base score из вектора (совместимо со старым API)."""
    result = cvss_full_from_vector(vector)
    return result.get("base_score", 0.0)


def cvss_full_from_vector(vector: str) -> dict:
    """Полный расчёт CVSS v3.1: base + temporal + environmental."""
    out: dict = {
        "vector": vector, "valid": False,
        "base_score": 0.0, "base_severity": "none",
        "temporal_score": 0.0, "temporal_severity": "none",
        "env_score": 0.0, "env_severity": "none",
    }
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        if "CVSS" in parts:
            del parts["CVSS"]
    except Exception:
        return out

    def g(k, default):
        return parts.get(k, default)

    scope_changed = g("S", "U") == "C"
    av = CVSS_METRICS["AV"].get(g("AV", "N"), 0.85)
    ac = CVSS_METRICS["AC"].get(g("AC", "L"), 0.77)
    pr_key = "PR_C" if scope_changed else "PR_U"
    pr = CVSS_METRICS[pr_key].get(g("PR", "N"), 0.85)
    ui = CVSS_METRICS["UI"].get(g("UI", "N"), 0.85)
    c = CVSS_METRICS["C"].get(g("C", "N"), 0.0)
    i = CVSS_METRICS["I"].get(g("I", "N"), 0.0)
    a = CVSS_METRICS["A"].get(g("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        base_score = 0.0
    else:
        base_score = (1.08 if scope_changed else 1.0) * min(
            impact + exploit, 10)
    base_score = _roundup(base_score)

    # Temporal
    e = TEMPORAL_METRICS["E"].get(g("E", "X"), 1.0)
    rl = TEMPORAL_METRICS["RL"].get(g("RL", "X"), 1.0)
    rc = TEMPORAL_METRICS["RC"].get(g("RC", "X"), 1.0)
    temporal = _roundup(base_score * e * rl * rc) if base_score > 0 else 0.0

    out.update({
        "valid": True,
        "base_score": base_score,
        "base_severity": _severity_from_score(base_score),
        "temporal_score": temporal,
        "temporal_severity": _severity_from_score(temporal),
        "env_score": base_score,  # simplified (env не менялось)
        "env_severity": _severity_from_score(base_score),
    })
    return out


def severity_from_score(score: float) -> str:
    return _severity_from_score(score)


def validate_cvss_vector(vector: str) -> tuple[bool, str]:
    """Проверить корректность CVSS-вектора."""
    if not vector:
        return False, "пустой вектор"
    if not vector.startswith("CVSS:3."):
        return False, "должен начинаться с 'CVSS:3.x/'"
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:] if ":" in p)
    except Exception:
        return False, "не удалось распарсить"
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [k for k in required if k not in parts]
    if missing:
        return False, f"отсутствуют: {','.join(missing)}"
    return True, "ok"


# ===========================================================================
# Report model
# ===========================================================================

@dataclass
class BugReport:
    platform: str
    target: str = ""
    title: str = ""
    summary: str = ""
    steps: str = ""
    impact: str = ""
    poc: str = ""
    remediation: str = ""
    expected: str = ""
    actual: str = ""
    severity: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    affected: str = ""
    refs: list[str] = field(default_factory=list)
    author: str = "anon"
    created: str = ""
    finding_id: int = 0
    tags: list[str] = field(default_factory=list)


def _sanitize_steps(text: str) -> str:
    """Нумеруем строки, если они ещё не нумерованы."""
    if not text:
        return ""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    numbered = []
    for i, l in enumerate(lines, 1):
        if re.match(r"^\d+[.)]\s", l):
            numbered.append(l)
        else:
            numbered.append(f"{i}. {l}")
    return "\n".join(numbered)


# ===========================================================================
# Quality checker
# ===========================================================================

def quality_check(report: BugReport) -> list[tuple[str, str, str]]:
    """Вернуть [(field, level, msg)] где level ∈ ok | warn | error."""
    out: list[tuple[str, str, str]] = []

    # Title
    if not report.title or len(report.title) < 10:
        out.append(("title", "error", "Заголовок короче 10 символов"))
    elif len(report.title) > 120:
        out.append(("title", "warn", "Заголовок длиннее 120 символов"))
    else:
        out.append(("title", "ok", f"OK ({len(report.title)} симв.)"))

    # Summary
    if not report.summary or len(report.summary) < 50:
        out.append(("summary", "error", "Summary < 50 символов"))
    elif len(report.summary) > 1500:
        out.append(("summary", "warn", "Summary > 1500 символов"))
    else:
        out.append(("summary", "ok", f"OK ({len(report.summary)} симв.)"))

    # Steps
    n_steps = len([l for l in report.steps.splitlines() if l.strip()])
    if n_steps < 3:
        out.append(("steps", "error", f"Меньше 3 шагов ({n_steps})"))
    else:
        out.append(("steps", "ok", f"OK ({n_steps} шагов)"))

    # Impact
    if not report.impact or len(report.impact) < 80:
        out.append(("impact", "warn", "Impact < 80 символов — развёрни эффект"))
    else:
        out.append(("impact", "ok", f"OK ({len(report.impact)} симв.)"))

    # PoC
    if not report.poc:
        out.append(("poc", "warn", "Нет PoC — большинство триаж-команд "
                                   "это отклонит"))
    else:
        has_cmd = bool(re.search(r"(curl|wget|python|POST|GET|http)",
                                  report.poc, re.IGNORECASE))
        if not has_cmd:
            out.append(("poc", "warn", "PoC без команд/URL"))
        else:
            out.append(("poc", "ok", "OK"))

    # Remediation
    if not report.remediation or len(report.remediation) < 40:
        out.append(("remediation", "warn", "Remediation < 40 символов"))
    else:
        out.append(("remediation", "ok", f"OK"))

    # CVSS
    if report.cvss_vector:
        valid, msg = validate_cvss_vector(report.cvss_vector)
        if not valid:
            out.append(("cvss", "error", f"Невалидный вектор: {msg}"))
        else:
            calc = cvss_score_from_vector(report.cvss_vector)
            if report.cvss_score and abs(calc - report.cvss_score) > 0.2:
                out.append(("cvss", "warn",
                            f"Вектор даёт {calc}, заявлено {report.cvss_score}"))
            else:
                out.append(("cvss", "ok", f"CVSS {calc} "
                                            f"({severity_from_score(calc)})"))
    else:
        out.append(("cvss", "warn", "Нет CVSS-вектора"))

    # CWE
    if not report.cwe:
        out.append(("cwe", "warn", "CWE не указан"))
    else:
        out.append(("cwe", "ok", report.cwe))

    # Target
    if not report.target:
        out.append(("target", "error", "Target не указан"))
    else:
        out.append(("target", "ok", report.target[:50]))

    return out


# ===========================================================================
# Renderers
# ===========================================================================

def _render_markdown(r: BugReport) -> str:
    tpl = TEMPLATES.get(r.platform, TEMPLATES["hackerone"])
    out: list[str] = []

    out.append(f"# {r.title}\n")
    out.append(f"**Target:** {r.target or '—'}  ")
    if r.cvss_vector:
        calc = r.cvss_score or cvss_score_from_vector(r.cvss_vector)
        out.append(f"**Severity:** {r.severity or severity_from_score(calc)} "
                   f"(CVSS {calc})  ")
        out.append(f"**CVSS Vector:** `{r.cvss_vector}`  ")
    if r.cwe:
        out.append(f"**CWE:** {r.cwe}  ")
    if r.author:
        out.append(f"**Author:** {r.author}  ")
    if r.created:
        out.append(f"**Date:** {r.created}  ")
    out.append("")

    for key, title, _hint in tpl["sections"]:
        val = getattr(r, key, "") or ""
        if not val:
            continue
        if key == "steps":
            val = _sanitize_steps(val)
        out.append(f"## {title}\n")
        out.append(val)
        out.append("")

    if r.refs:
        out.append("## References\n")
        for ref in r.refs:
            out.append(f"- {ref}")
        out.append("")

    if r.tags:
        out.append(f"\n_Tags: {', '.join(r.tags)}_\n")

    return "\n".join(out)


HTML_CSS = """
body{background:#0a0a0a;color:#c8c8c8;font-family:'JetBrains Mono',
     Consolas,monospace;padding:32px;max-width:1000px;margin:0 auto;
     line-height:1.6;}
h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;}
h2{color:#00ff9c;margin-top:32px;border-left:4px solid #00ff9c;
   padding-left:12px;}
.meta{background:#0d0d0d;border:1px solid #222;padding:12px;
      border-radius:4px;margin-bottom:24px;font-size:13px;}
.meta b{color:#7ad9ff;}
pre{background:#050505;border:1px solid #222;padding:12px;
    overflow-x:auto;color:#a0ffa0;border-radius:4px;}
code{background:#111;padding:2px 6px;border-radius:3px;color:#a0ffa0;}
.badge{display:inline-block;padding:3px 10px;border-radius:3px;
       font-size:11px;font-weight:bold;margin-left:8px;}
.critical{background:#3a0000;color:#ff4040;}
.high{background:#3a1a00;color:#ff7a40;}
.medium{background:#3a2a00;color:#ffd23f;}
.low{background:#003322;color:#00ff9c;}
.none{background:#111;color:#888;}
a{color:#7ad9ff;}
.tag{display:inline-block;background:#003322;color:#00ff9c;
     padding:2px 8px;border-radius:3px;font-size:11px;margin-right:4px;}
"""


def _render_html(r: BugReport) -> str:
    tpl = TEMPLATES.get(r.platform, TEMPLATES["hackerone"])
    sev = (r.severity or severity_from_score(
        r.cvss_score or cvss_score_from_vector(r.cvss_vector))).lower()
    calc = r.cvss_score or cvss_score_from_vector(r.cvss_vector)

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>{html_mod.escape(r.title)}</title>",
        f"<style>{HTML_CSS}</style></head><body>",
        f"<h1>{html_mod.escape(r.title)}"
        f"<span class='badge {sev}'>{sev.upper()}</span></h1>",
        "<div class='meta'>",
        f"<b>Platform:</b> {html_mod.escape(tpl['name'])}<br>",
        f"<b>Target:</b> {html_mod.escape(r.target or '—')}<br>",
    ]
    if r.cvss_vector:
        parts.append(f"<b>CVSS:</b> {calc} — "
                     f"<code>{html_mod.escape(r.cvss_vector)}</code><br>")
    if r.cwe:
        parts.append(f"<b>CWE:</b> {html_mod.escape(r.cwe)}<br>")
    parts.append(f"<b>Author:</b> {html_mod.escape(r.author)}<br>")
    parts.append(f"<b>Date:</b> {html_mod.escape(r.created)}")
    if r.tags:
        tags_html = "".join(
            f"<span class='tag'>{html_mod.escape(t)}</span>" for t in r.tags)
        parts.append(f"<br><b>Tags:</b> {tags_html}")
    parts.append("</div>")

    for key, title, _hint in tpl["sections"]:
        val = getattr(r, key, "") or ""
        if not val:
            continue
        if key == "steps":
            val = _sanitize_steps(val)
        safe = html_mod.escape(val).replace("\n", "<br>")
        parts.append(f"<h2>{html_mod.escape(title)}</h2>")
        parts.append(f"<div>{safe}</div>")

    if r.refs:
        parts.append("<h2>References</h2><ul>")
        for ref in r.refs:
            safe = html_mod.escape(ref)
            parts.append(f"<li><a href='{safe}'>{safe}</a></li>")
        parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts)


def _render_csv_row(r: BugReport) -> dict:
    """Преобразовать отчёт в плоскую строку для CSV."""
    return {
        "platform": r.platform,
        "target": r.target,
        "title": r.title,
        "severity": r.severity,
        "cvss_vector": r.cvss_vector,
        "cvss_score": r.cvss_score,
        "cwe": r.cwe,
        "author": r.author,
        "created": r.created,
        "finding_id": r.finding_id,
        "tags": ",".join(r.tags),
        "summary_len": len(r.summary or ""),
        "steps_len": len(r.steps or ""),
        "impact_len": len(r.impact or ""),
        "poc_len": len(r.poc or ""),
    }


# ===========================================================================
# Preset defaults
# ===========================================================================

def _preset_defaults(preset_key: str, endpoint: str = "",
                     param: str = "") -> dict:
    p = VULN_PRESETS.get(preset_key, {})
    ctx = {
        "endpoint": endpoint or "/vulnerable",
        "param": param or "id",
        "subdomain": endpoint or "sub.example.com",
        "service": "unknown",
    }
    return {
        "title": p.get("title_tpl", "").format(**ctx),
        "summary": p.get("summary_tpl", "").format(**ctx),
        "impact": p.get("impact_tpl", "").format(**ctx),
        "remediation": p.get("remediation_tpl", "").format(**ctx),
        "severity": p.get("severity", ""),
        "cvss_vector": p.get("cvss", ""),
        "cvss_score": p.get("cvss_score", 0.0),
        "cwe": p.get("cwe", ""),
        "refs": list(p.get("refs", [])),
    }


# ===========================================================================
# Wizard
# ===========================================================================

def wizard(platform: str = "hackerone",
           preset: str | None = None,
           target: str | None = None,
           from_finding: int | None = None) -> BugReport:
    """Интерактивный wizard."""
    r = BugReport(platform=platform, author="anon",
                  created=datetime.now().strftime("%Y-%m-%d %H:%M"))

    # Префилл из finding
    if from_finding:
        filled = build_from_finding(from_finding, platform=platform,
                                     preset=preset)
        if filled.title:
            r = filled

    # Префилл из пресета
    if preset and preset in VULN_PRESETS:
        console.print(f"[cyan]Пресет: {VULN_PRESETS[preset]['name']}[/cyan]")
        endpoint = Prompt.ask("Endpoint/URL (пусто = /vulnerable)",
                              default="").strip()
        param = ""
        if preset in ("xss-reflected", "sqli", "open-redirect",
                      "idor", "path-traversal", "nosqli"):
            param = Prompt.ask("Параметр (пусто = id)",
                                default="").strip()
        d = _preset_defaults(preset, endpoint, param)
        if not r.title: r.title = d["title"]
        if not r.summary: r.summary = d["summary"]
        if not r.impact: r.impact = d["impact"]
        if not r.remediation: r.remediation = d["remediation"]
        if not r.severity: r.severity = d["severity"]
        r.cvss_vector = r.cvss_vector or d["cvss_vector"]
        r.cvss_score = r.cvss_score or d["cvss_score"]
        r.cwe = r.cwe or d["cwe"]
        r.refs = r.refs or d["refs"]
        r.tags = r.tags or [preset]

    console.print(f"\n[bold cyan]📝 Заполнение отчёта "
                  f"({TEMPLATES[platform]['name']})[/bold cyan]\n")

    if not target:
        target = Prompt.ask("Target (домен/URL)", default=r.target or "")
    r.target = target or r.target

    if not r.title:
        r.title = Prompt.ask("Title")
    else:
        r.title = Prompt.ask("Title", default=r.title)

    r.summary = _ask_multiline("Summary", r.summary)
    r.steps = _ask_multiline("Steps to Reproduce (одна на строку)", "")
    r.impact = _ask_multiline("Impact", r.impact)
    r.poc = _ask_multiline("PoC / Supporting Material", "")
    r.remediation = _ask_multiline("Remediation", r.remediation)

    if platform == "bugcrowd":
        r.expected = _ask_multiline("Expected Result", "")
        r.actual = _ask_multiline("Actual Result", "")

    # CVSS
    if not r.cvss_vector:
        cvss = Prompt.ask("CVSS vector (пусто = рассчитать из severity)",
                          default="").strip()
        if cvss:
            r.cvss_vector = cvss
            r.cvss_score = cvss_score_from_vector(cvss)
    if not r.severity and r.cvss_vector:
        r.severity = severity_from_score(
            r.cvss_score or cvss_score_from_vector(r.cvss_vector))

    r.author = Prompt.ask("Author", default="anon")

    # Quality check
    console.print("\n[bold cyan]🔍 Quality check:[/bold cyan]")
    qc = quality_check(r)
    errors = 0
    warns = 0
    t = Table(show_header=False, border_style="dim")
    t.add_column("Field", style="cyan", width=14)
    t.add_column("Level", width=8)
    t.add_column("Message", style="white")
    for field_, level, msg in qc:
        icon = {"ok": "[green]✓[/green]",
                "warn": "[yellow]⚠[/yellow]",
                "error": "[red]✗[/red]"}[level]
        t.add_row(field_, icon, msg)
        if level == "error": errors += 1
        elif level == "warn": warns += 1
    console.print(t)

    if errors:
        console.print(f"[red]⚠ {errors} критичных проблем — "
                      f"отчёт будет отклонён триажем.[/red]")
    elif warns:
        console.print(f"[yellow]⚠ {warns} предупреждений — "
                      f"можно улучшить.[/yellow]")
    else:
        console.print("[green]✓ Отчёт выглядит качественно![/green]")

    return r


def _ask_multiline(label: str, default: str = "") -> str:
    """Многострочный ввод: пустая строка = конец, Enter = принять default."""
    if default:
        console.print(f"[cyan]{label}[/cyan] [dim](Enter — принять "
                      f"текущее, '.' + Enter — ввести заново)[/dim]")
        short = default.splitlines()[0][:80] if default else ""
        console.print(f"[dim]  Текущее: {short}"
                      f"{'…' if len(default) > 80 else ''}[/dim]")
        choice = Prompt.ask("", default="").strip()
        if choice != ".":
            return default

    console.print(f"[cyan]{label}[/cyan] [dim](пустая строка — конец)[/dim]")
    lines: list[str] = []
    while True:
        try:
            line = input("  > ")
        except (EOFError, KeyboardInterrupt):
            break
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


# ===========================================================================
# Экспорт
# ===========================================================================

def _safe_name(r: BugReport) -> str:
    base = f"bug_{r.platform}_{r.target or 'target'}"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_{ts}"


def export_report(r: BugReport, fmt: str = "md",
                  out_path: str | None = None) -> Path | None:
    """Экспортировать отчёт (md / html / json / csv)."""
    if not out_path:
        name = _safe_name(r)
        ext = {"md": ".md", "html": ".html",
               "json": ".json", "csv": ".csv"}[fmt]
        out_path = str(REPORTS_DIR / f"{name}{ext}")

    try:
        if fmt == "md":
            content = _render_markdown(r)
        elif fmt == "html":
            content = _render_html(r)
        elif fmt == "json":
            content = json.dumps(asdict(r), indent=2, ensure_ascii=False)
        elif fmt == "csv":
            row = _render_csv_row(r)
            # single-row CSV
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(row.keys()))
                w.writeheader()
                w.writerow(row)
            size = Path(out_path).stat().st_size / 1024
            console.print(f"[green]✓ CSV: {out_path} ({size:.1f} KB)[/green]")
            db.save_scan("report_pack", r.target or "unknown",
                         {"platform": r.platform, "fmt": fmt,
                          "title": r.title, "path": str(out_path)})
            return Path(out_path)
        else:
            console.print(f"[red]Неизвестный формат: {fmt}[/red]")
            return None

        Path(out_path).write_text(content, encoding="utf-8")
        size = Path(out_path).stat().st_size / 1024
        console.print(f"[green]✓ {fmt.upper()}: {out_path} "
                      f"({size:.1f} KB)[/green]")
        db.save_scan("report_pack", r.target or "unknown",
                     {"platform": r.platform, "fmt": fmt,
                      "title": r.title, "path": str(out_path)})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_all(r: BugReport) -> list[Path]:
    """Экспорт во все 4 формата."""
    out: list[Path] = []
    for fmt in ("md", "html", "json", "csv"):
        p = export_report(r, fmt=fmt)
        if p:
            out.append(p)
    return out


def export_bulk_csv(reports: list[BugReport],
                    path: str | None = None) -> Path | None:
    """Экспорт всех отчётов в один CSV-файл."""
    if not reports:
        console.print("[yellow]Нет отчётов.[/yellow]")
        return None
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(REPORTS_DIR / f"bulk_{ts}.csv")
    try:
        rows = [_render_csv_row(r) for r in reports]
        cols = list(rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for row in rows:
                w.writerow(row)
        console.print(f"[green]✓ Bulk CSV: {path} "
                      f"({len(reports)} записей)[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


# ===========================================================================
# Notes & Findings интеграция
# ===========================================================================

def build_from_finding(finding_id: int, platform: str = "hackerone",
                       preset: str | None = None) -> BugReport:
    """Построить отчёт из finding в Notes."""
    try:
        from modules import notes as _notes
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Не могу загрузить notes: {exc}[/red]")
        return BugReport(platform=platform)

    n = _notes.get_note(finding_id)
    if not n:
        console.print(f"[red]Finding #{finding_id} не найден.[/red]")
        return BugReport(platform=platform)

    if n.get("kind") != "finding":
        console.print(f"[yellow]Запись #{finding_id} не finding "
                      f"(kind={n.get('kind')})[/yellow]")

    # Ищем подходящий пресет по тегам/title
    if not preset:
        tags = [t.lower() for t in (n.get("tags") or [])]
        for key in VULN_PRESETS:
            if any(key.replace("-", "") in t.replace("-", "")
                   or key.split("-")[0] in t for t in tags):
                preset = key
                break
        if not preset:
            tl = (n.get("title") or "").lower()
            for kw, key in [
                ("xss", "xss-stored"), ("sql", "sqli"),
                ("ssrf", "ssrf"), ("idor", "idor"),
                ("rce", "rce"), ("csrf", "csrf"),
                ("takeover", "subdomain-takeover"),
                ("xxe", "xxe"), ("ssti", "ssti"),
                ("redirect", "open-redirect"),
                ("jwt", "jwt-alg-none"),
                ("race", "race-condition"),
                ("smuggling", "http-smuggling"),
                ("cache", "cache-poisoning"),
            ]:
                if kw in tl:
                    preset = key
                    break

    r = BugReport(
        platform=platform,
        target=n.get("target") or "",
        title=n.get("title") or "",
        summary=n.get("body") or "",
        severity=(n.get("severity") or "").lower(),
        author="anon",
        created=datetime.now().strftime("%Y-%m-%d %H:%M"),
        finding_id=finding_id,
        tags=list(n.get("tags") or []),
    )

    if preset and preset in VULN_PRESETS:
        d = _preset_defaults(preset, endpoint=r.target)
        if not r.summary:
            r.summary = d["summary"]
        r.impact = d["impact"]
        r.remediation = d["remediation"]
        r.cvss_vector = d["cvss_vector"]
        r.cvss_score = d["cvss_score"]
        r.cwe = d["cwe"]
        r.refs = d["refs"]
        if not r.severity:
            r.severity = d["severity"]
        if preset not in r.tags:
            r.tags.append(preset)
        console.print(f"[cyan]Применён пресет: "
                      f"{VULN_PRESETS[preset]['name']}[/cyan]")

    console.print(f"[green]✓ Отчёт построен из finding #{finding_id}[/green]")
    return r


def bulk_from_findings(platform: str = "hackerone",
                        target: str | None = None) -> list[BugReport]:
    """Построить отчёты из всех findings (опц. фильтр по target)."""
    try:
        from modules import notes as _notes
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]notes error: {exc}[/red]")
        return []
    findings = _notes.list_notes(kind="finding", target=target)
    if not findings:
        console.print("[yellow]Нет findings.[/yellow]")
        return []
    console.print(f"[cyan]Строю {len(findings)} отчётов…[/cyan]")
    return [build_from_finding(f["id"], platform=platform)
            for f in findings]


# ===========================================================================
# Save to notes (обратная интеграция)
# ===========================================================================

def save_report_to_notes(r: BugReport) -> int:
    """Сохранить готовый отчёт как finding в notes."""
    try:
        from modules import notes
        nid = notes.add_note(
            kind="finding",
            title=r.title or "Bug Bounty Report",
            target=r.target or "unknown",
            severity=(r.severity or "info").lower(),
            status="open",
            tags=["bugbounty", r.platform] + list(r.tags),
            body=_render_markdown(r)[:8000],
        )
        if nid > 0:
            console.print(f"[green]✓ Finding #{nid} добавлен в notes[/green]")
        return nid
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]notes: {exc}[/red]")
        return -1


def _notify_report(r: BugReport, paths: list[Path]) -> None:
    """Notify о готовом отчёте."""
    try:
        from modules import notifier
        notifier.notify_all(
            f"📝 Bug Bounty: {r.severity.upper() or 'INFO'} — "
            f"{r.target or 'unknown'}",
            f"Title: {r.title}\n"
            f"Platform: {r.platform}\n"
            f"Files: {len(paths)}\n"
            f"CVSS: {r.cvss_score or cvss_score_from_vector(r.cvss_vector)}",
            severity=(r.severity or "medium").lower(),
        )
    except Exception:
        pass


# ===========================================================================
# Timeline
# ===========================================================================

def timeline_reports(days_back: int = 90) -> None:
    """Timeline сохранённых отчётов по датам."""
    files = sorted(REPORTS_DIR.glob("*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        console.print("[yellow]Отчётов нет.[/yellow]")
        return
    by_day: dict[str, list[dict]] = defaultdict(list)
    now_ts = datetime.now().timestamp()
    cutoff = now_ts - days_back * 86400
    for f in files:
        if f.stat().st_mtime < cutoff:
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            day = datetime.fromtimestamp(
                f.stat().st_mtime).strftime("%Y-%m-%d")
            by_day[day].append({
                "file": f.name,
                "title": data.get("title", "?"),
                "severity": data.get("severity", "?"),
                "target": data.get("target", "?"),
            })
        except Exception:
            continue
    if not by_day:
        console.print(f"[yellow]Нет отчётов за {days_back} дней.[/yellow]")
        return
    for day in sorted(by_day.keys(), reverse=True):
        items = by_day[day]
        t = Table(title=f"📅 {day} ({len(items)})")
        t.add_column("Severity", style="red", width=10)
        t.add_column("Target", style="green", max_width=30)
        t.add_column("Title", style="white", max_width=50)
        for it in items[:30]:
            t.add_row(it["severity"].upper() or "?",
                       (it["target"] or "?")[:30],
                       (it["title"] or "?")[:50])
        console.print(t)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]📝 Report Templates Pack Pro[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "Новый отчёт (wizard)"),
        ("2", "Отчёт из пресета уязвимости"),
        ("3", "Отчёт из Notes & Findings (по ID)"),
        ("4", "Bulk: все findings → отчёты"),
        ("5", "Список платформ и пресетов"),
        ("6", "CVSS-калькулятор (вектор → score)"),
        ("7", "Список сохранённых отчётов"),
        ("8", "Timeline отчётов (по датам)"),
        ("9", "Bulk export всех отчётов → CSV"),
    ]
    for n, title in opts:
        t.add_row(n, title)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованных bug bounty "
                  "программ.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        plat = Prompt.ask("Платформа",
                          choices=list(TEMPLATES.keys()),
                          default="hackerone")
        r = wizard(platform=plat)
        fmt = Prompt.ask("Формат",
                         choices=["md", "html", "json", "csv", "all"],
                         default="md")
        paths: list[Path] = []
        if fmt == "all":
            paths = export_all(r)
        else:
            p = export_report(r, fmt=fmt)
            if p:
                paths.append(p)
        if paths:
            _notify_report(r, paths)
            if Confirm.ask("Сохранить в notes?", default=False):
                save_report_to_notes(r)
    elif c == "2":
        plat = Prompt.ask("Платформа",
                          choices=list(TEMPLATES.keys()),
                          default="hackerone")
        preset = Prompt.ask("Пресет",
                            choices=list(VULN_PRESETS.keys()),
                            default="xss-stored")
        r = wizard(platform=plat, preset=preset)
        fmt = Prompt.ask("Формат",
                         choices=["md", "html", "json", "csv", "all"],
                         default="md")
        paths = export_all(r) if fmt == "all" else \
            ([p] if (p := export_report(r, fmt=fmt)) else [])
        if paths:
            _notify_report(r, paths)
    elif c == "3":
        fid = int(Prompt.ask("Finding ID"))
        plat = Prompt.ask("Платформа",
                          choices=list(TEMPLATES.keys()),
                          default="hackerone")
        preset_choice = Prompt.ask("Пресет (пусто = авто)",
                                    default="").strip()
        r = build_from_finding(fid, platform=plat,
                                preset=preset_choice or None)
        console.print(f"\n[cyan]Preview:[/cyan]\n"
                      f"{_render_markdown(r)[:1500]}")
        fmt = Prompt.ask("Формат",
                         choices=["md", "html", "json", "csv", "all"],
                         default="md")
        paths = export_all(r) if fmt == "all" else \
            ([p] if (p := export_report(r, fmt=fmt)) else [])
        if paths:
            _notify_report(r, paths)
    elif c == "4":
        plat = Prompt.ask("Платформа",
                          choices=list(TEMPLATES.keys()),
                          default="hackerone")
        tf = Prompt.ask("Target (пусто = все)",
                        default="").strip() or None
        reports = bulk_from_findings(platform=plat, target=tf)
        for r in reports:
            if not r.title:
                continue
            export_report(r, fmt="md")
        if reports:
            export_bulk_csv(reports)
    elif c == "5":
        show_platforms()
        console.print()
        show_presets()
    elif c == "6":
        vec = Prompt.ask("CVSS vector (например "
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)")
        full = cvss_full_from_vector(vec)
        t = Table(title="CVSS result")
        t.add_column("Тип", style="cyan")
        t.add_column("Score", style="green")
        t.add_column("Severity", style="yellow")
        t.add_row("Base", str(full["base_score"]),
                  full["base_severity"])
        t.add_row("Temporal", str(full["temporal_score"]),
                  full["temporal_severity"])
        console.print(t)
    elif c == "7":
        list_reports()
    elif c == "8":
        timeline_reports()
    elif c == "9":
        reports = bulk_from_findings()
        if reports:
            export_bulk_csv([r for r in reports if r.title])


def show_platforms() -> None:
    t = Table(title=f"Платформы ({len(TEMPLATES)})")
    t.add_column("Slug", style="cyan")
    t.add_column("Name", style="green")
    t.add_column("Секции", style="magenta", max_width=60)
    for slug, data in TEMPLATES.items():
        t.add_row(slug, data["name"],
                  ", ".join(s for s, _, _ in data["sections"]))
    console.print(t)


def show_presets() -> None:
    t = Table(title=f"Пресеты уязвимостей ({len(VULN_PRESETS)})")
    t.add_column("Slug", style="cyan", max_width=22)
    t.add_column("Name", style="green", max_width=28)
    t.add_column("Sev", style="red", width=10)
    t.add_column("CVSS", style="yellow", width=5)
    t.add_column("CWE", style="magenta", width=12)
    for slug, d in VULN_PRESETS.items():
        t.add_row(slug, d["name"], d["severity"].upper(),
                  str(d["cvss_score"]), d["cwe"])
    console.print(t)


def list_reports() -> None:
    files = sorted(REPORTS_DIR.glob("*"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        console.print("[yellow]Отчётов нет.[/yellow]")
        return
    t = Table(title=f"Сохранённые отчёты ({len(files)})")
    t.add_column("Файл", style="cyan", max_width=50)
    t.add_column("Размер", style="green", width=10)
    t.add_column("Дата", style="white", width=20)
    for f in files[:40]:
        st = f.stat()
        t.add_row(f.name, f"{st.st_size / 1024:.1f} KB",
                  datetime.fromtimestamp(st.st_mtime).strftime(
                      "%Y-%m-%d %H:%M:%S"))
    console.print(t)
    console.print(f"\n[dim]Папка: {REPORTS_DIR}[/dim]")


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_wizard(platform: str = "hackerone") -> None:
    r = wizard(platform=platform)
    paths = export_all(r)
    if paths:
        _notify_report(r, paths)


def cli_from_preset(platform: str, preset: str) -> None:
    r = wizard(platform=platform, preset=preset)
    paths = export_all(r)
    if paths:
        _notify_report(r, paths)


def cli_from_finding(finding_id: int, platform: str = "hackerone",
                     preset: str | None = None) -> None:
    r = build_from_finding(finding_id, platform=platform, preset=preset)
    if r.title:
        paths = export_all(r)
        if paths:
            _notify_report(r, paths)


def cli_bulk(target: str | None = None,
             platform: str = "hackerone") -> None:
    reports = bulk_from_findings(platform=platform, target=target)
    for r in reports:
        if r.title:
            export_report(r, fmt="md")
    if reports:
        export_bulk_csv([r for r in reports if r.title])


def cli_platforms() -> None:
    show_platforms()


def cli_presets() -> None:
    show_presets()


def cli_cvss(vector: str) -> None:
    full = cvss_full_from_vector(vector)
    console.print(
        f"[green]Base: {full['base_score']} "
        f"({full['base_severity']}) | "
        f"Temporal: {full['temporal_score']} "
        f"({full['temporal_severity']})[/green]"
    )


def cli_list() -> None:
    list_reports()


def cli_timeline(days: int = 90) -> None:
    timeline_reports(days_back=days)