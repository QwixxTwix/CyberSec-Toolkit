"""
Report Templates Pack — Bug Bounty platform templates.
Author: idqwixxa

Возможности:
    - 6 платформенных шаблонов (HackerOne, Bugcrowd, Intigriti,
      YesWeHack, Immunefi, CVE/MITRE)
    - 13 пресетов уязвимостей (XSS, SQLi, SSRF, IDOR, RCE, AuthBypass,
      Subdomain Takeover, Open Redirect, CSRF, XXE, Race, BizLogic, Info)
    - Авто-подстановка из Notes & Findings по target
    - CVSS v3.1: вектор ↔ score, severity
    - Quality checker (валидация отчёта перед отправкой)
    - Экспорт: MD, HTML, JSON

⚠ Только для авторизованных bug bounty программ.
"""
import html as html_mod
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

REPORTS_DIR = REPORT_DIR / "bug_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Шаблоны платформ
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
}


# ===========================================================================
# Пресеты уязвимостей
# ===========================================================================

VULN_PRESETS = {
    "xss-stored": {
        "name": "Stored XSS",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.4,
        "cwe": "CWE-79",
        "title_tpl": "Stored XSS in {endpoint}",
        "summary_tpl": (
            "Stored Cross-Site Scripting (XSS) уязвимость в {endpoint}. "
            "Вредоносный JavaScript сохраняется на сервере и "
            "выполняется в браузерах всех пользователей, просматривающих "
            "затронутую страницу."
        ),
        "impact_tpl": (
            "Атакующий может:\n"
            "- Угнать сессионные cookie аутентифицированных пользователей\n"
            "- Выполнить действия от имени жертвы (CSRF-подобно)\n"
            "- Перенаправить жертву на фишинговый сайт\n"
            "- Развернуть криптомайнер/beEF-hook в браузерах жертв"
        ),
        "remediation_tpl": (
            "- Контекстно-зависимое экранирование вывода (HTML/JS/CSS/URL)\n"
            "- Валидация входных данных по белому списку\n"
            "- Content-Security-Policy: script-src 'self'\n"
            "- Использование шаблонизаторов с автоэкранированием"
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "xss-reflected": {
        "name": "Reflected XSS",
        "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1,
        "cwe": "CWE-79",
        "title_tpl": "Reflected XSS in {endpoint} ({param})",
        "summary_tpl": (
            "Reflected Cross-Site Scripting в параметре {param} "
            "endpoint'а {endpoint}. Payload отражается в HTML-ответе без "
            "должной санитизации."
        ),
        "impact_tpl": (
            "При переходе жертвы по подготовленной ссылке — выполняется "
            "произвольный JavaScript в контексте домена уязвимого "
            "приложения. Позволяет красть сессии, выполнять действия "
            "от имени жертвы."
        ),
        "remediation_tpl": (
            "- HTML-энкодинг всех пользовательских данных в ответе\n"
            "- Content-Security-Policy\n"
            "- X-XSS-Protection не считается защитой — только CSP + энкодинг"
        ),
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "sqli": {
        "name": "SQL Injection",
        "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "cwe": "CWE-89",
        "title_tpl": "SQL Injection in {endpoint} ({param})",
        "summary_tpl": (
            "SQL-инъекция в параметре {param} endpoint'а {endpoint}. "
            "Пользовательский ввод попадает в SQL-запрос без параметризации, "
            "что позволяет произвольно манипулировать запросом."
        ),
        "impact_tpl": (
            "- Чтение всей БД (включая хеши паролей, PII)\n"
            "- Модификация/удаление данных\n"
            "- Обход аутентификации\n"
            "- При определённых конфигурациях — RCE через xp_cmdshell / "
            "LOAD_FILE / UDF"
        ),
        "remediation_tpl": (
            "- Параметризованные запросы (prepared statements)\n"
            "- ORM с биндингом параметров\n"
            "- Валидация типа/длины входных данных\n"
            "- Least-privilege для DB-пользователя приложения\n"
            "- WAF как дополнительный слой, не как единственная защита"
        ),
        "refs": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "ssrf": {
        "name": "SSRF",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cvss_score": 8.6,
        "cwe": "CWE-918",
        "title_tpl": "SSRF in {endpoint}",
        "summary_tpl": (
            "Server-Side Request Forgery в {endpoint}. Сервер загружает "
            "URL по пользовательскому вводу без проверки на внутренние "
            "адреса/метаданные."
        ),
        "impact_tpl": (
            "- Доступ к internal-сервисам (Redis, Elasticsearch, K8s API)\n"
            "- Чтение cloud-metadata (169.254.169.254) → кража IAM creds\n"
            "- Порт-скан внутренней сети\n"
            "- При file:// или gopher:// — локальное чтение файлов / RCE"
        ),
        "remediation_tpl": (
            "- Allowlist доменов/схем вместо блоклиста IP\n"
            "- Резолвить хост и проверять итоговый IP (не только hostname)\n"
            "- Запрет на 169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8 и т.д.\n"
            "- Отдельный network segment без прав"
        ),
        "refs": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    "idor": {
        "name": "IDOR",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 8.1,
        "cwe": "CWE-639",
        "title_tpl": "IDOR in {endpoint} — доступ к чужим объектам",
        "summary_tpl": (
            "Insecure Direct Object Reference в {endpoint}. "
            "Идентификатор объекта (id/uuid) не проверяется на "
            "принадлежность текущему пользователю."
        ),
        "impact_tpl": (
            "- Чтение/изменение/удаление объектов других пользователей\n"
            "- При больших ID — массовая утечка через enumerating\n"
            "- Доступ к чужим данным: PII, платежи, документы"
        ),
        "remediation_tpl": (
            "- Ownership check на каждый запрос к объекту\n"
            "- Использование indirect reference (случайные токены/мапы)\n"
            "- UUID v4 вместо последовательных ID\n"
            "- Централизованный authorization layer"
        ),
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
    },
    "rce": {
        "name": "Remote Code Execution",
        "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": 10.0,
        "cwe": "CWE-94",
        "title_tpl": "RCE in {endpoint}",
        "summary_tpl": (
            "Remote Code Execution в {endpoint}. "
            "Пользовательский ввод попадает в eval/exec/system "
            "без санитизации."
        ),
        "impact_tpl": (
            "Полная компрометация сервера:\n"
            "- Чтение env/secrets/SSH-ключей\n"
            "- Lateral movement по внутренней сети\n"
            "- Установка backdoor/persistence\n"
            "- Полный контроль над инфраструктурой приложения"
        ),
        "remediation_tpl": (
            "- Никогда не передавать пользовательский ввод в eval/exec\n"
            "- Использовать безопасные API (subprocess с arrays, не shell)\n"
            "- При необходимости — sandboxing (seccomp, gVisor, docker)\n"
            "- Least-privilege для process user"
        ),
        "refs": ["https://owasp.org/www-community/attacks/Code_Injection"],
    },
    "auth-bypass": {
        "name": "Authentication Bypass",
        "severity": "critical",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1,
        "cwe": "CWE-287",
        "title_tpl": "Authentication Bypass via {endpoint}",
        "summary_tpl": (
            "Обход аутентификации в {endpoint}. "
            "Позволяет получить доступ без валидных credentials."
        ),
        "impact_tpl": (
            "- Полный доступ ко всем защищённым функциям\n"
            "- Изменение/удаление данных от имени любого пользователя\n"
            "- Эскалация до admin"
        ),
        "remediation_tpl": (
            "- Единая точка аутентификации (middleware)\n"
            "- Deny-by-default: все endpoints требуют auth, кроме явно публичных\n"
            "- Проверка токена/сессии перед любым действием\n"
            "- Не полагаться на client-side checks"
        ),
        "refs": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    },
    "subdomain-takeover": {
        "name": "Subdomain Takeover",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1,
        "cwe": "CWE-350",
        "title_tpl": "Subdomain Takeover on {subdomain}",
        "summary_tpl": (
            "Поддомен {subdomain} имеет CNAME на несуществующий "
            "ресурс ({service}) и может быть захвачен любым "
            "пользователем сервиса."
        ),
        "impact_tpl": (
            "- Фишинг на доверенном домене\n"
            "- Кража cookie (если Domain=.example.com)\n"
            "- Обход CSP / SOP защиты\n"
            "- XSS через отражение в отчётах аналитики"
        ),
        "remediation_tpl": (
            "- Удалить DNS-запись для неиспользуемых сервисов\n"
            "- Автоматизированный мониторинг dangling CNAME\n"
            "- Не резервировать сабдомены под сервисы, которые "
            "не будут переиспользоваться"
        ),
        "refs": ["https://github.com/EdOverflow/can-i-take-over-xyz"],
    },
    "open-redirect": {
        "name": "Open Redirect",
        "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "cvss_score": 4.7,
        "cwe": "CWE-601",
        "title_tpl": "Open Redirect in {endpoint} ({param})",
        "summary_tpl": (
            "Открытый редирект через параметр {param}. "
            "Не валидируется домен-назначение."
        ),
        "impact_tpl": (
            "- Используется для фишинга (доверенный URL → атакующий)\n"
            "- Обход OAuth redirect_uri checks в связке с другими багами\n"
            "- Доставка XSS/CSRF payload"
        ),
        "remediation_tpl": (
            "- Allowlist доменов\n"
            "- Относительные пути вместо абсолютных\n"
            "- Подпись целевого URL (HMAC)"
        ),
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    },
    "csrf": {
        "name": "CSRF",
        "severity": "medium",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cvss_score": 5.4,
        "cwe": "CWE-352",
        "title_tpl": "CSRF in {endpoint}",
        "summary_tpl": (
            "Cross-Site Request Forgery в {endpoint}. "
            "Форма не защищена CSRF-токеном, cookie без SameSite."
        ),
        "impact_tpl": (
            "- Выполнение state-changing действий от имени жертвы\n"
            "- Смена пароля/email, удаление аккаунта, переводы"
        ),
        "remediation_tpl": (
            "- CSRF-токен на каждую state-changing форму\n"
            "- SameSite=Lax/Strict на session cookie\n"
            "- Проверка Origin/Referer\n"
            "- Повторная аутентификация для критичных операций"
        ),
        "refs": ["https://owasp.org/www-community/attacks/csrf"],
    },
    "xxe": {
        "name": "XXE",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cvss_score": 8.6,
        "cwe": "CWE-611",
        "title_tpl": "XXE in {endpoint}",
        "summary_tpl": (
            "XML External Entity Injection в {endpoint}. "
            "Парсер обрабатывает внешние entity без ограничений."
        ),
        "impact_tpl": (
            "- Чтение локальных файлов (file://)\n"
            "- SSRF на внутренние сервисы (http://)\n"
            "- DoS (billion laughs)\n"
            "- При определённых конфигурациях — RCE"
        ),
        "remediation_tpl": (
            "- Отключить DTD (disallow-doctype-decl=true)\n"
            "- Отключить внешние entity\n"
            "- Использовать безопасные парсеры с дефолтными настройками"
        ),
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
    },
    "race-condition": {
        "name": "Race Condition",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 5.3,
        "cwe": "CWE-362",
        "title_tpl": "Race Condition in {endpoint}",
        "summary_tpl": (
            "Race Condition в {endpoint}. "
            "Отсутствует атомарность между check и use (TOCTOU)."
        ),
        "impact_tpl": (
            "- Многократное использование одного-time токена/купона\n"
            "- Обход лимитов (withdraw, промокоды)\n"
            "- Двойное списание/начисление баланса\n"
            "- Покупка дешевле заявленной цены"
        ),
        "remediation_tpl": (
            "- Атомарные операции (SELECT ... FOR UPDATE, транзакции)\n"
            "- Distributed locks (Redis, etcd)\n"
            "- Idempotency keys на API\n"
            "- Очереди с единственным consumer"
        ),
        "refs": ["https://portswigger.net/web-security/race-conditions"],
    },
    "business-logic": {
        "name": "Business Logic",
        "severity": "high",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cvss_score": 6.5,
        "cwe": "CWE-840",
        "title_tpl": "Business Logic flaw in {endpoint}",
        "summary_tpl": (
            "Business Logic уязвимость в {endpoint}. "
            "Сервер не проверяет инварианты бизнес-процесса."
        ),
        "impact_tpl": (
            "Зависит от сценария:\n"
            "- Обход правил (уровни, лимиты, подписки)\n"
            "- Финансовые потери\n"
            "- Доступ к платному контенту бесплатно"
        ),
        "remediation_tpl": (
            "- Серверная валидация всех бизнес-правил\n"
            "- Не доверять client-side (цены, статусы, роли)\n"
            "- Audit log для критичных операций"
        ),
        "refs": ["https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"],
    },
    "info-disclosure": {
        "name": "Information Disclosure",
        "severity": "low",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score": 5.3,
        "cwe": "CWE-200",
        "title_tpl": "Information Disclosure in {endpoint}",
        "summary_tpl": (
            "Утечка информации в {endpoint}. "
            "Раскрываются чувствительные данные без аутентификации."
        ),
        "impact_tpl": (
            "- Раскрытие структуры приложения\n"
            "- Помощь атакующему в дальнейших атаках\n"
            "- Утечка PII/credentials"
        ),
        "remediation_tpl": (
            "- Не отдавать debug-информацию в production\n"
            "- Отключить directory listing, stack traces\n"
            "- Правильные ACL на файлы (.git, .env, backup)"
        ),
        "refs": ["https://owasp.org/www-community/vulnerabilities/Information_exposure"],
    },
}


# ===========================================================================
# CVSS helper
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


def cvss_score_from_vector(vector: str) -> float:
    """Вычислить CVSS v3.1 base score из вектора."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = parts.get("S") == "C"
        av = CVSS_METRICS["AV"].get(parts.get("AV", "N"), 0.85)
        ac = CVSS_METRICS["AC"].get(parts.get("AC", "L"), 0.77)
        pr_key = "PR_C" if scope_changed else "PR_U"
        pr = CVSS_METRICS[pr_key].get(parts.get("PR", "N"), 0.85)
        ui = CVSS_METRICS["UI"].get(parts.get("UI", "N"), 0.85)
        c = CVSS_METRICS["C"].get(parts.get("C", "N"), 0.0)
        i = CVSS_METRICS["I"].get(parts.get("I", "N"), 0.0)
        a = CVSS_METRICS["A"].get(parts.get("A", "N"), 0.0)

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploit = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        score = (1.08 if scope_changed else 1.0) * min(impact + exploit, 10)
        return round(min(score, 10.0), 1)
    except Exception:
        return 0.0


def severity_from_score(score: float) -> str:
    if score == 0: return "none"
    if score < 4: return "low"
    if score < 7: return "medium"
    if score < 9: return "high"
    return "critical"


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
    """
    Вернуть [(field, level, message)] где level ∈ ok | warn | error.
    """
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
        has_cmd = bool(re.search(r"(curl|wget|python|POST|GET|http)", report.poc,
                                  re.IGNORECASE))
        if not has_cmd:
            out.append(("poc", "warn", "PoC без команд/URL — добавь"
                                       " воспроизводимый пример"))
        else:
            out.append(("poc", "ok", "OK"))

    # Remediation
    if not report.remediation or len(report.remediation) < 40:
        out.append(("remediation", "warn", "Remediation < 40 символов"))
    else:
        out.append(("remediation", "ok", f"OK ({len(report.remediation)} симв.)"))

    # Severity + CVSS
    if report.cvss_vector:
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

    return out


# ===========================================================================
# Markdown renderer
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
    out.append(f"**Author:** {r.author}  ")
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

    return "\n".join(out)


# ===========================================================================
# HTML renderer
# ===========================================================================

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
    parts.append("</div>")

    for key, title, _hint in tpl["sections"]:
        val = getattr(r, key, "") or ""
        if not val:
            continue
        if key == "steps":
            val = _sanitize_steps(val)
        # экранируем, потом переносы
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


# ===========================================================================
# Wizard — заполнение отчёта
# ===========================================================================

def _preset_defaults(preset_key: str, endpoint: str = "",
                     param: str = "") -> dict:
    p = VULN_PRESETS.get(preset_key, {})
    ctx = {"endpoint": endpoint or "/vulnerable", "param": param or "id",
           "subdomain": endpoint or "sub.example.com",
           "service": "unknown"}
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


def wizard(platform: str = "hackerone",
           preset: str | None = None,
           target: str | None = None,
           from_finding: int | None = None) -> BugReport:
    """Интерактивный wizard."""
    r = BugReport(platform=platform, author="anon",
                  created=datetime.now().strftime("%Y-%m-%d %H:%M"))

    # Если из finding — префилл
    if from_finding:
        try:
            from modules import notes as _notes
            n = _notes.get_note(from_finding)
            if n and n.get("kind") == "finding":
                r.target = n.get("target") or ""
                r.title = n.get("title") or ""
                r.summary = n.get("body") or ""
                r.severity = (n.get("severity") or "").lower()
                r.cwe = ""
                r.finding_id = from_finding
                console.print(f"[green]✓ Префилл из finding "
                              f"#{from_finding}[/green]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]finding load: {exc}[/yellow]")

    # Префилл из пресета
    if preset:
        console.print(f"[cyan]Пресет: {VULN_PRESETS[preset]['name']}[/cyan]")
        endpoint = Prompt.ask("Endpoint/URL (пусто = /vulnerable)",
                              default="").strip()
        param = Prompt.ask("Параметр (пусто = id)",
                           default="").strip() if preset in (
            "xss-reflected", "sqli", "open-redirect", "idor"
        ) else ""
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

    console.print(f"\n[bold cyan]📝 Заполнение отчёта "
                  f"({TEMPLATES[platform]['name']})[/bold cyan]\n")

    if not target:
        target = Prompt.ask("Target (домен/URL)", default=r.target or "")
    r.target = target or r.target

    if not r.title:
        r.title = Prompt.ask("Title")
    else:
        new_title = Prompt.ask("Title", default=r.title)
        r.title = new_title

    r.summary = _ask_multiline("Summary", r.summary)
    r.steps = _ask_multiline("Steps to Reproduce (по одной на строку)",
                              "")
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
    """Многострочный ввод: пустая строка = конец, Enter-Enter = принять default."""
    if default:
        console.print(f"[cyan]{label}[/cyan] [dim](Enter — принять "
                      f"текущее, '.' + Enter — ввести заново)[/dim]")
        short = default.splitlines()[0][:80] if default else ""
        console.print(f"[dim]  Текущее: {short}"
                      f"{'…' if len(default) > 80 else ''}[/dim]")
        choice = Prompt.ask("", default="").strip()
        if choice == ".":
            pass  # вводим заново
        else:
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
    """Экспортировать отчёт в md / html / json."""
    if not out_path:
        name = _safe_name(r)
        ext = {"md": ".md", "html": ".html", "json": ".json"}[fmt]
        out_path = str(REPORTS_DIR / f"{name}{ext}")

    try:
        if fmt == "md":
            content = _render_markdown(r)
        elif fmt == "html":
            content = _render_html(r)
        elif fmt == "json":
            content = json.dumps(asdict(r), indent=2, ensure_ascii=False)
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
    """Экспорт во все 3 формата."""
    out: list[Path] = []
    for fmt in ("md", "html", "json"):
        p = export_report(r, fmt=fmt)
        if p:
            out.append(p)
    return out


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

    # Ищем подходящий пресет по тегам
    if not preset:
        tags = [t.lower() for t in (n.get("tags") or [])]
        for key in VULN_PRESETS:
            if any(key.replace("-", "") in t.replace("-", "")
                   or key.split("-")[0] in t for t in tags):
                preset = key
                break
        if not preset:
            # ищем по title
            title_low = (n.get("title") or "").lower()
            if "xss" in title_low: preset = "xss-stored"
            elif "sql" in title_low: preset = "sqli"
            elif "ssrf" in title_low: preset = "ssrf"
            elif "idor" in title_low: preset = "idor"
            elif "rce" in title_low: preset = "rce"
            elif "csrf" in title_low: preset = "csrf"
            elif "takeover" in title_low: preset = "subdomain-takeover"

    r = BugReport(
        platform=platform,
        target=n.get("target") or "",
        title=n.get("title") or "",
        summary=n.get("body") or "",
        severity=(n.get("severity") or "").lower(),
        author="anon",
        created=datetime.now().strftime("%Y-%m-%d %H:%M"),
        finding_id=finding_id,
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
    reports = [build_from_finding(f["id"], platform=platform)
               for f in findings]
    return reports


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]📝 Report Templates Pack[/bold]")
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
    ]
    for n, title in opts:
        t.add_row(n, title)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованных bug bounty "
                  "программ.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        plat = Prompt.ask("Платформа", choices=list(TEMPLATES.keys()),
                          default="hackerone")
        r = wizard(platform=plat)
        fmt = Prompt.ask("Формат экспорта",
                         choices=["md", "html", "json", "all"],
                         default="md")
        if fmt == "all":
            export_all(r)
        else:
            export_report(r, fmt=fmt)
    elif c == "2":
        plat = Prompt.ask("Платформа", choices=list(TEMPLATES.keys()),
                          default="hackerone")
        preset = Prompt.ask("Пресет",
                            choices=list(VULN_PRESETS.keys()),
                            default="xss-stored")
        r = wizard(platform=plat, preset=preset)
        fmt = Prompt.ask("Формат", choices=["md", "html", "json", "all"],
                         default="md")
        if fmt == "all":
            export_all(r)
        else:
            export_report(r, fmt=fmt)
    elif c == "3":
        fid = int(Prompt.ask("Finding ID"))
        plat = Prompt.ask("Платформа", choices=list(TEMPLATES.keys()),
                          default="hackerone")
        preset_choice = Prompt.ask("Пресет (пусто = авто)",
                                    default="").strip()
        r = build_from_finding(fid, platform=plat,
                                preset=preset_choice or None)
        console.print(f"\n[cyan]Preview:[/cyan]\n{_render_markdown(r)[:1500]}")
        fmt = Prompt.ask("Формат экспорта",
                         choices=["md", "html", "json", "all"],
                         default="md")
        if fmt == "all":
            export_all(r)
        else:
            export_report(r, fmt=fmt)
    elif c == "4":
        plat = Prompt.ask("Платформа", choices=list(TEMPLATES.keys()),
                          default="hackerone")
        tf = Prompt.ask("Target (пусто = все)", default="").strip() or None
        reports = bulk_from_findings(platform=plat, target=tf)
        for r in reports:
            if not r.title:
                continue
            export_report(r, fmt="md")
    elif c == "5":
        show_platforms()
        console.print()
        show_presets()
    elif c == "6":
        vec = Prompt.ask("CVSS vector (например "
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)")
        score = cvss_score_from_vector(vec)
        console.print(f"[green]Score: {score} "
                      f"({severity_from_score(score)})[/green]")
    elif c == "7":
        list_reports()


def show_platforms() -> None:
    t = Table(title=f"Платформы ({len(TEMPLATES)})")
    t.add_column("Slug", style="cyan")
    t.add_column("Name", style="green")
    t.add_column("Секции", style="magenta")
    for slug, data in TEMPLATES.items():
        t.add_row(slug, data["name"],
                  ", ".join(s for s, _, _ in data["sections"]))
    console.print(t)


def show_presets() -> None:
    t = Table(title=f"Пресеты уязвимостей ({len(VULN_PRESETS)})")
    t.add_column("Slug", style="cyan")
    t.add_column("Name", style="green")
    t.add_column("Sev", style="red", width=10)
    t.add_column("CVSS", style="yellow", width=5)
    t.add_column("CWE", style="magenta", width=10)
    for slug, d in VULN_PRESETS.items():
        t.add_row(slug, d["name"], d["severity"].upper(),
                  str(d["cvss_score"]), d["cwe"])
    console.print(t)


def list_reports() -> None:
    files = sorted(REPORTS_DIR.glob("*"), key=lambda p: p.stat().st_mtime,
                   reverse=True)
    if not files:
        console.print("[yellow]Отчётов нет.[/yellow]")
        return
    t = Table(title=f"Сохранённые отчёты ({len(files)})")
    t.add_column("Файл", style="cyan")
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
    export_all(r)


def cli_from_preset(platform: str, preset: str) -> None:
    r = wizard(platform=platform, preset=preset)
    export_all(r)


def cli_from_finding(finding_id: int, platform: str = "hackerone",
                     preset: str | None = None) -> None:
    r = build_from_finding(finding_id, platform=platform, preset=preset)
    if r.title:
        export_all(r)


def cli_bulk(target: str | None = None,
             platform: str = "hackerone") -> None:
    bulk_from_findings(platform=platform, target=target)


def cli_platforms() -> None:
    show_platforms()


def cli_presets() -> None:
    show_presets()


def cli_cvss(vector: str) -> None:
    score = cvss_score_from_vector(vector)
    console.print(f"[green]Score: {score} "
                  f"({severity_from_score(score)})[/green]")


def cli_list() -> None:
    list_reports()