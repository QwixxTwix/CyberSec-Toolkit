"""Модуль Roadmap: обучение, квиз, трекер прогресса."""
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


ROADMAP = {
    "Junior": [
        "Networking basics (OSI, TCP/IP, DNS, HTTP)",
        "Linux CLI (bash, permissions, processes)",
        "Python scripting basics",
        "Web basics (HTML, JS, HTTP methods, cookies)",
        "TryHackMe: Pre Security Path",
        "Основы криптографии (хеши, симметрия/асимметрия)",
    ],
    "Middle": [
        "OWASP Top 10 — все уязвимости",
        "Burp Suite, ffuf, nmap, sqlmap",
        "Linux privilege escalation (LinPEAS, GTFOBins)",
        "Windows privilege escalation",
        "HackTheBox: Easy/Medium machines",
        "Active Directory basics",
        "Recon: Shodan, Censys, subdomain enumeration",
    ],
    "Senior": [
        "Active Directory attacks (Kerberoasting, DCSync)",
        "Reverse engineering & malware analysis",
        "Cloud security (AWS/Azure/GCP)",
        "Exploit development (buffer overflow, ROP)",
        "Bug bounty write-ups & CVE research",
        "Red teaming (C2, opsec, persistence)",
        "Forensics & incident response",
    ],
}


RESOURCES = [
    ("TryHackMe", "https://tryhackme.com"),
    ("HackTheBox", "https://hackthebox.com"),
    ("PortSwigger Academy", "https://portswigger.net/web-security"),
    ("OWASP", "https://owasp.org"),
    ("PentesterLab", "https://pentesterlab.com"),
    ("HackTricks", "https://book.hacktricks.xyz"),
    ("GTFOBins", "https://gtfobins.github.io"),
    ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings"),
]


QUIZ = [
    {
        "q": "Какой порт используется по умолчанию для HTTPS?",
        "options": ["80", "443", "22", "8080"],
        "answer": "2",
    },
    {
        "q": "Что проверяет HSTS-заголовок?",
        "options": ["CORS", "Принудительный HTTPS", "CSRF", "SQLi"],
        "answer": "2",
    },
    {
        "q": "Какой алгоритм хеширования считается устаревшим?",
        "options": ["bcrypt", "argon2", "MD5", "SHA-256"],
        "answer": "3",
    },
    {
        "q": "Что делает команда `nmap -sS`?",
        "options": [
            "SYN-сканирование (stealth)",
            "UDP-сканирование",
            "Пинг-скан",
            "Сканирование портов через connect()",
        ],
        "answer": "1",
    },
    {
        "q": "Какой из этих заголовков защищает от XSS?",
        "options": [
            "X-Frame-Options",
            "Content-Security-Policy",
            "Referrer-Policy",
            "Permissions-Policy",
        ],
        "answer": "2",
    },
    {
        "q": "Что такое SQL-инъекция?",
        "options": [
            "Внедрение SQL-кода через пользовательский ввод",
            "Ошибка в СУБД",
            "Межсайтовый скриптинг",
            "Отказ в обслуживании",
        ],
        "answer": "1",
    },
    {
        "q": "Что делает команда `chmod 777 file`?",
        "options": [
            "Даёт всем полный доступ к файлу",
            "Удаляет файл",
            "Меняет владельца",
            "Делает файл исполняемым только для root",
        ],
        "answer": "1",
    },
    {
        "q": "Что такое CSRF?",
        "options": [
            "Cross-Site Request Forgery",
            "Cross-Site Scripting Filter",
            "Client-Side Response Filter",
            "Central Server Request Format",
        ],
        "answer": "1",
    },
    {
        "q": "Что возвращает команда `whoami` в Linux?",
        "options": [
            "Текущий каталог",
            "Имя текущего пользователя",
            "Список процессов",
            "IP-адрес",
        ],
        "answer": "2",
    },
    {
        "q": "Что такое privilege escalation?",
        "options": [
            "Повышение прав в системе",
            "Понижение прав",
            "Шифрование данных",
            "Резервное копирование",
        ],
        "answer": "1",
    },
]


def show_roadmap() -> None:
    """Показать Roadmap по уровням."""
    for level, topics in ROADMAP.items():
        table = Table(title=f"[bold cyan]{level}[/bold cyan]")
        table.add_column("#", style="yellow", width=3)
        table.add_column("Тема")
        for i, t in enumerate(topics, 1):
            table.add_row(str(i), t)
        console.print(table)


def show_resources() -> None:
    """Показать ресурсы для обучения."""
    table = Table(title="Обучающие ресурсы")
    table.add_column("Название", style="cyan")
    table.add_column("URL", style="green")
    for name, url in RESOURCES:
        table.add_row(name, url)
    console.print(table)


def run_quiz() -> None:
    """Пройти квиз."""
    score = 0
    for i, q in enumerate(QUIZ, 1):
        console.print(f"\n[bold]Q{i}:[/bold] {q['q']}")
        for j, opt in enumerate(q["options"], 1):
            console.print(f"  {j}) {opt}")
        ans = Prompt.ask(
            "Ответ",
            choices=["1", "2", "3", "4"][:len(q["options"])],
        )
        if ans == q["answer"]:
            score += 1
            console.print("[green]✓ Верно[/green]")
        else:
            console.print(f"[red]✗ Правильно: {q['answer']}[/red]")
    total = len(QUIZ)
    pct = round(score / total * 100)
    console.print(f"\n[bold cyan]Итог: {score}/{total} ({pct}%)[/bold cyan]")
    db.save_scan("quiz", "roadmap", {"score": score, "total": total})


def track_progress() -> None:
    """Обновить статус темы."""
    topic = Prompt.ask("Тема")
    status = Prompt.ask(
        "Статус",
        choices=["todo", "in-progress", "done"],
        default="todo",
    )
    db.set_progress(topic, status)
    console.print(f"[green]✓ {topic} → {status}[/green]")


def show_progress() -> None:
    """Показать весь прогресс."""
    data = db.get_progress()
    if not data:
        console.print("[yellow]Прогресс пуст.[/yellow]")
        return
    table = Table(title="Прогресс обучения")
    table.add_column("Тема", style="cyan")
    table.add_column("Статус", style="green")
    for k, v in sorted(data.items()):
        color = {"todo": "red", "in-progress": "yellow",
                 "done": "green"}.get(v, "white")
        table.add_row(k, f"[{color}]{v}[/{color}]")
    console.print(table)


def menu() -> None:
    """Меню Roadmap."""
    table = Table(title="[bold]Roadmap / Обучение[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Показать Roadmap (Junior → Senior)"),
        ("2", "Ресурсы (THM, HTB, PortSwigger)"),
        ("3", "Пройти квиз (10 вопросов)"),
        ("4", "Обновить прогресс по теме"),
        ("5", "Показать прогресс"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    {
        "1": show_roadmap,
        "2": show_resources,
        "3": run_quiz,
        "4": track_progress,
        "5": show_progress,
    }[c]()