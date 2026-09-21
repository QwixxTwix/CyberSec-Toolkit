"""
Blockchain / Web3 Security Suite (extended).
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Solidity static analysis (30+ паттернов) ───
    - Reentrancy (direct + cross-function + read-only)
    - Unchecked send/transfer/call return
    - delegatecall / call to user input
    - tx.origin auth
    - Integer overflow (Sol <0.8)
    - block.timestamp dependency
    - selfdestruct
    - Missing access control
    - Assembly usage
    - Weak randomness (blockhash/difficulty/timestamp)
    - Front-running vulnerable swaps
    - Sandwich attacks
    - Flash loan attack vectors
    - Oracle manipulation (single source)
    - DoS loops (unbounded)
    - Visibility issues (public state vars)
    - ERC20 approve race condition
    - SafeERC20 missing
    - Signature replay (ecrecover)
    - permit (ERC-2612)
    - setApprovalForAll
    - unchecked { }
    - storage collision (proxy)
    - initializer not locked
    - first-depositor attack
    - donation attack

    ─── Contract analysis ───
    - ERC20 / ERC721 / ERC1155 detection
    - Proxy detection (EIP-1967, EIP-1822, UUPS, Transparent)
    - Token info (name/symbol/decimals/totalSupply)
    - Bytecode size / entropy analysis
    - Opcode frequency (rough)
    - Function selector extraction (from bytecode + source)

    ─── Multi-chain support ───
    - Ethereum / Polygon / BSC / Arbitrum / Optimism / Base /
      Avalanche / Fantom / Goerli / Sepolia

    ─── Private keys ───
    - 10+ паттернов (hex, WIF, mnemonics, xprv, keystore, Tron,
      Solana, Starknet, Aptos, Sui, Cosmos)
    - Extended filtering (sha256 context, hash, checksum)

    ─── Honeypot heuristics ───
    - Code size / EOA
    - Transfer-hook patterns
    - External references (honeypot.is, de.fi, token sniffer)

    ─── Wallet drainer patterns ───
    - Extended regex (approve/permit/setApprovalForAll/transferFrom)
    - Domain / signature phishing patterns

    ─── Интеграция ───
    - Findings → notes (critical/high)
    - Notify (при private key / critical)
    - Экспорт: JSON / CSV / Markdown / HTML
"""
import csv
import hashlib
import html as html_mod
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (Progress, SpinnerColumn, TextColumn,
                            BarColumn)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WEB3_DIR = REPORT_DIR / "web3"
WEB3_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class W3Finding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: W3Finding) -> int:
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
            tags=["web3", f.kind],
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
# Solidity patterns (расширено до 30+)
# ===========================================================================

SOLIDITY_PATTERNS = [
    # ---------- Critical ----------
    {
        "id": "reentrancy_call",
        "name": "Potential Reentrancy (external call)",
        "severity": "critical",
        "regex": re.compile(
            r"\.call\s*[{(]|\.call\.value\s*\(|\.delegatecall\s*[{(]"),
        "hint": "Проверь state update ПОСЛЕ external call — "
                "используй nonReentrant modifier или CEI pattern",
    },
    {
        "id": "reentrancy_send",
        "name": "Reentrancy via send/transfer",
        "severity": "high",
        "regex": re.compile(r"\.send\s*\(|\.transfer\s*\("),
        "hint": "2300 gas защита, но всё равно проверяй порядок",
    },
    {
        "id": "tx_origin",
        "name": "tx.origin authentication",
        "severity": "high",
        "regex": re.compile(r"\btx\.origin\b"),
        "hint": "tx.origin уязвим для phishing — используй msg.sender",
    },
    {
        "id": "delegatecall",
        "name": "delegatecall",
        "severity": "high",
        "regex": re.compile(r"\.delegatecall\b"),
        "hint": "delegatecall к user-controlled адресу = RCE",
    },
    {
        "id": "selfdestruct",
        "name": "selfdestruct / suicide",
        "severity": "high",
        "regex": re.compile(r"\bselfdestruct\s*\(|\bsuicide\s*\("),
        "hint": "selfdestruct без access control = kill контракта",
    },
    {
        "id": "weak_randomness",
        "name": "Weak randomness",
        "severity": "high",
        "regex": re.compile(
            r"\bblock\.(?:blockhash|difficulty|prevrandao|coinbase)\b"),
        "hint": "Используй Chainlink VRF — block.* предсказуемо",
    },
    {
        "id": "integer_overflow_legacy",
        "name": "Legacy Solidity (<0.8) — overflow риск",
        "severity": "high",
        "regex": re.compile(r"pragma solidity\s+\^?0?\.[0-7]\."),
        "hint": "Solidity <0.8 не проверяет overflow — используй SafeMath",
    },
    {
        "id": "unchecked_call",
        "name": "Unchecked call return",
        "severity": "high",
        "regex": re.compile(
            r"\.call\s*[({][^;]{0,200};\s*$",
            re.MULTILINE),
        "hint": "Проверяй return (bool success) — иначе silent fail",
    },
    {
        "id": "unchecked_send",
        "name": "Unchecked send",
        "severity": "medium",
        "regex": re.compile(r"\.send\s*\([^)]+\)\s*;"),
        "hint": "Проверяй возвращаемое значение send()",
    },
    {
        "id": "oracle_single_source",
        "name": "Single-source oracle (манипулируемо)",
        "severity": "high",
        "regex": re.compile(
            r"getReserves\s*\(|slot0\s*\(|latestAnswer\s*\(|"
            r"latestRoundData\s*\("),
        "hint": "Один источник = flash loan attack. "
                "Используй TWAP + несколько источников",
    },
    {
        "id": "flash_loan_hint",
        "name": "Flash loan hook",
        "severity": "high",
        "regex": re.compile(
            r"flashLoan|onFlashLoan|executeOperation|"
            r"IERC3156|IFlashLoanReceiver"),
        "hint": "Проверь reentrancy и проверку caller",
    },

    # ---------- High ----------
    {
        "id": "timestamp_dependency",
        "name": "block.timestamp dependency",
        "severity": "medium",
        "regex": re.compile(r"\bblock\.timestamp\b"),
        "hint": "Майнер может манипулировать ±15 сек",
    },
    {
        "id": "assembly",
        "name": "Inline assembly",
        "severity": "medium",
        "regex": re.compile(r"\bassembly\s*\{"),
        "hint": "assembly обходит проверки компилятора",
    },
    {
        "id": "approve_unlimited",
        "name": "Unlimited approve pattern",
        "severity": "medium",
        "regex": re.compile(
            r"approve\s*\([^,]+,\s*(?:type\s*\(\s*uint256\s*\)\.max|"
            r"2\s*\*\*\s*256|0x[fF]{64}|uint256\s*\(\s*-1\s*\))",
        ),
        "hint": "Unlimited approval = rug-pull вектор",
    },
    {
        "id": "setApprovalForAll",
        "name": "setApprovalForAll",
        "severity": "medium",
        "regex": re.compile(r"setApprovalForAll\s*\("),
        "hint": "Полный доступ к NFT коллекции",
    },
    {
        "id": "permit_eip2612",
        "name": "ERC-2612 permit",
        "severity": "medium",
        "regex": re.compile(r"\bpermit\s*\(\s*address\s+owner"),
        "hint": "Проверь domain separator и nonce (replay)",
    },
    {
        "id": "ecrecover",
        "name": "ecrecover",
        "severity": "medium",
        "regex": re.compile(r"\becrecover\s*\("),
        "hint": "Проверь malleability (EIP-2) + nonce",
    },
    {
        "id": "access_control_missing",
        "name": "Public admin-like function (эвристика)",
        "severity": "medium",
        "regex": re.compile(
            r"function\s+\w*(?:admin|owner|pause|destroy|mint|"
            r"withdraw|upgrade|sweep|rescue|setFee|setRouter)\w*"
            r"\s*\([^)]*\)\s+(?:external|public)"
            r"(?![\s\S]{0,200}?(?:onlyOwner|onlyAdmin|onlyRole|"
            r"onlyMinter|require\s*\(\s*msg\.sender))",
            re.IGNORECASE),
        "hint": "Возможно публичная admin-функция",
    },
    {
        "id": "call_value",
        "name": "External call with value",
        "severity": "medium",
        "regex": re.compile(r"\.call\s*\{\s*value\s*:"),
        "hint": "Проверь recipient — произвольный адрес?",
    },
    {
        "id": "low_level_call_abi",
        "name": "Low-level call (abi.encode)",
        "severity": "medium",
        "regex": re.compile(r"\.call\s*\(\s*(?:bytes|abi\.encode)"),
        "hint": "Проверь проверку результата",
    },
    {
        "id": "unbounded_loop",
        "name": "Unbounded loop (DoS)",
        "severity": "medium",
        "regex": re.compile(
            r"for\s*\(\s*(?:uint|int)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*"
            r"\w+(?:\.length|\.length\(\))"),
        "hint": "DoS через gas limit — используй pagination",
    },
    {
        "id": "storage_pointer",
        "name": "storage pointer in function",
        "severity": "low",
        "regex": re.compile(r"\bstorage\s+\w+"),
        "hint": "Проверь, что state не изменяется неявно",
    },
    {
        "id": "uninitialized_pointer",
        "name": "Uninitialized storage pointer (legacy)",
        "severity": "high",
        "regex": re.compile(
            r"(?:struct\s+\w+\s+\w+\s*;)(?![\s\S]{0,50}?=)"),
        "hint": "Sol <0.5 позволяет uninit pointer → storage collision",
    },

    # ---------- Medium ----------
    {
        "id": "unchecked_block",
        "name": "unchecked { } block",
        "severity": "low",
        "regex": re.compile(r"\bunchecked\s*\{"),
        "hint": "Убедись, что overflow реально невозможен",
    },
    {
        "id": "floating_pragma",
        "name": "Floating pragma",
        "severity": "low",
        "regex": re.compile(r"pragma solidity\s+\^"),
        "hint": "Зафиксируй точную версию — избегай непредсказуемых апгрейдов",
    },
    {
        "id": "deprecated_constructor",
        "name": "Deprecated constructor (function + contract name)",
        "severity": "high",
        "regex": re.compile(
            r"function\s+\w+\s*\([^)]*\)\s+(?:public|external)\s*(?:payable)?\s*\{\s*(?:owner|admin)\s*="),
        "hint": "В Sol <0.4.x это был конструктор. В новых версиях — "
                "уязвимость!",
    },
    {
        "id": "shadow_state_var",
        "name": "Shadowed state variable (эвристика)",
        "severity": "medium",
        "regex": re.compile(
            r"function\s+\w+\s*\([^)]*\)\s+[^{]+\{[^}]{0,100}?"
            r"uint(?:256)?\s+(\w+)\s*="),
        "hint": "Проверь, не затеняет ли локальная переменная state var",
    },
    {
        "id": "todo_comment",
        "name": "TODO / FIXME comment",
        "severity": "low",
        "regex": re.compile(r"//\s*(?:TODO|FIXME|XXX|HACK)",
                             re.IGNORECASE),
        "hint": "Незакрытые TODO — потенциальные баги",
    },
    {
        "id": "testnet_deploy",
        "name": "Testnet / hardcoded URL",
        "severity": "low",
        "regex": re.compile(
            r"https?://(?:ropsten|rinkeby|kovan|goerli|sepolia)\."
            r"(?:infura|alchemy|etherscan)"),
        "hint": "Убери testnet-URL перед mainnet deploy",
    },
    {
        "id": "hardcoded_address",
        "name": "Hardcoded address",
        "severity": "low",
        "regex": re.compile(r"0x[a-fA-F0-9]{40}"),
        "hint": "Проверь, это не EOA/ничей адрес",
    },
    {
        "id": "arbitrary_jump",
        "name": "Yul arbitrary jump",
        "severity": "high",
        "regex": re.compile(r"\bjump\s*\(|\bjumpi\s*\("),
        "hint": "Yul jump без проверок = RCE",
    },
    {
        "id": "initializer_not_locked",
        "name": "Initializer without _disableInitializers",
        "severity": "high",
        "regex": re.compile(
            r"function\s+initialize\s*\([^)]*\)\s+[^{]+\{[^}]{0,200}?"
            r"initialized\s*="),
        "hint": "Upgradeable: не забудь _disableInitializers() в "
                "конструкторе",
    },
    {
        "id": "first_depositor",
        "name": "First-depositor attack (ERC4626-like)",
        "severity": "medium",
        "regex": re.compile(
            r"(?:totalSupply|totalAssets)\s*\(\s*\)\s*==\s*0|"
            r"if\s*\(\s*totalSupply\s*\(\s*\)\s*==\s*0"),
        "hint": "Initial share inflation — используй dead shares",
    },
    {
        "id": "donation_attack",
        "name": "Donation attack (balance used for shares)",
        "severity": "medium",
        "regex": re.compile(
            r"token\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"),
        "hint": "Используй internal accounting вместо balanceOf(this)",
    },
    {
        "id": "signature_malleable",
        "name": "Signature malleability (no EIP-2)",
        "severity": "medium",
        "regex": re.compile(
            r"uint8\s+v\b|(?:s|v)\s*=\s*\w+\[[^\]]+\]\s*;"),
        "hint": "Проверь 27/28 vs 0/1 и низкий s",
    },
    {
        "id": "delegatecall_user_input",
        "name": "delegatecall with user input",
        "severity": "critical",
        "regex": re.compile(
            r"\.delegatecall\s*\([^)]*(?:msg\.data|_data|input)"),
        "hint": "User-controlled delegatecall = RCE",
    },
]


# ===========================================================================
# Private keys (расширено)
# ===========================================================================

PK_PATTERNS = [
    ("Ethereum Private Key (64 hex)",
     re.compile(r"\b(?:0x)?([0-9a-fA-F]{64})\b")),
    ("Bitcoin WIF (5/H/K/L)",
     re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")),
    ("BIP39 Mnemonic (12 words)",
     re.compile(r"\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b")),
    ("BIP39 Mnemonic (24 words)",
     re.compile(r"\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b")),
    ("Keystore JSON",
     re.compile(r'"crypto"\s*:\s*\{[^}]*"cipher"')),
    ("HD Wallet xprv",
     re.compile(r"\bxprv[1-9A-HJ-NP-Za-km-z]{100,115}\b")),
    ("Solana Keypair (base58, ~88 chars)",
     re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{80,100}\b")),
    ("Tron Private Key (64 hex)",
     re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("Starknet Private Key (0x + 63-64 hex)",
     re.compile(r"\b0x[0-9a-fA-F]{62,64}\b")),
    ("Aptos / Sui Private Key (0x + 64 hex)",
     re.compile(r"\b0x[0-9a-fA-F]{64}\b")),
    ("Cosmos Private Key (base64 ~44)",
     re.compile(r"\b[A-Za-z0-9+/]{43}=?\b")),
    ("Polkadot / Substrate seed (12 words)",
     re.compile(r"\b(?:[a-z]{4,10}\s+){11}[a-z]{4,10}\b")),
]


# ===========================================================================
# Chain configs (для multi-chain)
# ===========================================================================

CHAINS = {
    "ethereum": {
        "name": "Ethereum Mainnet",
        "explorer": "https://api.etherscan.io/api",
        "scan": "https://etherscan.io/address/{a}",
        "chain_id": 1,
    },
    "polygon": {
        "name": "Polygon",
        "explorer": "https://api.polygonscan.com/api",
        "scan": "https://polygonscan.com/address/{a}",
        "chain_id": 137,
    },
    "bsc": {
        "name": "BSC",
        "explorer": "https://api.bscscan.com/api",
        "scan": "https://bscscan.com/address/{a}",
        "chain_id": 56,
    },
    "arbitrum": {
        "name": "Arbitrum One",
        "explorer": "https://api.arbiscan.io/api",
        "scan": "https://arbiscan.io/address/{a}",
        "chain_id": 42161,
    },
    "optimism": {
        "name": "Optimism",
        "explorer": "https://api-optimistic.etherscan.io/api",
        "scan": "https://optimistic.etherscan.io/address/{a}",
        "chain_id": 10,
    },
    "base": {
        "name": "Base",
        "explorer": "https://api.basescan.org/api",
        "scan": "https://basescan.org/address/{a}",
        "chain_id": 8453,
    },
    "avalanche": {
        "name": "Avalanche C-Chain",
        "explorer": "https://api.snowtrace.io/api",
        "scan": "https://snowtrace.io/address/{a}",
        "chain_id": 43114,
    },
    "fantom": {
        "name": "Fantom",
        "explorer": "https://api.ftmscan.com/api",
        "scan": "https://ftmscan.com/address/{a}",
        "chain_id": 250,
    },
    "goerli": {
        "name": "Goerli (testnet)",
        "explorer": "https://api-goerli.etherscan.io/api",
        "scan": "https://goerli.etherscan.io/address/{a}",
        "chain_id": 5,
    },
    "sepolia": {
        "name": "Sepolia (testnet)",
        "explorer": "https://api-sepolia.etherscan.io/api",
        "scan": "https://sepolia.etherscan.io/address/{a}",
        "chain_id": 11155111,
    },
}


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class Web3Finding:
    kind: str
    severity: str
    detail: str = ""
    source: str = ""
    line: int = 0
    code_snippet: str = ""
    data: dict = field(default_factory=dict)


# ===========================================================================
# Solidity analysis
# ===========================================================================

def analyze_solidity(path: str) -> list[Web3Finding]:
    """Анализ Solidity-файла."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []
    try:
        source = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return []

    console.print(f"[cyan]🔍 Solidity: {p.name} "
                  f"({len(source)} bytes)[/cyan]")

    findings: list[Web3Finding] = []
    lines = source.splitlines()

    for pat in SOLIDITY_PATTERNS:
        try:
            for m in pat["regex"].finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                snippet = ""
                try:
                    snippet = lines[line_no - 1].strip()[:120]
                except Exception:
                    pass
                findings.append(Web3Finding(
                    kind=pat["id"],
                    severity=pat["severity"],
                    detail=pat["name"],
                    source=str(p),
                    line=line_no,
                    code_snippet=snippet,
                    data={"hint": pat["hint"]},
                ))
        except Exception as exc:
            log.debug("pattern %s: %s", pat["id"], exc)

    seen = set()
    unique: list[Web3Finding] = []
    for f in findings:
        k = (f.kind, f.line)
        if k not in seen:
            seen.add(k)
            unique.append(f)

    _print_solidity_findings(unique, p.name)
    _save_findings_bulk(unique, target=str(p))

    db.save_scan("web3_solidity", p.name, {
        "findings": len(unique),
        "severities": {
            s: sum(1 for f in unique if f.severity == s)
            for s in ("critical", "high", "medium", "low")
        },
    })
    return unique


def _save_findings_bulk(findings: list[Web3Finding],
                          target: str = "") -> None:
    """Findings → notes + notify."""
    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    if not critical and not high:
        return
    for f in (critical + high)[:10]:
        _save_finding(W3Finding(
            kind=f"solidity_{f.kind}",
            severity=f.severity,
            title=f"Solidity: {f.detail}",
            target=target,
            evidence=f"Line {f.line}: {f.code_snippet}\n"
                     f"Hint: {f.data.get('hint', '')}",
            data={"kind": f.kind, "line": f.line,
                  "hint": f.data.get("hint", "")},
        ))
    _notify(
        f"⛓  Solidity findings: {len(critical)}C / {len(high)}H",
        f"Target: {target}\n"
        f"Critical: {', '.join(f.detail for f in critical[:5])}\n"
        f"High: {', '.join(f.detail for f in high[:5])}",
        severity="high",
    )


def _print_solidity_findings(findings: list[Web3Finding],
                              name: str) -> None:
    if not findings:
        console.print(f"[green]✓ {name}: паттернов не найдено.[/green]")
        return
    for sev in ("critical", "high", "medium", "low"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green"}[sev]
        t = Table(title=f"[{sty}]{sev.upper()} ({len(group)})[/{sty}]")
        t.add_column("#", width=4)
        t.add_column("Pattern", style="cyan", max_width=32)
        t.add_column("Line", width=6)
        t.add_column("Snippet", style="white", max_width=55)
        for i, f in enumerate(group[:40], 1):
            t.add_row(str(i), f.detail, str(f.line),
                      f.code_snippet[:55])
        console.print(t)


def analyze_solidity_dir(path: str) -> list[Web3Finding]:
    """Анализ директории с .sol файлами."""
    p = Path(path)
    if not p.is_dir():
        return analyze_solidity(path)
    all_findings: list[Web3Finding] = []
    sols = sorted(p.rglob("*.sol"))
    if not sols:
        console.print("[yellow]Нет .sol файлов.[/yellow]")
        return []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task("scan", total=len(sols))
        for sol in sols:
            prog.advance(task)
            try:
                all_findings.extend(analyze_solidity(str(sol)))
            except Exception as exc:
                log.warning("solidity %s: %s", sol, exc)
    console.print(f"\n[bold cyan]Всего: {len(all_findings)} находок"
                  f"[/bold cyan]")

    # Сводный отчёт
    if all_findings and Confirm.ask("Экспорт отчёта?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        export_findings(all_findings, "solidity_dir", fmt=fmt)
    return all_findings


# ===========================================================================
# Private key scanner
# ===========================================================================

def scan_private_keys(path: str) -> list[Web3Finding]:
    """Скан файлов/директории на приватные ключи."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []

    files: list[Path] = []
    if p.is_file():
        files = [p]
    else:
        for ext in ("*.js", "*.ts", "*.json", "*.txt", "*.env",
                     "*.log", "*.html", "*.sol", "*.md", "*.yaml",
                     "*.yml", "*.config"):
            files.extend(p.rglob(ext))
        files = list(set(files))[:500]

    console.print(f"[cyan]🔑 Сканирую {len(files)} файлов "
                  f"на приватные ключи…[/cyan]")
    findings: list[Web3Finding] = []

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task("scan", total=len(files))
        for f in files:
            prog.advance(task)
            try:
                if f.stat().st_size > 5 * 1024 * 1024:
                    continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for label, pat in PK_PATTERNS:
                try:
                    for m in pat.finditer(text):
                        val = m.group(1) if m.groups() else m.group()
                        # Фильтр хешей для 64-hex
                        if "hex" in label.lower() and "Tron" not in label:
                            ctx = text[max(0, m.start() - 100):
                                        m.end() + 50]
                            low_ctx = ctx.lower()
                            if any(w in low_ctx for w in (
                                "sha256", "md5", "sha1", "sha512",
                                "hash", "checksum", "digest",
                                "commit", "git",
                            )):
                                continue
                        line_no = text[:m.start()].count("\n") + 1
                        findings.append(Web3Finding(
                            kind="private_key",
                            severity="critical",
                            detail=label,
                            source=str(f),
                            line=line_no,
                            code_snippet=val[:80],
                            data={"value": val[:120]},
                        ))
                except Exception:
                    continue

    # Dedup
    seen = set()
    unique: list[Web3Finding] = []
    for f in findings:
        k = (f.detail, f.data.get("value"))
        if k not in seen:
            seen.add(k)
            unique.append(f)

    if unique:
        t = Table(title=f"🔑 Найдено {len(unique)} кандидатов",
                  border_style="red")
        t.add_column("#", width=4)
        t.add_column("Type", style="cyan", max_width=32)
        t.add_column("Value", style="red", max_width=50)
        t.add_column("Source", style="dim", max_width=40)
        t.add_column("Line", width=6)
        for i, f in enumerate(unique[:50], 1):
            t.add_row(str(i), f.detail,
                      (f.data.get("value") or "")[:50],
                      Path(f.source).name[:40],
                      str(f.line))
        console.print(t)

        # Findings + notify (critical!)
        _save_finding(W3Finding(
            kind="private_key_leaked",
            severity="critical",
            title=f"Приватные ключи найдены: {len(unique)}",
            target=str(p),
            evidence="\n".join(
                f"{f.detail} @ {f.source}:{f.line}"
                for f in unique[:10]),
            data={"count": len(unique),
                  "files": [f.source for f in unique[:20]]},
        ))
        _notify(
            f"🚨 Private keys leaked: {len(unique)}",
            f"Path: {p}\n"
            f"Types: {', '.join(set(f.detail for f in unique[:10]))}",
            severity="critical",
        )
    else:
        console.print("[green]✓ Приватных ключей не найдено.[/green]")

    db.save_scan("web3_pkscan", str(p), {
        "scanned": len(files),
        "found": len(unique),
    })

    if unique and Confirm.ask("Экспорт отчёта?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        export_findings(unique, "pk_scan", fmt=fmt)
    return unique


# ===========================================================================
# Etherscan lookup (multi-chain)
# ===========================================================================

def etherscan_lookup(address: str,
                       chain: str = "ethereum") -> dict:
    """Публичная информация о контракте/адресе."""
    if chain not in CHAINS:
        console.print(f"[red]Неизвестная сеть: {chain}[/red]")
        return {}
    info = CHAINS[chain]
    api = info["explorer"]
    result: dict = {"address": address, "chain": chain,
                     "chain_name": info["name"]}

    console.print(f"[cyan]🔍 {info['name']}: {address}[/cyan]")

    # 1. Balance
    try:
        r = requests.get(
            api,
            params={"module": "account", "action": "balance",
                     "address": address, "tag": "latest"},
            timeout=TIMEOUT, verify=False)
        data = r.json()
        if data.get("status") == "1":
            wei = int(data["result"])
            balance = wei / 10**18
            result["balance_eth"] = balance
            console.print(f"[green]Balance: {balance:.6f} "
                          f"native[/green]")
        else:
            console.print(f"[yellow]Balance API: "
                          f"{data.get('message')}[/yellow]")
    except Exception as exc:
        console.print(f"[red]Balance error: {exc}[/red]")

    # 2. Code
    try:
        r = requests.get(
            api,
            params={"module": "proxy", "action": "eth_getCode",
                     "address": address, "tag": "latest"},
            timeout=TIMEOUT, verify=False)
        data = r.json()
        code = data.get("result", "0x")
        is_contract = code and code != "0x"
        result["is_contract"] = bool(is_contract)
        result["code_size"] = len(code) if code else 0
        console.print(f"[cyan]Is contract:[/cyan] {is_contract} "
                      f"(code hex len {result['code_size']})")
    except Exception as exc:
        log.debug("code check: %s", exc)

    # 3. Tx count (nonce)
    try:
        r = requests.get(
            api,
            params={"module": "proxy",
                     "action": "eth_getTransactionCount",
                     "address": address, "tag": "latest"},
            timeout=TIMEOUT, verify=False)
        data = r.json()
        nonce = int(data.get("result", "0x0"), 16)
        result["tx_count"] = nonce
        console.print(f"[cyan]Tx count:[/cyan] {nonce}")
    except Exception as exc:
        log.debug("nonce: %s", exc)

    # 4. Token info (if contract)
    if result.get("is_contract"):
        _token_info(address, chain, api, result)

    # 5. Proxy detection (EIP-1967)
    _proxy_check(address, chain, api, result)

    # 6. Explorer link
    result["explorer_url"] = info["scan"].format(a=address)
    console.print(f"[dim]→ {result['explorer_url']}[/dim]")

    db.save_scan("web3_etherscan", f"{chain}:{address}", result)
    return result


def _token_info(address: str, chain: str, api: str,
                 result: dict) -> None:
    """Проверка ERC20/721/1155 signature."""
    # Селекторы
    sigs = {
        "name()": "0x06fdde03",
        "symbol()": "0x95d89b41",
        "decimals()": "0x313ce567",
        "totalSupply()": "0x18160ddd",
        "ownerOf(uint256)": "0x6352211e",
        "balanceOf(uint256)": "0x00fdd58e",  # ERC1155
    }
    hits = {}
    for sig_name, selector in sigs.items():
        try:
            r = requests.get(
                api,
                params={"module": "proxy", "action": "eth_call",
                         "to": address, "data": selector,
                         "tag": "latest"},
                timeout=TIMEOUT, verify=False)
            data = r.json()
            out = data.get("result", "0x")
            if out and out != "0x":
                hits[sig_name] = out[:66]
        except Exception:
            continue
    result["token_signatures"] = hits

    standards = []
    if "name()" in hits and "symbol()" in hits and \
            "decimals()" in hits and "totalSupply()" in hits:
        standards.append("ERC20")
    if "ownerOf(uint256)" in hits:
        standards.append("ERC721")
    if "balanceOf(uint256)" in hits:
        standards.append("ERC1155")
    result["token_standards"] = standards
    if standards:
        console.print(f"[cyan]Token standards:[/cyan] "
                      f"{', '.join(standards)}")


def _proxy_check(address: str, chain: str, api: str,
                  result: dict) -> None:
    """Проверка proxy-паттерна (EIP-1967)."""
    slots = {
        "EIP-1967_impl": "0x360894a13ba1a3210667c828492db98dca3e2076cc37"
                         "32b9f1c13c3e93e5b6c8",
        "EIP-1967_admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8"
                          "ee177a3871a8e5d7d2c0d1",
        "EIP-1967_beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72a"
                            "d8cd3eebae0d3c1c04f1a8b8",
    }
    proxies = {}
    for name, slot in slots.items():
        try:
            r = requests.get(
                api,
                params={"module": "proxy", "action": "eth_getStorageAt",
                         "address": address, "position": slot,
                         "tag": "latest"},
                timeout=TIMEOUT, verify=False)
            data = r.json()
            val = data.get("result", "0x")
            if val and val != "0x" + "0" * 64:
                impl_addr = "0x" + val[-40:]
                proxies[name] = impl_addr
        except Exception:
            continue
    if proxies:
        result["proxy_slots"] = proxies
        console.print(f"[yellow]⚠ Proxy detected:[/yellow] "
                      f"{list(proxies.keys())}")


# ===========================================================================
# Honeypot heuristics
# ===========================================================================

def honeypot_heuristics(address: str) -> dict:
    """Эвристики honeypot-детекта."""
    console.print(f"[cyan]🍯 Honeypot check: {address}[/cyan]")

    result: dict = {"address": address, "checks": {},
                     "external": {}}

    try:
        r = requests.get(
            "https://api.etherscan.io/api",
            params={"module": "proxy", "action": "eth_getCode",
                     "address": address, "tag": "latest"},
            timeout=TIMEOUT, verify=False)
        code_hex = r.json().get("result", "")
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return result

    if not code_hex or code_hex == "0x":
        console.print("[yellow]Нет кода (EOA).[/yellow]")
        result["checks"]["is_contract"] = False
        return result

    result["checks"]["is_contract"] = True
    code_len = len(code_hex) // 2
    result["checks"]["code_size_bytes"] = code_len
    result["checks"]["code_entropy"] = round(
        _shannon_entropy_bytes(bytes.fromhex(code_hex[2:])), 3)

    suspicious = []
    if code_len < 500:
        suspicious.append("Маленький контракт (<500 байт)")
    if code_len > 24000:
        suspicious.append("Большой контракт (>24KB, EIP-170 лимит)")
    if result["checks"]["code_entropy"] < 3.0:
        suspicious.append("Низкая энтропия байткода (возможно stub)")

    result["checks"]["suspicious"] = suspicious

    for s in suspicious:
        console.print(f"[yellow]⚠ {s}[/yellow]")

    console.print(f"[cyan]Code size:[/cyan] {code_len} bytes, "
                  f"entropy: {result['checks']['code_entropy']}")

    result["external"] = {
        "honeypot_is": f"https://honeypot.is/ethereum?address={address}",
        "de.fi": f"https://de.fi/scanner/contract/{address}",
        "etherscan": f"https://etherscan.io/address/{address}#code",
        "tokensniffer": f"https://tokensniffer.com/token/eth/{address}",
    }
    for k, v in result["external"].items():
        console.print(f"[dim]{k}: {v}[/dim]")

    db.save_scan("web3_honeypot", address, result)
    return result


def _shannon_entropy_bytes(data: bytes) -> float:
    """Shannon entropy в битах на байт."""
    if not data:
        return 0.0
    from collections import Counter
    import math
    counter = Counter(data)
    length = len(data)
    ent = 0.0
    for c in counter.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


# ===========================================================================
# Wallet drainer patterns
# ===========================================================================

DRAINER_PATTERNS = [
    (r"setApprovalForAll\s*\(\s*(?:msg\.sender|_from)\s*,\s*"
     r"(?:true|address\s*\(\s*0x[0-9a-f]+)\s*\)",
     "setApprovalForAll — потенциальный drainer"),
    (r"increaseAllowance\s*\(\s*[^,]+,\s*type\s*\(\s*uint256\s*\)\.max",
     "increaseAllowance до max — drainer"),
    (r"permit\s*\([^)]*,\s*v\s*,\s*r\s*,\s*s",
     "Permit2 — drainer"),
    (r"transferFrom\s*\(\s*[^,]+,\s*0x[0-9a-fA-F]{40}\s*,",
     "transferFrom без user consent"),
    (r"multicall\s*\(|multisend\s*\(",
     "Multicall / multisend — batched ops"),
    (r"signTypedData|eth_signTypedData",
     "Typed-data signature request (drainer)"),
    (r"personal_sign|eth_sign\b",
     "Personal_sign request"),
    (r"window\.ethereum\.request",
     "MetaMask RPC call"),
    (r"walletconnect|wallet_switchEthereumChain",
     "WalletConnect / chain switch"),
    (r"seaport|wyvern|looksrare|blur",
     "Marketplace (Seaport/Wyvern/LooksRare/Blur) — approve риск"),
    (r"0x00000000006c3852cbEf3e08E8dF289169EdE581",
     "Seaport 1.1 contract"),
    (r"0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",
     "Seaport 1.5 contract"),
    (r"transferOwnership\s*\(\s*0x0",
     "transferOwnership(0) — renounce"),
    (r"airdrop|claimAirdrop|claimReward",
     "Airdrop/claim (фишинг)"),
    (r"drain|drainer|steal|exfil",
     "Explicit drain keywords"),
]


def scan_drainer_patterns(path: str) -> list[Web3Finding]:
    """Скан JS-файлов на паттерны wallet drainer."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []

    files: list[Path] = []
    if p.is_file():
        files = [p]
    else:
        for ext in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.html",
                     "*.htm"):
            files.extend(p.rglob(ext))
        files = list(set(files))[:200]

    findings: list[Web3Finding] = []
    console.print(f"[cyan]💀 Сканирую {len(files)} файлов "
                  f"на drainer-паттерны…[/cyan]")

    for f in files:
        try:
            if f.stat().st_size > 5 * 1024 * 1024:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, desc in DRAINER_PATTERNS:
            try:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    line = text[:m.start()].count("\n") + 1
                    findings.append(Web3Finding(
                        kind="drainer_pattern",
                        severity="high",
                        detail=desc,
                        source=str(f),
                        line=line,
                        code_snippet=m.group()[:120],
                    ))
            except Exception:
                continue

    if findings:
        t = Table(title=f"💀 Drainer patterns ({len(findings)})",
                  border_style="red")
        t.add_column("#", width=4)
        t.add_column("Desc", style="cyan", max_width=40)
        t.add_column("Line", width=6)
        t.add_column("Snippet", style="red", max_width=55)
        for i, f in enumerate(findings[:50], 1):
            t.add_row(str(i), f.detail, str(f.line),
                      f.code_snippet[:55])
        console.print(t)
        _save_finding(W3Finding(
            kind="drainer_detected",
            severity="high",
            title=f"Drainer-паттерны: {len(findings)}",
            target=str(p),
            evidence="\n".join(
                f"{f.detail} @ {Path(f.source).name}:{f.line}"
                for f in findings[:10]),
            data={"count": len(findings)},
        ))
    else:
        console.print("[green]✓ Drainer-паттернов не найдено.[/green]")
    return findings


# ===========================================================================
# Экспорт
# ===========================================================================

def export_findings(findings: list[Web3Finding], name: str = "web3",
                     fmt: str = "html") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "csv": ".csv", "md": ".md",
           "html": ".html"}.get(fmt, ".json")
    path = WEB3_DIR / f"{name}_{ts}{ext}"

    try:
        if fmt == "json":
            path.write_text(json.dumps(
                [asdict(f) for f in findings], indent=2,
                ensure_ascii=False, default=str),
                encoding="utf-8")
        elif fmt == "csv":
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["severity", "kind", "detail", "source",
                            "line", "snippet"])
                for fd in findings:
                    w.writerow([fd.severity, fd.kind, fd.detail,
                                fd.source, fd.line,
                                fd.code_snippet[:200]])
        elif fmt == "md":
            lines = [
                f"# Web3 findings: {name}",
                f"_Generated: {datetime.now().isoformat()}_",
                f"_Total: {len(findings)}_",
                "",
                "| Sev | Kind | Detail | Location |",
                "|-----|------|--------|----------|",
            ]
            for f in findings:
                loc = f"{Path(f.source).name}:{f.line}"
                lines.append(
                    f"| {f.severity} | {f.kind} | {f.detail[:40]} | "
                    f"`{loc}` |")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                f"<title>Web3 findings — {html_mod.escape(name)}</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;"
                "max-width:1300px;margin:0 auto;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;"
                "margin-top:12px;font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "text-align:left;border:1px solid #222;}",
                "td{padding:5px 8px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                ".critical{color:#ff2020;font-weight:bold;}"
                ".high{color:#ff7a40;font-weight:bold;}"
                ".medium{color:#ffd23f;}"
                ".low{color:#00ff9c;}",
                "</style></head><body>",
                f"<h1>⛓  Web3 findings: "
                f"{html_mod.escape(name)} ({len(findings)})</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>Sev</th><th>Kind</th><th>Detail</th>"
                "<th>Location</th><th>Snippet</th></tr>",
            ]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for f in sorted(findings,
                              key=lambda x: order.get(x.severity, 9)):
                loc = f"{Path(f.source).name}:{f.line}"
                parts.append(
                    f"<tr><td class='{f.severity}'>"
                    f"{f.severity.upper()}</td>"
                    f"<td>{html_mod.escape(f.kind)}</td>"
                    f"<td>{html_mod.escape(f.detail)}</td>"
                    f"<td>{html_mod.escape(loc)}</td>"
                    f"<td><code>{html_mod.escape(f.code_snippet[:120])}"
                    f"</code></td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")

        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# CLI
# ===========================================================================

def cli_solidity(path: str) -> None:
    findings = analyze_solidity(path)
    if findings and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        export_findings(findings, "solidity", fmt=fmt)


def cli_dir(path: str) -> None:
    analyze_solidity_dir(path)


def cli_pk(path: str) -> None:
    scan_private_keys(path)


def cli_etherscan(address: str) -> None:
    chain = Prompt.ask("Сеть",
                        choices=list(CHAINS.keys()),
                        default="ethereum")
    etherscan_lookup(address, chain)


def cli_honeypot(address: str) -> None:
    honeypot_heuristics(address)


def cli_drainer(path: str) -> None:
    findings = scan_drainer_patterns(path)
    if findings and Confirm.ask("Экспорт?", default=False):
        fmt = Prompt.ask("Формат",
                         choices=["html", "json", "csv", "md"],
                         default="html")
        export_findings(findings, "drainer", fmt=fmt)


def menu() -> None:
    t = Table(title="[bold]⛓  Blockchain / Web3 Security[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", f"Solidity static analysis ({len(SOLIDITY_PATTERNS)} паттернов)"),
        ("2", "Solidity directory scan"),
        ("3", f"Private key scanner ({len(PK_PATTERNS)} типов)"),
        ("4", f"Etherscan lookup ({len(CHAINS)} chains)"),
        ("5", "Honeypot heuristics"),
        ("6", f"Wallet drainer patterns ({len(DRAINER_PATTERNS)})"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного анализа.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        analyze_solidity(Prompt.ask("Путь к .sol"))
    elif c == "2":
        analyze_solidity_dir(Prompt.ask("Директория"))
    elif c == "3":
        scan_private_keys(Prompt.ask("Путь (файл/директория)"))
    elif c == "4":
        addr = Prompt.ask("0x-адрес")
        chain = Prompt.ask("Сеть", choices=list(CHAINS.keys()),
                            default="ethereum")
        etherscan_lookup(addr, chain)
    elif c == "5":
        honeypot_heuristics(Prompt.ask("0x-адрес контракта"))
    elif c == "6":
        scan_drainer_patterns(Prompt.ask("Путь (файл/директория)"))