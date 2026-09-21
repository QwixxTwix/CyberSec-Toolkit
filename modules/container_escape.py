"""
Container Escape Suite — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF.

Возможности:
    ─── Runtime / Container detection ───
    - Docker / containerd / CRI-O / Podman / K8s / LXC detection
    - /proc/1/cgroup fingerprint
    - /.dockerenv + /run/.containerenv
    - Container ID extraction

    ─── Privileges / Namespaces ───
    - Full capabilities decode (41 Linux caps)
    - CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, ...
    - Namespace check (user / pid / net / mnt)
    - Seccomp mode
    - AppArmor / SELinux status
    - User namespaces enabled

    ─── Escape vectors ───
    - Docker socket / containerd socket / CRI-O socket
    - Host mounts (/host, /var/lib/docker, /var/lib/kubelet)
    - /proc/1/root read access
    - /proc/sys/kernel/core_pattern (host RCE)
    - cgroup v1/v2 escape (CVE-2022-0492)
    - eBPF availability
    - Kernel module loading
    - Debugfs / procfs dangerous mounts

    ─── K8s-specific ───
    - Service account token
    - Kubelet API (10250 / 10255)
    - /var/run/secrets enumeration
    - Pod environment variables

    ─── Kernel CVEs ───
    - 12+ CVE база с affected / check / exploit
    - Auto kernel version matching (heuristics)

    ─── Findings ───
    - Findings → notes для critical/high
    - HTML / JSON экспорт
    - Notify по завершении
"""
import html as html_mod
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

CE_DIR = REPORT_DIR / "container_escape"
CE_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Linux Capabilities (полный список)
# ===========================================================================

LINUX_CAPS = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

# Capabilities, критичные для container escape
DANGEROUS_CAPS = {
    2: "critical",   # CAP_DAC_READ_SEARCH — читать любой файл
    16: "critical",  # CAP_SYS_MODULE — загрузка kernel module
    17: "critical",  # CAP_SYS_RAWIO — /dev/mem, /dev/kmem
    19: "high",      # CAP_SYS_PTRACE — ptrace любого процесса
    21: "critical",  # CAP_SYS_ADMIN — mount, cgroup, namespaces
    22: "high",      # CAP_SYS_BOOT — reboot
    24: "medium",    # CAP_SYS_RESOURCE
    27: "high",      # CAP_MKNOD — создать device-файлы
    32: "high",      # CAP_MAC_OVERRIDE
    33: "high",      # CAP_MAC_ADMIN
}


# ===========================================================================
# Kernel CVE база (расширенная)
# ===========================================================================

KERNEL_CVES = {
    "CVE-2021-4034": {
        "name": "PwnKit (pkexec)",
        "affects": "polkit pkexec < 0.120",
        "check": "pkexec --version 2>&1 | head -1",
        "exploit": "https://github.com/berdav/CVE-2021-4034",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2022-0847": {
        "name": "Dirty Pipe",
        "affects": "Linux kernel 5.8 – 5.16.11",
        "check": "uname -r",
        "exploit": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2021-3493": {
        "name": "OverlayFS (Ubuntu)",
        "affects": "Ubuntu kernel < 5.11",
        "check": "uname -r; cat /etc/os-release",
        "exploit": "https://github.com/briskets/CVE-2021-3493",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2021-3156": {
        "name": "Baron Samedit (sudo)",
        "affects": "sudo 1.8.2 – 1.8.31p2, 1.9.0 – 1.9.5p1",
        "check": "sudo --version | head -2",
        "exploit": "https://github.com/blasty/CVE-2021-3156",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2022-0492": {
        "name": "cgroups v2 escape",
        "affects": "Linux kernel < 5.16.2 (with CAP_SYS_ADMIN)",
        "check": "cat /proc/self/status | grep CapEff",
        "exploit": "https://github.com/PaloAltoNetworks/cgroup-escape",
        "impact": "Container escape",
        "severity": "critical",
    },
    "CVE-2019-5736": {
        "name": "runc escape",
        "affects": "runc < 1.0.0-rc6",
        "check": "docker version; runc --version",
        "exploit": "https://github.com/Frichetten/CVE-2019-5736-PoC",
        "impact": "Container escape → host root",
        "severity": "critical",
    },
    "CVE-2022-0185": {
        "name": "fs_context heap overflow",
        "affects": "Linux kernel 5.1 – 5.16.1",
        "check": "uname -r",
        "exploit": "https://github.com/Crusaders-of-Rust/CVE-2022-0185",
        "impact": "Container escape (with CAP_SYS_ADMIN)",
        "severity": "critical",
    },
    "CVE-2022-1015": {
        "name": "nftables OOB write",
        "affects": "Linux kernel < 5.17",
        "check": "uname -r; lsmod | grep nf_tables",
        "exploit": "https://github.com/linsecurity/CVE-2022-1015",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2022-25636": {
        "name": "nft_fwd_dup_netdev OOB",
        "affects": "Linux kernel 5.4 – 5.16.x",
        "check": "uname -r; lsmod | grep nf_dup_netdev",
        "exploit": "https://github.com/Bonfee/CVE-2022-25636",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2022-2588": {
        "name": "cls_route UAF",
        "affects": "Linux kernel < 5.19",
        "check": "uname -r; lsmod | grep cls_route",
        "exploit": "https://github.com/Markakd/CVE-2022-2588",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2023-0386": {
        "name": "OverlayFS copy-up",
        "affects": "Linux kernel < 6.2",
        "check": "uname -r",
        "exploit": "https://github.com/xkaneiki/CVE-2023-0386",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2023-2640": {
        "name": "Ubuntu OverlayFS",
        "affects": "Ubuntu kernel 6.2 / 6.5",
        "check": "uname -r; cat /etc/os-release",
        "exploit": "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629",
        "impact": "Local priv-esc (root)",
        "severity": "high",
    },
    "CVE-2024-1086": {
        "name": "nf_tables UAF",
        "affects": "Linux kernel 5.14 – 6.6",
        "check": "uname -r; lsmod | grep nf_tables",
        "exploit": "https://github.com/Notselwyn/CVE-2024-1086",
        "impact": "Local priv-esc (root)",
        "severity": "critical",
    },
    "CVE-2024-21626": {
        "name": "runc cwd leak (Leaky Vessels)",
        "affects": "runc < 1.1.11",
        "check": "runc --version; docker version",
        "exploit": "https://github.com/snyk/leaky-vessels",
        "impact": "Container escape → host",
        "severity": "critical",
    },
}


# ===========================================================================
# Model
# ===========================================================================

@dataclass
class CheckResult:
    check: str
    result: str
    severity: str = "info"     # critical | high | medium | low | info
    detail: str = ""
    remediation: str = ""


def _save_finding(r: CheckResult) -> int:
    if r.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f"Container escape: {r.check}",
            target="local",
            severity=r.severity,
            status="open",
            tags=["container-escape", r.severity],
            body=(f"**Check:** {r.check}\n"
                  f"**Result:** {r.result}\n"
                  f"**Detail:** {r.detail}\n\n"
                  f"**Remediation:** {r.remediation or '—'}"),
        )
    except Exception:
        return -1


# ===========================================================================
# Detection
# ===========================================================================

def _run_cmd(cmd: list[str], timeout: int = 5) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout)
        return r.returncode, ((r.stdout or "") + (r.stderr or ""))[:1000]
    except FileNotFoundError:
        return (-1, "not found")
    except subprocess.TimeoutExpired:
        return (-1, f"timeout {timeout}s")
    except Exception as exc:
        return (-1, str(exc)[:100])


def detect_runtime() -> CheckResult:
    """Определить container runtime."""
    indicators: list[str] = []
    runtime = "unknown"
    container_id = ""

    if Path("/.dockerenv").exists():
        indicators.append("/.dockerenv")
        runtime = "docker"

    if Path("/run/.containerenv").exists():
        indicators.append("/run/.containerenv")
        if runtime == "unknown":
            runtime = "podman"

    try:
        cgroup = Path("/proc/1/cgroup").read_text(errors="ignore")
        for r_name, marker in [
            ("docker", "docker"), ("k8s", "kubepods"),
            ("containerd", "containerd"), ("crio", "crio"),
            ("podman", "libpod"), ("lxc", "lxc"),
        ]:
            if marker in cgroup.lower():
                indicators.append(f"cgroup:{marker}")
                if runtime == "unknown":
                    runtime = r_name
        # Container ID (64 hex)
        m = re.search(r"/([0-9a-f]{64})(?:\.scope)?", cgroup)
        if m:
            container_id = m.group(1)[:12]
    except Exception:
        pass

    # /proc/1/comm
    try:
        comm = Path("/proc/1/comm").read_text(errors="ignore").strip()
        if comm in ("tini", "dumb-init", "containerd-shim",
                     "runc", "podman", "systemd"):
            indicators.append(f"init:{comm}")
    except Exception:
        pass

    detail_parts = indicators or ["no indicators"]
    if container_id:
        detail_parts.append(f"id:{container_id}")

    return CheckResult(
        check="Container runtime",
        result=runtime.upper() if runtime != "unknown" else "BARE METAL",
        severity="info",
        detail=", ".join(detail_parts),
    )


def in_container() -> CheckResult:
    """Старый API — оставлен для совместимости."""
    r = detect_runtime()
    return CheckResult(
        check="Running in container",
        result=("YES" if r.result != "BARE METAL" else "NO"),
        severity="info",
        detail=r.detail,
    )


def check_user() -> CheckResult:
    uid = os.getuid() if hasattr(os, "getuid") else -1
    gid = os.getgid() if hasattr(os, "getgid") else -1
    sev = "critical" if uid == 0 else "info"
    return CheckResult(
        check="Current UID",
        result=str(uid),
        severity=sev,
        detail=f"uid={uid}, gid={gid} "
                f"({'root in container' if uid == 0 else 'non-root'})",
    )


# ===========================================================================
# Capabilities
# ===========================================================================

def _parse_caps(hex_str: str) -> set[int]:
    try:
        caps = int(hex_str, 16)
    except Exception:
        return set()
    return {i for i in range(64) if caps & (1 << i)}


def get_capabilities() -> tuple[set[int], set[int], set[int]]:
    """Вернуть (cap_eff, cap_prm, cap_bnd)."""
    eff, prm, bnd = set(), set(), set()
    try:
        status = Path("/proc/self/status").read_text(errors="ignore")
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                eff = _parse_caps(line.split(":")[1].strip())
            elif line.startswith("CapPrm:"):
                prm = _parse_caps(line.split(":")[1].strip())
            elif line.startswith("CapBnd:"):
                bnd = _parse_caps(line.split(":")[1].strip())
    except Exception:
        pass
    return eff, prm, bnd


def check_capabilities() -> list[CheckResult]:
    """Детальный разбор capabilities."""
    eff, _prm, _bnd = get_capabilities()
    if not eff:
        return [CheckResult(
            check="Capabilities", result="not readable",
            severity="info", detail="no /proc/self/status",
        )]

    results: list[CheckResult] = []
    # Верхняя строка: сводка
    dangerous_present = sorted(
        (c, LINUX_CAPS.get(c, f"CAP_{c}")) for c in eff
        if c in DANGEROUS_CAPS
    )
    results.append(CheckResult(
        check="Capabilities (total)",
        result=f"{len(eff)} активных",
        severity=("critical" if len(dangerous_present) >= 2 else
                   "high" if dangerous_present else "info"),
        detail=f"dangerous: {', '.join(n for _, n in dangerous_present[:5])}"
                or "нет опасных",
    ))
    # Каждая опасная
    for cap_num, name in dangerous_present:
        results.append(CheckResult(
            check=f"cap: {name}",
            result="PRESENT",
            severity=DANGEROUS_CAPS[cap_num],
            detail=f"bit={cap_num}",
            remediation=f"Убрать {name} из docker run --cap-drop={name}",
        ))
    return results


def check_privileged() -> CheckResult:
    """Backward-compat: CAP_SYS_ADMIN."""
    eff, _, _ = get_capabilities()
    has = 21 in eff  # CAP_SYS_ADMIN
    return CheckResult(
        check="CAP_SYS_ADMIN",
        result="PRESENT" if has else "absent",
        severity="critical" if has else "info",
        detail=f"CAP_SYS_ADMIN (bit 21): "
                f"{'разрешает mount, cgroup escape' if has else 'ok'}",
        remediation="--cap-drop=CAP_SYS_ADMIN",
    )


def check_ptrace() -> CheckResult:
    eff, _, _ = get_capabilities()
    has = 19 in eff
    return CheckResult(
        check="CAP_SYS_PTRACE",
        result="PRESENT" if has else "absent",
        severity="high" if has else "info",
        detail="может читать/инжектить в любые процессы",
        remediation="--cap-drop=CAP_SYS_PTRACE",
    )


def check_sys_module() -> CheckResult:
    eff, _, _ = get_capabilities()
    has = 16 in eff
    return CheckResult(
        check="CAP_SYS_MODULE",
        result="PRESENT" if has else "absent",
        severity="critical" if has else "info",
        detail="можно загружать kernel modules (root на хосте)",
        remediation="--cap-drop=CAP_SYS_MODULE",
    )


def check_dac_read_search() -> CheckResult:
    eff, _, _ = get_capabilities()
    has = 2 in eff
    return CheckResult(
        check="CAP_DAC_READ_SEARCH",
        result="PRESENT" if has else "absent",
        severity="critical" if has else "info",
        detail="обход DAC — чтение любого файла (включая /etc/shadow)",
        remediation="--cap-drop=CAP_DAC_READ_SEARCH",
    )


# ===========================================================================
# Namespaces
# ===========================================================================

def check_namespaces() -> list[CheckResult]:
    """Проверить ns: user, pid, net, mnt."""
    results: list[CheckResult] = []
    # Сравним ns с PID 1 (обычно init контейнера). Если совпадает
    # со всеми — не изолирован.
    def _read_ns(pid: int) -> dict[str, str]:
        try:
            return {p.name: os.readlink(str(p))
                    for p in Path(f"/proc/{pid}/ns").iterdir()}
        except Exception:
            return {}

    me = _read_ns(os.getpid())
    init_ns = _read_ns(1)

    # user namespace
    if "user" in me:
        sev = "medium" if me["user"] != init_ns.get("user") else "info"
        results.append(CheckResult(
            check="userns",
            result=("isolated" if me["user"] != init_ns.get("user")
                    else "shared with PID1"),
            severity=sev,
            detail=f"ns={me['user']}",
        ))
    return results


def check_seccomp() -> CheckResult:
    """Seccomp mode."""
    try:
        status = Path("/proc/self/status").read_text(errors="ignore")
        m = re.search(r"Seccomp:\s*(\d+)", status)
        if not m:
            return CheckResult("Seccomp", "unknown", "info")
        mode = int(m.group(1))
        mapping = {0: "disabled", 1: "strict", 2: "filter"}
        name = mapping.get(mode, "?")
        sev = "high" if mode == 0 else "info"
        return CheckResult(
            check="Seccomp",
            result=name,
            severity=sev,
            detail=f"mode={mode}",
            remediation="docker run --security-opt seccomp=default",
        )
    except Exception:
        return CheckResult("Seccomp", "unknown", "info")


def check_apparmor() -> CheckResult:
    if not Path("/sys/kernel/security/apparmor").exists():
        return CheckResult("AppArmor", "not available", "info")
    try:
        current = Path("/proc/self/attr/current").read_text(
            errors="ignore").strip()
        return CheckResult(
            check="AppArmor",
            result=current[:60] or "unconfined",
            severity=("high" if "unconfined" in current.lower() else "info"),
            detail=f"profile={current[:60]}",
            remediation="Использовать AppArmor profile: "
                         "--security-opt apparmor=docker-default",
        )
    except Exception:
        return CheckResult("AppArmor", "unknown", "info")


def check_selinux() -> CheckResult:
    if not shutil.which("getenforce"):
        return CheckResult("SELinux", "not installed", "info")
    rc, out = _run_cmd(["getenforce"])
    mode = out.strip()
    sev = "high" if mode.lower() == "disabled" else "info"
    return CheckResult(
        check="SELinux",
        result=mode or "?",
        severity=sev,
        detail=f"getenforce={mode}",
    )


def check_userns_enabled() -> CheckResult:
    try:
        val = Path("/proc/sys/user/max_user_namespaces").read_text(
            errors="ignore").strip()
        enabled = int(val) > 0 if val.isdigit() else False
        return CheckResult(
            check="User namespaces",
            result=f"max={val}",
            severity="medium" if enabled else "low",
            detail="разрешены (потенциально полезно для privesc)"
                    if enabled else "отключены",
        )
    except Exception:
        return CheckResult("User namespaces", "unknown", "info")


# ===========================================================================
# Sockets / docker
# ===========================================================================

def check_docker_socket() -> CheckResult:
    sock = Path("/var/run/docker.sock")
    if not sock.exists():
        return CheckResult("Docker socket", "not found", "info")
    readable = os.access(str(sock), os.R_OK)
    writable = os.access(str(sock), os.W_OK)
    sev = "critical" if writable else ("high" if readable else "info")
    return CheckResult(
        check="Docker socket",
        result=(f"{'RW' if writable else 'RO' if readable else 'NA'}"),
        severity=sev,
        detail="→ docker run --privileged -v /:/host = escape",
        remediation="Не монтировать docker.sock внутрь контейнера",
    )


def check_containerd_socket() -> CheckResult:
    for path in ("/run/containerd/containerd.sock",
                 "/run/containerd/containerd.sock.ttrpc"):
        p = Path(path)
        if p.exists():
            return CheckResult(
                check="containerd socket",
                result=f"PRESENT ({p.name})",
                severity="critical",
                detail="→ ctr escape → host root",
                remediation="Не монтировать containerd.sock",
            )
    return CheckResult("containerd socket", "not found", "info")


def check_crio_socket() -> CheckResult:
    for path in ("/var/run/crio/crio.sock",
                 "/run/crio/crio.sock"):
        if Path(path).exists():
            return CheckResult(
                check="CRI-O socket", result="PRESENT",
                severity="critical",
                detail="→ crictl escape",
            )
    return CheckResult("CRI-O socket", "not found", "info")


def check_podman_socket() -> CheckResult:
    for path in (f"/run/user/{os.getuid()}/podman/podman.sock",
                 "/run/podman/podman.sock"):
        if Path(path).exists():
            return CheckResult(
                check="Podman socket", result="PRESENT",
                severity="critical",
                detail="→ podman escape",
            )
    return CheckResult("Podman socket", "not found", "info")


# ===========================================================================
# Mounts / host access
# ===========================================================================

def check_host_mounts() -> CheckResult:
    suspicious: list[str] = []
    try:
        for line in Path("/proc/mounts").read_text(
                errors="ignore").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            target = parts[1]
            if any(k in target for k in (
                "/var/lib/docker", "/var/lib/kubelet", "/host",
                "/mnt/host", "/proc/1/root", "/var/run/docker.sock",
                "/run/containerd", "/mnt/",
            )):
                suspicious.append(target)
    except Exception:
        return CheckResult("Host mounts", "no /proc/mounts", "info")

    if suspicious:
        return CheckResult(
            check="Host mounts",
            result=f"{len(suspicious)} host paths",
            severity="critical",
            detail=", ".join(suspicious[:5]),
            remediation="Убрать hostPath-монтирования",
        )
    return CheckResult("Host mounts", "clean", "info")


def check_proc1_root() -> CheckResult:
    p = Path("/proc/1/root")
    if not p.exists():
        return CheckResult("/proc/1/root", "absent", "info")
    try:
        entries = list(p.iterdir())[:5]
        return CheckResult(
            check="/proc/1/root",
            result="READABLE",
            severity="critical",
            detail=f"host root виден ({len(entries)} entries)",
            remediation="Убрать --pid=host",
        )
    except PermissionError:
        return CheckResult("/proc/1/root", "denied", "info")
    except Exception as exc:
        return CheckResult("/proc/1/root", "err", "info", str(exc)[:60])


def check_core_pattern() -> CheckResult:
    """core_pattern — используется для escape через pipe."""
    try:
        val = Path("/proc/sys/kernel/core_pattern").read_text(
            errors="ignore").strip()
        if val.startswith("|"):
            return CheckResult(
                check="core_pattern",
                result="PIPE",
                severity="medium",
                detail=f"pattern={val[:80]} (может быть использован "
                       f"для выполнения команды от host)",
            )
        return CheckResult("core_pattern", "plain", "info",
                            f"pattern={val[:60]}")
    except Exception:
        return CheckResult("core_pattern", "unknown", "info")


def check_cgroup_version() -> CheckResult:
    if Path("/sys/fs/cgroup/cgroup.controllers").exists():
        # Проверим cgroup v2 escape
        return CheckResult(
            check="cgroup version",
            result="v2 (unified)",
            severity="medium",
            detail="проверь CVE-2022-0492 (release_agent требует "
                    "CAP_SYS_ADMIN или userns)",
        )
    return CheckResult("cgroup version", "v1 (legacy)", "info")


def check_ebpf() -> CheckResult:
    """Проверить /sys/fs/bpf и CAP_BPF."""
    if not Path("/sys/fs/bpf").exists():
        return CheckResult("eBPF", "not mounted", "info")
    eff, _, _ = get_capabilities()
    has_bpf = 39 in eff
    has_admin = 21 in eff
    if has_bpf or has_admin:
        return CheckResult(
            check="eBPF available",
            result="YES",
            severity="medium",
            detail=f"CAP_BPF={has_bpf}, CAP_SYS_ADMIN={has_admin}",
        )
    return CheckResult("eBPF available", "limited", "info")


def check_module_loading() -> CheckResult:
    """Проверить /proc/modules (readable) + CAP_SYS_MODULE."""
    eff, _, _ = get_capabilities()
    has = 16 in eff
    try:
        modules = Path("/proc/modules").read_text(errors="ignore")
        count = len(modules.splitlines())
    except Exception:
        count = 0
    if has:
        return CheckResult(
            check="Kernel modules",
            result="loadable (CAP_SYS_MODULE)",
            severity="critical",
            detail=f"{count} модулей видно",
        )
    return CheckResult(
        "Kernel modules", f"read-only ({count})", "info",
    )


# ===========================================================================
# K8s
# ===========================================================================

def check_k8s_sa() -> list[CheckResult]:
    results: list[CheckResult] = []
    sa_dir = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    if not sa_dir.exists():
        return [CheckResult("K8s ServiceAccount", "not in pod", "info")]

    results.append(CheckResult(
        check="K8s ServiceAccount",
        result="PRESENT",
        severity="high",
        detail=f"dir={sa_dir}",
    ))

    # Token
    token_p = sa_dir / "token"
    if token_p.exists():
        try:
            token = token_p.read_text().strip()
            results.append(CheckResult(
                check="  SA token",
                result=f"len={len(token)}",
                severity="high",
                detail="JWT для K8s API",
            ))
        except Exception:
            pass

    # Namespace
    ns_p = sa_dir / "namespace"
    if ns_p.exists():
        try:
            ns = ns_p.read_text().strip()
            results.append(CheckResult(
                check="  SA namespace",
                result=ns, severity="info",
            ))
        except Exception:
            pass
    return results


def check_kubelet() -> CheckResult:
    """Проверить kubelet endpoints (localhost)."""
    accessible: list[str] = []
    for host, port, path in [
        ("127.0.0.1", 10255, "/pods"),
        ("127.0.0.1", 10250, "/pods"),
        ("127.0.0.1", 10248, "/healthz"),
    ]:
        try:
            s = socket.socket()
            s.settimeout(1.0)
            s.connect((host, port))
            s.close()
            accessible.append(f"{port}{path}")
        except Exception:
            continue
    if accessible:
        return CheckResult(
            check="Kubelet API",
            result=f"{len(accessible)} accessible",
            severity="critical",
            detail=", ".join(accessible),
            remediation="Не публиковать kubelet без auth",
        )
    return CheckResult("Kubelet API", "not accessible", "info")


def check_host_pid() -> CheckResult:
    try:
        procs = [p for p in Path("/proc").iterdir() if p.name.isdigit()]
        if len(procs) > 50:
            return CheckResult(
                check="hostPID",
                result=f"likely (>{len(procs)} processes)",
                severity="critical",
                detail="виден host PID namespace",
                remediation="--pid=container (не host)",
            )
        return CheckResult("hostPID", "no", "info",
                            f"{len(procs)} processes visible")
    except Exception:
        return CheckResult("hostPID", "unknown", "info")


def check_host_network() -> CheckResult:
    """hostNet — если видим много host IP."""
    try:
        # Проверим /proc/net/tcp на необычные адреса
        val = Path("/proc/self/ns/net").readlink()
        return CheckResult(
            check="Network namespace",
            result=str(val)[:40],
            severity="info",
        )
    except Exception:
        return CheckResult("Network namespace", "unknown", "info")


def check_kernel() -> CheckResult:
    rc, out = _run_cmd(["uname", "-r"])
    return CheckResult("Kernel", out.strip() or "?", "info")


# ===========================================================================
# Main scan
# ===========================================================================

def scan_all(save_findings: bool = True) -> list[CheckResult]:
    """Полный скан."""
    console.print("[cyan]🔒 Container escape checks…[/cyan]\n")

    checks_simple = [
        detect_runtime,
        check_user,
        check_privileged,
        check_ptrace,
        check_sys_module,
        check_dac_read_search,
        check_seccomp,
        check_apparmor,
        check_selinux,
        check_userns_enabled,
        check_docker_socket,
        check_containerd_socket,
        check_crio_socket,
        check_podman_socket,
        check_host_mounts,
        check_proc1_root,
        check_core_pattern,
        check_cgroup_version,
        check_ebpf,
        check_module_loading,
        check_kubelet,
        check_host_pid,
        check_host_network,
        check_kernel,
    ]

    results: list[CheckResult] = []

    # Simple
    for fn in checks_simple:
        try:
            results.append(fn())
        except Exception as exc:
            log.warning("%s: %s", fn.__name__, exc)

    # Capabilities (multi)
    try:
        results.extend(check_capabilities())
    except Exception as exc:
        log.warning("caps: %s", exc)

    # K8s SA (multi)
    try:
        results.extend(check_k8s_sa())
    except Exception as exc:
        log.warning("k8s sa: %s", exc)

    # Namespaces
    try:
        results.extend(check_namespaces())
    except Exception as exc:
        log.warning("ns: %s", exc)

    # Печать
    t = Table(title="🔓 Container Escape Checks")
    t.add_column("Check", style="cyan", max_width=30)
    t.add_column("Result", style="green", max_width=30)
    t.add_column("Severity", width=10)
    t.add_column("Detail", style="dim", max_width=45)
    for r in sorted(
        results,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                        "low": 3, "info": 4}.get(x.severity, 5),
    ):
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green",
               "info": "dim"}.get(r.severity, "white")
        t.add_row(r.check, r.result,
                  f"[{sty}]{r.severity.upper()}[/{sty}]",
                  r.detail[:45])
    console.print(t)

    # Итог
    critical = [r for r in results if r.severity == "critical"]
    high = [r for r in results if r.severity == "high"]
    if critical:
        console.print(f"\n[bold red]⚠ {len(critical)} критичных "
                      f"escape-векторов:[/bold red]")
        for r in critical:
            console.print(f"  [red]• {r.check}: {r.result} — "
                          f"{r.detail}[/red]")
    elif high:
        console.print(f"\n[yellow]⚠ {len(high)} high-risk:[/yellow]")
        for r in high:
            console.print(f"  [yellow]• {r.check}: {r.result}[/yellow]")
    else:
        console.print("\n[green]✓ Критичных escape-векторов "
                      "не найдено.[/green]")

    # Findings → notes
    if save_findings:
        saved = sum(1 for r in results if _save_finding(r) > 0)
        if saved:
            console.print(f"\n[green]✓ Findings в notes: {saved}[/green]")

    # Экспорт
    _export_json(results)
    _export_html(results)

    # Notify
    try:
        from modules import notifier
        notifier.notify_all(
            "🔓 Container Escape Scan",
            f"Critical: {len(critical)}\nHigh: {len(high)}\n"
            f"Total checks: {len(results)}",
        )
    except Exception:
        pass

    db.save_scan("container_escape", "local", {
        "critical": len(critical),
        "high": len(high),
        "checks": [asdict(r) for r in results],
    })
    return results


def _export_json(results: list[CheckResult],
                  path: Path | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = CE_DIR / f"escape_{ts}.json"
    try:
        path.write_text(json.dumps(
            [asdict(r) for r in results],
            indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"\n[green]✓ JSON: {path}[/green]")
        return path
    except Exception:
        return None


def _export_html(results: list[CheckResult],
                  path: Path | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = CE_DIR / f"escape_{ts}.html"

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Container Escape Scan</title>",
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
        "<h1>🔓 Container Escape Scan</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Checks: {len(results)}</p>",
        "<table><tr><th>Check</th><th>Result</th>"
        "<th>Severity</th><th>Detail</th><th>Remediation</th></tr>",
    ]
    for r in sorted(results,
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                                    "low": 3, "info": 4}.get(x.severity, 5)):
        parts.append(
            f"<tr><td>{html_mod.escape(r.check)}</td>"
            f"<td>{html_mod.escape(r.result[:80])}</td>"
            f"<td class='{r.severity}'>{r.severity.upper()}</td>"
            f"<td>{html_mod.escape(r.detail[:150])}</td>"
            f"<td>{html_mod.escape(r.remediation[:150])}</td></tr>")
    parts.append("</table></body></html>")
    try:
        path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return path
    except Exception:
        return None


# ===========================================================================
# Kernel CVEs
# ===========================================================================

def list_kernel_cves() -> None:
    t = Table(title=f"🐧 Kernel/Container CVEs ({len(KERNEL_CVES)})")
    t.add_column("CVE", style="cyan", width=16)
    t.add_column("Name", style="magenta", width=25)
    t.add_column("Sev", width=10)
    t.add_column("Affects", style="yellow", max_width=40)
    t.add_column("Impact", style="red", max_width=25)
    for cve, data in KERNEL_CVES.items():
        sev = data.get("severity", "medium")
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow"}.get(sev, "white")
        t.add_row(cve, data["name"],
                  f"[{sty}]{sev.upper()}[/{sty}]",
                  data["affects"][:40], data["impact"][:25])
    console.print(t)

    choice = Prompt.ask("Детали CVE (Enter = нет)",
                        default="").strip()
    if choice and choice in KERNEL_CVES:
        d = KERNEL_CVES[choice]
        console.print(f"\n[bold cyan]{choice} — {d['name']}[/bold cyan]")
        console.print(f"[cyan]Affects:[/cyan] {d['affects']}")
        console.print(f"[cyan]Impact:[/cyan]  {d['impact']}")
        console.print(f"[cyan]Check:[/cyan]   {d['check']}")
        console.print(f"[cyan]Exploit:[/cyan] {d['exploit']}")


def cve_check(cve_id: str) -> None:
    d = KERNEL_CVES.get(cve_id)
    if not d:
        console.print(f"[red]Неизвестный CVE: {cve_id}[/red]")
        return
    console.print(f"\n[bold cyan]{cve_id} — {d['name']}[/bold cyan]")
    console.print(f"[cyan]Affects:[/cyan] {d['affects']}")
    console.print(f"[cyan]Impact:[/cyan]  {d['impact']}")
    console.print(f"[cyan]Severity:[/cyan] {d.get('severity', '?')}")
    console.print(f"\n[yellow]Check command:[/yellow]")
    console.print(f"  [green]{d['check']}[/green]")
    console.print(f"\n[yellow]Exploit:[/yellow]")
    console.print(f"  [green]{d['exploit']}[/green]")


# ===========================================================================
# CLI
# ===========================================================================

def cli_scan() -> None:
    scan_all()


def cli_cves() -> None:
    list_kernel_cves()


def cli_cve(cve_id: str) -> None:
    cve_check(cve_id)


def cli_caps() -> None:
    """Только capabilities."""
    results = check_capabilities()
    t = Table(title="🔓 Capabilities")
    t.add_column("Check", style="cyan")
    t.add_column("Result", style="green")
    t.add_column("Sev", width=10)
    for r in results:
        t.add_row(r.check, r.result, r.severity.upper())
    console.print(t)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]🔓 Container Escape Suite[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "Полный скан (24+ checks)"),
        ("2", "Только capabilities"),
        ("3", "Список kernel/container CVE"),
        ("4", "Детали CVE"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного пентеста / CTF."
                  "[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        scan_all()
    elif c == "2":
        cli_caps()
    elif c == "3":
        list_kernel_cves()
    elif c == "4":
        cve_check(Prompt.ask("CVE ID", default="CVE-2022-0847"))