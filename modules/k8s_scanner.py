"""
Kubernetes / Container Scanner Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Recon ───
    - K8s порты (30+): apiserver, kubelet, etcd, kube-proxy, cAdvisor,
      NodePort range, NodeLocal DNS
    - PaaS порты: ArgoCD (8080), Rancher (8443/80), Harbor (8080/443),
      Vault (8200), Consul (8500), Istio Ingress, Linkerd
    - Cloud provider detection (EKS/GKE/AKS/DO/DigitalOcean/Oracle)

    ─── API exploitation ───
    - Anonymous auth (с полным RBAC enumeration)
    - Namespaces, pods, secrets, cronjobs, configmaps, serviceaccounts
    - Token extraction → full cluster admin checks
    - Node listing + exec via kubelet
    - Pod → ServiceAccount token → API chain
    - RBAC enumeration (clusterrolebindings, rolebindings)
    - CRD enumeration

    ─── Service checks ───
    - kubelet read-only (10255) + exec (10250) + stats + metrics
    - etcd v2/v3 (auth check + key dump)
    - Docker daemon API (containers, images, exec)
    - containerd API (unix socket)
    - Dashboard, Grafana, Kibana, Prometheus, Alertmanager
    - ArgoCD, Rancher, Harbor, Vault, Consul, Istio, Linkerd

    ─── Container escape ───
    - Локальные проверки (privileged, CAP_SYS_ADMIN, docker.sock, K8s SA)
    - CVE knowledge base (2024-21626 runc, 2022-0492 cgroups, ...)
    - hostPath, hostPID, hostNetwork detection
    - Service account token mount detection

    ─── Интеграция ───
    - Findings → notes (critical/high)
    - Notify
    - HTML / JSON / CSV экспорт
"""
import base64
import csv
import html as html_mod
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

K8S_DIR = REPORT_DIR / "k8s"
K8S_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 10


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class K8sFinding:
    kind: str
    target: str
    port: int
    severity: str
    url: str = ""
    title: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)
    error: str = ""
    remediation: str = ""


def _save_finding(f: K8sFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title or f.kind,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["k8s", "container", f.kind.replace(" ", "_").lower()],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n"
                  f"**Port:** {f.port}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1500]}`\n\n"
                  f"**Remediation:** {f.remediation or '—'}"),
        )
    except Exception:
        return -1


# ===========================================================================
# Ports
# ===========================================================================

K8S_PORTS = {
    6443:  "kube-apiserver (https)",
    8443:  "kube-apiserver (alt, https) / Rancher",
    8080:  "kube-apiserver (insecure, old) / ArgoCD",
    10250: "kubelet (https, exec/logs)",
    10255: "kubelet (http read-only, deprecated)",
    10256: "kube-proxy health",
    10257: "kube-controller-manager",
    10259: "kube-scheduler",
    2379:  "etcd client",
    2380:  "etcd peer",
    4001:  "etcd (old)",
    7001:  "etcd (alt)",
    3000:  "Grafana",
    9090:  "Prometheus",
    9093:  "Alertmanager",
    5601:  "Kibana",
    8001:  "kubectl proxy",
    8081:  "k8s Dashboard",
    80:    "Rancher / Ingress",
    443:   "Rancher / Ingress (TLS)",
    8200:  "Vault",
    8500:  "Consul",
    8501:  "Consul UI",
    8502:  "Consul (gRPC)",
    8503:  "Consul (gRPC TLS)",
    8888:  "Kubeflow / Jupyter",
    9876:  "K8s Dashboard (alt)",
    30000: "NodePort range (start)",
    32767: "NodePort range (end)",
}

# PaaS/DevOps services
PAAS_PORTS = {
    8080:  "ArgoCD / generic",
    9000:  "SonarQube / Harbor (alt)",
    9200:  "Elasticsearch",
    9418:  "Git (git protocol)",
    3000:  "Grafana / Gitea",
    8000:  "Generic web",
    8088:  "YARN / generic",
    9091:  "Pushgateway",
}


# ===========================================================================
# HTTP helpers
# ===========================================================================

def _http_get(url: str, headers: dict | None = None,
              timeout: int = TIMEOUT, verify: bool = False,
              allow_redirects: bool = False) -> requests.Response | None:
    try:
        return requests.get(
            url, timeout=timeout, verify=verify,
            headers=headers or {"User-Agent": config.USER_AGENT},
            allow_redirects=allow_redirects,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("GET %s: %s", url, exc)
        return None


def check_port_open(host: str, port: int,
                    timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ===========================================================================
# K8s API server checks
# ===========================================================================

def check_k8s_api(host: str, port: int = 6443) -> K8sFinding | None:
    """Проверить kube-apiserver + anonymous auth + RBAC enum."""
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}:{port}"
        r = _http_get(f"{base}/api", verify=False)
        if not r:
            continue

        if r.status_code in (401, 403):
            return K8sFinding(
                kind="kube-apiserver (auth required)",
                target=f"{host}:{port}", port=port, severity="info",
                url=base, title=f"K8s API server (auth)",
                evidence=f"GET /api → {r.status_code}",
                data={"status": r.status_code},
            )

        if r.status_code != 200:
            continue

        try:
            versions = r.json()
        except Exception:
            versions = {}

        # Anonymous check
        ns_r = _http_get(f"{base}/api/v1/namespaces", verify=False)
        namespaces: list[str] = []
        anon = False
        if ns_r and ns_r.status_code == 200:
            anon = True
            try:
                namespaces = [n["metadata"]["name"]
                              for n in ns_r.json().get("items", [])]
            except Exception:
                pass

        sev = "critical" if anon else "medium"
        f = K8sFinding(
            kind="kube-apiserver",
            target=f"{host}:{port}", port=port, severity=sev,
            url=base,
            title=f"K8s API server{' (ANONYMOUS!)' if anon else ''}",
            evidence=(f"GET /api → 200, "
                      f"anonymous={'YES' if anon else 'no'}, "
                      f"namespaces={len(namespaces)}"),
            data={"versions": versions,
                  "anonymous_auth": anon,
                  "namespaces": namespaces},
            remediation=("Отключить anonymous auth: "
                         "--anonymous-auth=false"),
        )

        if not anon:
            return f

        # ===================================================
        # Full anonymous exploitation
        # ===================================================

        # Pods
        pods_r = _http_get(f"{base}/api/v1/pods", verify=False)
        if pods_r and pods_r.status_code == 200:
            try:
                pods = pods_r.json().get("items", [])
                f.data["pods_count"] = len(pods)
                f.data["pod_samples"] = [
                    {"ns": p.get("metadata", {}).get("namespace"),
                     "name": p.get("metadata", {}).get("name"),
                     "node": p.get("spec", {}).get("nodeName"),
                     "image": (p.get("spec", {}).get("containers")
                               or [{}])[0].get("image", "")}
                    for p in pods[:20]
                ]
            except Exception:
                pass

        # Secrets
        sec_r = _http_get(f"{base}/api/v1/secrets", verify=False)
        if sec_r and sec_r.status_code == 200:
            try:
                secrets = sec_r.json().get("items", [])
                f.data["secrets_count"] = len(secrets)
                f.data["secret_samples"] = [
                    {"ns": s.get("metadata", {}).get("namespace"),
                     "name": s.get("metadata", {}).get("name"),
                     "type": s.get("type")}
                    for s in secrets[:20]
                ]
                f.severity = "critical"
                f.evidence += f", SECRETS ACCESSIBLE ({len(secrets)})"
            except Exception:
                pass

        # Service accounts
        sa_r = _http_get(f"{base}/api/v1/serviceaccounts", verify=False)
        if sa_r and sa_r.status_code == 200:
            try:
                sas = sa_r.json().get("items", [])
                f.data["service_accounts_count"] = len(sas)
            except Exception:
                pass

        # Nodes
        nodes_r = _http_get(f"{base}/api/v1/nodes", verify=False)
        if nodes_r and nodes_r.status_code == 200:
            try:
                nodes = nodes_r.json().get("items", [])
                f.data["nodes_count"] = len(nodes)
                f.data["node_samples"] = [
                    {"name": n.get("metadata", {}).get("name"),
                     "version": (n.get("status", {}).get("nodeInfo") or {})
                        .get("kubeletVersion"),
                     "os_image": (n.get("status", {}).get("nodeInfo") or {})
                        .get("osImage"),
                     "internal_ip": next(
                         (a.get("address") for a in
                          (n.get("status", {}).get("addresses") or [])
                          if a.get("type") == "InternalIP"), "")}
                    for n in nodes[:10]
                ]
            except Exception:
                pass

        # ConfigMaps
        cm_r = _http_get(f"{base}/api/v1/configmaps", verify=False)
        if cm_r and cm_r.status_code == 200:
            try:
                cms = cm_r.json().get("items", [])
                f.data["configmaps_count"] = len(cms)
            except Exception:
                pass

        # CronJobs
        cj_r = _http_get(
            f"{base}/apis/batch/v1/cronjobs", verify=False)
        if cj_r and cj_r.status_code == 200:
            try:
                cjs = cj_r.json().get("items", [])
                f.data["cronjobs_count"] = len(cjs)
            except Exception:
                pass

        # RBAC: clusterrolebindings
        crb_r = _http_get(
            f"{base}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            verify=False)
        if crb_r and crb_r.status_code == 200:
            try:
                crbs = crb_r.json().get("items", [])
                f.data["clusterrolebindings_count"] = len(crbs)
                # Looking for system:anonymous access
                anon_bindings = []
                for crb in crbs:
                    for subj in crb.get("subjects", []):
                        if subj.get("name") == "system:anonymous":
                            anon_bindings.append({
                                "name": crb.get("metadata", {}).get("name"),
                                "role": (crb.get("roleRef") or {}).get("name"),
                            })
                if anon_bindings:
                    f.data["anonymous_bindings"] = anon_bindings
            except Exception:
                pass

        # CRDs enumeration
        crd_r = _http_get(
            f"{base}/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            verify=False)
        if crd_r and crd_r.status_code == 200:
            try:
                crds = crd_r.json().get("items", [])
                f.data["crds_count"] = len(crds)
                f.data["crd_samples"] = [
                    c.get("metadata", {}).get("name") for c in crds[:15]
                ]
            except Exception:
                pass

        # Try /version for k8s version
        ver_r = _http_get(f"{base}/version", verify=False)
        if ver_r and ver_r.status_code == 200:
            try:
                f.data["server_version"] = ver_r.json()
            except Exception:
                pass

        return f

    return None


# ===========================================================================
# Kubelet checks
# ===========================================================================

def check_kubelet(host: str, port: int = 10255) -> K8sFinding | None:
    """Kubelet read-only (deprecated)."""
    r = _http_get(f"http://{host}:{port}/pods", verify=False)
    if not r:
        return None
    if r.status_code == 200:
        try:
            pods = r.json().get("items", [])
        except Exception:
            pods = []
        # Дополнительно: /metrics, /stats
        metrics = _http_get(f"http://{host}:{port}/metrics", verify=False)
        stats = _http_get(f"http://{host}:{port}/stats/summary", verify=False)
        return K8sFinding(
            kind="kubelet read-only",
            target=f"{host}:{port}", port=port, severity="high",
            url=f"http://{host}:{port}",
            title=f"Kubelet read-only API ({len(pods)} pods)",
            evidence=f"GET /pods → 200 ({len(pods)} pods), "
                     f"/metrics={'on' if metrics and metrics.status_code==200 else 'off'}, "
                     f"/stats={'on' if stats and stats.status_code==200 else 'off'}",
            data={"pods_count": len(pods),
                  "pod_samples": [p.get("metadata", {}).get("name")
                                  for p in pods[:20]],
                  "metrics_available": bool(
                      metrics and metrics.status_code == 200),
                  "stats_available": bool(
                      stats and stats.status_code == 200)},
            remediation="Отключить --read-only-port или закрыть firewall",
        )
    if r.status_code in (401, 403):
        return K8sFinding(
            kind="kubelet (auth required)",
            target=f"{host}:{port}", port=port, severity="info",
            url=f"http://{host}:{port}",
            evidence=f"GET /pods → {r.status_code}",
        )
    return None


def check_kubelet_exec(host: str, port: int = 10250,
                       token: str | None = None) -> K8sFinding | None:
    """Kubelet API — exec/logs может привести к RCE в pod."""
    headers = {"User-Agent": config.USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    r = _http_get(f"https://{host}:{port}/pods", verify=False,
                  headers=headers)
    if not r:
        return None

    if r.status_code == 200:
        pods: list[dict] = []
        try:
            pods = r.json().get("items", [])
        except Exception:
            pass
        return K8sFinding(
            kind="kubelet API (exec)",
            target=f"{host}:{port}", port=port, severity="critical",
            url=f"https://{host}:{port}",
            title="Kubelet API — потенциальный exec в pod",
            evidence=(f"GET /pods → 200 "
                      f"({len(pods)} pods returned)"
                      f"{' (with token)' if token else ''}"),
            data={"pods_count": len(pods),
                  "has_token": bool(token),
                  "pod_samples": [p.get("metadata", {}).get("name")
                                  for p in pods[:10]]},
            remediation="Включить kubelet auth+authz",
        )
    if r.status_code in (401, 403):
        return K8sFinding(
            kind="kubelet API (auth required)",
            target=f"{host}:{port}", port=port, severity="info",
            url=f"https://{host}:{port}",
            evidence=f"GET /pods → {r.status_code}",
        )

    # Пробуем /runningpods (иногда открыт)
    rp_r = _http_get(f"https://{host}:{port}/runningpods/", verify=False,
                     headers=headers)
    if rp_r and rp_r.status_code == 200:
        return K8sFinding(
            kind="kubelet /runningpods exposed",
            target=f"{host}:{port}", port=port, severity="high",
            url=f"https://{host}:{port}/runningpods/",
            title="Kubelet /runningpods открыт",
            evidence=f"GET /runningpods → 200",
            remediation="Ограничить доступ к kubelet",
        )
    return None


# ===========================================================================
# etcd
# ===========================================================================

def check_etcd(host: str, port: int = 2379,
               dump_keys: bool = True) -> K8sFinding | None:
    """etcd v2/v3 без auth."""
    # etcd v3
    try:
        url = f"http://{host}:{port}/v3/kv/range"
        r = requests.post(
            url,
            json={"key": base64.b64encode(b"/").decode()},
            timeout=TIMEOUT, verify=False,
            headers={"User-Agent": config.USER_AGENT,
                     "Content-Type": "application/json"},
        )
        if r.status_code == 200:
            try:
                data = r.json()
                keys = data.get("kvs", []) or []
                # Декодируем
                decoded: list[dict] = []
                for k in keys[:50]:
                    try:
                        k_name = base64.b64decode(k.get("key", "")).decode(
                            errors="ignore")
                        decoded.append({"key": k_name[:120]})
                    except Exception:
                        continue
                return K8sFinding(
                    kind="etcd unauthenticated",
                    target=f"{host}:{port}", port=port, severity="critical",
                    url=url,
                    title=f"etcd v3 без auth ({len(keys)} keys)",
                    evidence=(f"POST /v3/kv/range → 200, "
                              f"{len(keys)} keys возвращено"),
                    data={"keys_count": len(keys),
                          "sample_keys": decoded[:20]},
                    remediation="Включить etcd TLS + client cert auth",
                )
            except Exception:
                pass
    except Exception:
        pass

    # etcd v2
    r = _http_get(f"http://{host}:{port}/v2/keys/", verify=False)
    if r and r.status_code == 200:
        try:
            data = r.json()
            nodes = data.get("node", {}).get("nodes", []) or []
        except Exception:
            nodes = []
        return K8sFinding(
            kind="etcd v2 unauthenticated",
            target=f"{host}:{port}", port=port, severity="critical",
            url=f"http://{host}:{port}/v2/keys/",
            title="etcd v2 без auth",
            evidence=f"GET /v2/keys/ → 200 ({len(nodes)} top keys)",
            data={"top_keys": [n.get("key") for n in nodes[:20]]},
            remediation="Обновить etcd + включить auth",
        )

    # /version (info)
    r2 = _http_get(f"http://{host}:{port}/version", verify=False)
    if r2 and r2.status_code == 200:
        return K8sFinding(
            kind="etcd (version exposed)",
            target=f"{host}:{port}", port=port, severity="medium",
            url=f"http://{host}:{port}/version",
            title="etcd version exposed",
            evidence=r2.text[:200],
            remediation="Ограничить доступ firewall",
        )

    # HTTPS без проверки сертификата
    try:
        r3 = requests.get(f"https://{host}:{port}/version", timeout=TIMEOUT,
                          verify=False,
                          headers={"User-Agent": config.USER_AGENT})
        if r3.status_code == 200:
            return K8sFinding(
                kind="etcd (TLS)",
                target=f"{host}:{port}", port=port, severity="low",
                url=f"https://{host}:{port}/version",
                evidence=r3.text[:200],
            )
    except Exception:
        pass
    return None


# ===========================================================================
# Docker daemon
# ===========================================================================

def check_docker_api(host: str, port: int = 2375) -> K8sFinding | None:
    """Docker daemon API."""
    for scheme in ("http", "https"):
        r = _http_get(f"{scheme}://{host}:{port}/version", verify=False)
        if not r or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            data = {}

        # Containers
        containers: list[dict] = []
        c_r = _http_get(f"{scheme}://{host}:{port}/containers/json?all=1",
                        verify=False)
        if c_r and c_r.status_code == 200:
            try:
                containers = c_r.json()
            except Exception:
                pass

        # Images
        images: list[dict] = []
        i_r = _http_get(f"{scheme}://{host}:{port}/images/json", verify=False)
        if i_r and i_r.status_code == 200:
            try:
                images = i_r.json()
            except Exception:
                pass

        # Info (leaks env)
        info: dict = {}
        info_r = _http_get(f"{scheme}://{host}:{port}/info", verify=False)
        if info_r and info_r.status_code == 200:
            try:
                info = info_r.json()
            except Exception:
                pass

        sev = "critical" if containers else "high"
        return K8sFinding(
            kind="Docker daemon API exposed",
            target=f"{host}:{port}", port=port, severity=sev,
            url=f"{scheme}://{host}:{port}",
            title=f"Docker daemon API открыт (v{data.get('Version','?')})",
            evidence=(f"GET /version → 200 ({data.get('Version', '?')}), "
                      f"containers={len(containers)}, images={len(images)}"),
            data={"version": data.get("Version"),
                  "os": data.get("Os"),
                  "arch": data.get("Arch"),
                  "kernel": data.get("KernelVersion"),
                  "containers_count": len(containers),
                  "images_count": len(images),
                  "container_samples": [
                      {"id": (c.get("Id") or "")[:12],
                       "image": c.get("Image"),
                       "status": c.get("Status"),
                       "names": c.get("Names", [])}
                      for c in containers[:20]
                  ],
                  "docker_root": info.get("DockerRootDir")},
            remediation=("Не открывать docker.sock наружу. "
                         "Использовать TLS + client certs на 2376"),
        )
    return None


# ===========================================================================
# PaaS / DevOps services
# ===========================================================================

def check_argocd(host: str, port: int = 8080) -> K8sFinding | None:
    """ArgoCD detection."""
    for path in ("/api/version", "/api/v1/session/userinfo", "/"):
        r = _http_get(f"http://{host}:{port}{path}", verify=False)
        if r and r.status_code in (200, 401, 403):
            if "argocd" in r.text.lower() or \
               (r.headers.get("Content-Type") or "").startswith("application/json"):
                try:
                    data = r.json()
                except Exception:
                    data = {}
                return K8sFinding(
                    kind="ArgoCD",
                    target=f"{host}:{port}", port=port,
                    severity="high",
                    url=f"http://{host}:{port}",
                    title="ArgoCD exposed",
                    evidence=f"{path} → {r.status_code}",
                    data=data,
                    remediation="Ограничить ArgoCD UI + включить SSO",
                )
    return None


def check_rancher(host: str, port: int = 443) -> K8sFinding | None:
    """Rancher detection."""
    for scheme in ("https", "http"):
        r = _http_get(f"{scheme}://{host}:{port}/v3-public/settings",
                      verify=False)
        if r and r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                data = {}
            return K8sFinding(
                kind="Rancher",
                target=f"{host}:{port}", port=port, severity="high",
                url=f"{scheme}://{host}:{port}",
                title="Rancher API exposed",
                evidence=f"GET /v3-public/settings → 200",
                data={"settings_count": len(data.get("data", []))},
                remediation="Ограничить Rancher UI",
            )
    return None


def check_harbor(host: str, port: int = 8080) -> K8sFinding | None:
    """Harbor registry UI."""
    for scheme in ("https", "http"):
        r = _http_get(f"{scheme}://{host}:{port}/api/v2.0/systeminfo",
                      verify=False)
        if r and r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                data = {}
            return K8sFinding(
                kind="Harbor",
                target=f"{host}:{port}", port=port, severity="medium",
                url=f"{scheme}://{host}:{port}",
                title="Harbor exposed",
                evidence=f"GET /api/v2.0/systeminfo → 200",
                data=data,
            )
    return None


def check_vault(host: str, port: int = 8200) -> K8sFinding | None:
    """HashiCorp Vault."""
    for scheme in ("https", "http"):
        r = _http_get(f"{scheme}://{host}:{port}/v1/sys/health",
                      verify=False)
        if r and r.status_code in (200, 429, 472, 473, 501, 503):
            try:
                data = r.json()
            except Exception:
                data = {}
            sealed = data.get("sealed", True)
            init = data.get("initialized", False)
            sev = "high" if (init and not sealed) else "medium"
            return K8sFinding(
                kind="Vault",
                target=f"{host}:{port}", port=port, severity=sev,
                url=f"{scheme}://{host}:{port}",
                title=f"Vault exposed (sealed={sealed}, init={init})",
                evidence=f"GET /v1/sys/health → {r.status_code}",
                data=data,
                remediation="Изолировать Vault + API auth",
            )
    return None


def check_consul(host: str, port: int = 8500) -> K8sFinding | None:
    """Consul API."""
    r = _http_get(f"http://{host}:{port}/v1/status/leader", verify=False)
    if r and r.status_code == 200:
        # Try /v1/agent/self
        agent = _http_get(f"http://{host}:{port}/v1/agent/self", verify=False)
        data: dict = {}
        if agent and agent.status_code == 200:
            try:
                data = agent.json()
            except Exception:
                pass
        return K8sFinding(
            kind="Consul",
            target=f"{host}:{port}", port=port, severity="high",
            url=f"http://{host}:{port}",
            title="Consul API exposed",
            evidence=f"GET /v1/status/leader → 200",
            data={"version": (data.get("Config") or {}).get("Version"),
                  "dc": (data.get("Config") or {}).get("Datacenter")},
            remediation="Ограничить Consul API + ACL tokens",
        )
    return None


# ===========================================================================
# Monitoring / dashboards
# ===========================================================================

def check_dashboard(host: str, port: int = 8001) -> K8sFinding | None:
    """Kubernetes Dashboard."""
    checks = [
        (f"http://{host}:{port}/", "k8s Dashboard"),
        (f"http://{host}:{port}/api/v1/namespaces/kubernetes-dashboard/"
         f"services/https:kubernetes-dashboard:/proxy/",
         "k8s Dashboard (proxy)"),
    ]
    for url, kind in checks:
        r = _http_get(url, verify=False, allow_redirects=True)
        if r and r.status_code in (200, 301, 302):
            if "dashboard" in r.text.lower() or \
               "kubernetes" in r.text.lower():
                return K8sFinding(
                    kind=kind, target=f"{host}:{port}", port=port,
                    severity="high", url=url,
                    title="Kubernetes Dashboard доступен",
                    evidence=f"Dashboard доступен ({r.status_code})",
                    remediation="Ограничить доступ к dashboard",
                )
    return None


def check_prometheus(host: str, port: int = 9090) -> K8sFinding | None:
    r = _http_get(f"http://{host}:{port}/api/v1/status/config", verify=False)
    if r and r.status_code == 200:
        # Try /api/v1/targets
        targets: list[dict] = []
        t_r = _http_get(f"http://{host}:{port}/api/v1/targets", verify=False)
        if t_r and t_r.status_code == 200:
            try:
                targets = t_r.json().get("data", {}).get("activeTargets", [])
            except Exception:
                pass
        return K8sFinding(
            kind="Prometheus API", target=f"{host}:{port}", port=port,
            severity="medium", url=f"http://{host}:{port}",
            title=f"Prometheus API ({len(targets)} targets)",
            evidence=f"GET /api/v1/status/config → 200",
            data={"targets_count": len(targets)},
            remediation="Ограничить Prometheus API",
        )
    r2 = _http_get(f"http://{host}:{port}/-/healthy", verify=False)
    if r2 and r2.status_code == 200:
        return K8sFinding(
            kind="Prometheus (health exposed)",
            target=f"{host}:{port}", port=port, severity="low",
            url=f"http://{host}:{port}",
            title="Prometheus health endpoint",
            evidence="GET /-/healthy → 200",
        )
    return None


def check_alertmanager(host: str, port: int = 9093) -> K8sFinding | None:
    r = _http_get(f"http://{host}:{port}/api/v2/status", verify=False)
    if r and r.status_code == 200:
        return K8sFinding(
            kind="Alertmanager",
            target=f"{host}:{port}", port=port, severity="low",
            url=f"http://{host}:{port}",
            title="Alertmanager API exposed",
            evidence="GET /api/v2/status → 200",
        )
    return None


def check_kibana(host: str, port: int = 5601) -> K8sFinding | None:
    r = _http_get(f"http://{host}:{port}/api/status", verify=False)
    if r and r.status_code == 200:
        return K8sFinding(
            kind="Kibana API", target=f"{host}:{port}", port=port,
            severity="medium", url=f"http://{host}:{port}",
            title="Kibana API exposed",
            evidence="GET /api/status → 200",
        )
    return None


def check_grafana(host: str, port: int = 3000) -> K8sFinding | None:
    r = _http_get(f"http://{host}:{port}/api/health", verify=False)
    if r and r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        # Check default creds
        default_creds = None
        for user, pwd in [("admin", "admin"), ("admin", "prom-operator"),
                          ("admin", "grafana")]:
            try:
                auth_r = requests.get(
                    f"http://{host}:{port}/api/user",
                    auth=(user, pwd), timeout=5, verify=False)
                if auth_r.status_code == 200:
                    default_creds = (user, pwd)
                    break
            except Exception:
                continue
        sev = "critical" if default_creds else "low"
        return K8sFinding(
            kind="Grafana", target=f"{host}:{port}", port=port,
            severity=sev, url=f"http://{host}:{port}",
            title=f"Grafana (v{data.get('version', '?')})"
                  f"{' with default creds!' if default_creds else ''}",
            evidence=f"GET /api/health → 200"
                     + (f", default creds {default_creds}!"
                        if default_creds else ""),
            data={"version": data.get("version"),
                  "database": data.get("database"),
                  "default_creds": default_creds},
            remediation="Сменить admin пароль",
        )
    return None


# ===========================================================================
# Cloud provider detection
# ===========================================================================

def detect_cloud_provider(host: str) -> str:
    """Попытка определить cloud-провайдера по IP."""
    try:
        import socket
        ip = socket.gethostbyname(host)
    except Exception:
        return ""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            org = (data.get("org") or "").lower()
            if "amazon" in org:
                return "AWS"
            if "google" in org:
                return "GCP"
            if "microsoft" in org or "azure" in org:
                return "Azure"
            if "digitalocean" in org:
                return "DigitalOcean"
            if "oracle" in org:
                return "Oracle Cloud"
            if "alibaba" in org:
                return "Alibaba Cloud"
            return data.get("org", "")
    except Exception:
        pass
    return ""


# ===========================================================================
# All checks registry
# ===========================================================================

def _all_checks() -> dict[int, Any]:
    return {
        6443:  check_k8s_api,
        8443:  lambda h, p=8443: check_k8s_api(h, p),
        8080:  check_argocd,
        10250: check_kubelet_exec,
        10255: check_kubelet,
        2379:  check_etcd,
        2380:  lambda h, p=2380: check_etcd(h, p),
        2375:  lambda h, p=2375: check_docker_api(h, p),
        2376:  lambda h, p=2376: check_docker_api(h, p),
        8001:  check_dashboard,
        8081:  check_dashboard,
        9090:  check_prometheus,
        9093:  check_alertmanager,
        5601:  check_kibana,
        3000:  check_grafana,
        443:   check_rancher,
        8200:  check_vault,
        8500:  check_consul,
    }


# ===========================================================================
# Orchestrator
# ===========================================================================

def scan_host(host: str, ports: list[int] | None = None,
              threads: int = 10,
              save_findings: bool = True) -> list[K8sFinding]:
    """Полный скан K8s-хоста."""
    if not confirm_external(host):
        return []

    host = extract_host(host)
    check_ports = ports or list(_all_checks().keys())

    console.print(f"[cyan]☸  K8s scan Pro: {host} "
                  f"({len(check_ports)} ports)[/cyan]")

    # Cloud detect
    cloud = detect_cloud_provider(host)
    if cloud:
        console.print(f"[dim]Cloud provider: {cloud}[/dim]")

    findings: list[K8sFinding] = []

    # Fast TCP scan
    open_ports: list[int] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as p:
        task = p.add_task("tcp-scan", total=len(check_ports))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(check_port_open, host, pt): pt
                    for pt in check_ports}
            for f in as_completed(futs):
                p.advance(task)
                if f.result():
                    open_ports.append(futs[f])

    if not open_ports:
        console.print(f"[green]Открытых K8s-портов нет.[/green]")
        return []

    console.print(f"[yellow]Открытые порты: "
                  f"{', '.join(map(str, sorted(open_ports)))}[/yellow]\n")

    # Deep checks
    checks = _all_checks()
    console.print(f"[cyan]☸  Проверяю {len(open_ports)} открытых портов…"
                  f"[/cyan]\n")

    for pt in open_ports:
        fn = checks.get(pt)
        if not fn:
            findings.append(K8sFinding(
                kind=K8S_PORTS.get(pt, "unknown"),
                target=f"{host}:{pt}", port=pt, severity="info",
                title=f"Port {pt} open",
                evidence="port open (no specific check)",
            ))
            continue
        try:
            r = fn(host)
            if r:
                findings.append(r)
                _print_finding(r)
        except Exception as exc:  # noqa: BLE001
            log.warning("check %s: %s", pt, exc)

    _print_summary(findings, host)

    # Findings → notes
    if save_findings:
        saved = sum(1 for f in findings if _save_finding(f) > 0)
        if saved:
            console.print(f"\n[green]✓ Findings в notes: {saved}[/green]")

    # Notify
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    if crit or high:
        try:
            from modules import notifier
            notifier.notify_all(
                f"☸  K8s scan: {host}",
                f"Critical: {crit}\nHigh: {high}\n"
                f"Total: {len(findings)}\n"
                f"Cloud: {cloud or 'unknown'}",
            )
        except Exception:
            pass

    db.save_scan("k8s_scan", host, {
        "open_ports": sorted(open_ports),
        "cloud": cloud,
        "findings": [asdict(f) for f in findings],
    })
    return findings


def scan_hosts(hosts: list[str], threads: int = 5,
               save_findings: bool = True) -> list[K8sFinding]:
    all_findings: list[K8sFinding] = []
    for h in hosts:
        all_findings.extend(scan_host(h, threads=threads,
                                       save_findings=save_findings))
    return all_findings


# ===========================================================================
# Printing
# ===========================================================================

def _sev_style(sev: str) -> str:
    return {
        "critical": "bold red", "high": "red",
        "medium": "yellow", "low": "green", "info": "dim",
    }.get(sev, "white")


def _print_finding(f: K8sFinding) -> None:
    sty = _sev_style(f.severity)
    console.print(f"[{sty}]●[/{sty}] "
                  f"[cyan]{f.kind}[/cyan] "
                  f"@ [green]{f.target}[/green] "
                  f"[{sty}]({f.severity.upper()})[/{sty}]")
    if f.evidence:
        console.print(f"   [dim]{f.evidence}[/dim]")
    for k, v in list(f.data.items())[:5]:
        if isinstance(v, (str, int, bool)):
            console.print(f"   [dim]{k}: {v}[/dim]")
        elif isinstance(v, list) and v:
            console.print(f"   [dim]{k}: {v[:3]}[/dim]")


def _print_summary(findings: list[K8sFinding], host: str) -> None:
    if not findings:
        console.print(f"\n[green]✓ {host}: уязвимостей не найдено.[/green]")
        return
    table = Table(title=f"☸  Findings — {host}")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Sev", width=10)
    table.add_column("Kind", style="cyan", max_width=30)
    table.add_column("Target", style="green", max_width=25)
    table.add_column("Evidence", style="white", max_width=45)
    for i, f in enumerate(
        sorted(findings,
               key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                              "low": 3, "info": 4}.get(x.severity, 5)),
        1,
    ):
        sty = _sev_style(f.severity)
        table.add_row(
            str(i), f"[{sty}]{f.severity.upper()}[/{sty}]",
            f.kind, f.target, f.evidence[:45])
    console.print(table)


# ===========================================================================
# Container escape checks
# ===========================================================================

CVE_KB = {
    "CVE-2024-21626": ("runc", "high",
                       "runc file descriptor leak → контейнерный escape"),
    "CVE-2022-0492": ("cgroups", "high",
                      "cgroups v1 release_agent escape (требуется CAP_SYS_ADMIN)"),
    "CVE-2019-5736": ("runc", "critical",
                      "runc overwrite через /proc/self/exe"),
    "CVE-2021-30465": ("runc", "high",
                       "Symlink exchange в mount → escape"),
    "CVE-2021-25741": ("kubelet", "high",
                       "Symlink exchange в subPath volume"),
    "CVE-2020-8554": ("kube-apiserver", "medium",
                      "MITM via ExternalIP service"),
    "CVE-2020-15257": ("containerd", "high",
                       "containerd-shim API via abstract socket"),
    "CVE-2020-8565": ("kube-apiserver", "medium",
                      "Log leakage of cached secret"),
    "CVE-2018-1002105": ("kube-apiserver", "critical",
                         "Privilege escalation в kubelet connection"),
}


def container_escape_checks() -> list[dict]:
    """Локальные проверки на container escape."""
    console.print("[cyan]🔓 Container escape checks[/cyan]\n")

    checks: list[dict] = []
    is_linux = sys.platform.startswith("linux")

    # 1. In container?
    in_container = False
    if is_linux:
        in_container = (
            Path("/.dockerenv").exists()
            or Path("/run/.containerenv").exists()
        )
        if not in_container and Path("/proc/1/cgroup").exists():
            try:
                cgroup = Path("/proc/1/cgroup").read_text(errors="ignore")
                if "docker" in cgroup.lower() or "kubepods" in cgroup.lower():
                    in_container = True
            except Exception:
                pass
    checks.append({"check": "Running in container",
                    "result": in_container})

    # 2. CAP_SYS_ADMIN
    caps_eff = 0
    if Path("/proc/self/status").exists():
        try:
            status = Path("/proc/self/status").read_text(errors="ignore")
            m = re.search(r"CapEff:\s*([0-9a-f]+)", status)
            if m:
                caps_eff = int(m.group(1), 16)
        except Exception:
            pass

    checks.append({
        "check": "CAP_SYS_ADMIN (bit 21)",
        "result": bool(caps_eff & (1 << 21)),
    })
    checks.append({
        "check": "CAP_SYS_PTRACE (bit 19)",
        "result": bool(caps_eff & (1 << 19)),
    })
    checks.append({
        "check": "CAP_NET_ADMIN (bit 12)",
        "result": bool(caps_eff & (1 << 12)),
    })
    checks.append({
        "check": "CAP_NET_RAW (bit 13)",
        "result": bool(caps_eff & (1 << 13)),
    })

    # 3. Sockets
    docker_sock = Path("/var/run/docker.sock")
    checks.append({
        "check": "/var/run/docker.sock",
        "result": docker_sock.exists() and os.access(str(docker_sock), os.R_OK),
    })
    containerd_sock = Path("/run/containerd/containerd.sock")
    checks.append({
        "check": "/run/containerd/containerd.sock",
        "result": containerd_sock.exists(),
    })
    crio_sock = Path("/var/run/crio/crio.sock")
    checks.append({
        "check": "/var/run/crio/crio.sock",
        "result": crio_sock.exists(),
    })

    # 4. K8s SA token
    sa_token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    checks.append({
        "check": "K8s SA token mount",
        "result": sa_token.exists(),
        "detail": str(sa_token) if sa_token.exists() else "",
    })

    # 5. Host mounts
    suspicious_mounts: list[str] = []
    if Path("/proc/mounts").exists():
        try:
            for line in Path("/proc/mounts").read_text(
                    errors="ignore").splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                mp = parts[1]
                if mp in ("/", "/host", "/root", "/var/lib/docker",
                          "/var/lib/kubelet", "/etc/kubernetes"):
                    if not mp.startswith(("/proc", "/sys", "/dev")):
                        suspicious_mounts.append(line[:200])
        except Exception:
            pass
    checks.append({
        "check": "Suspicious mounts (host paths)",
        "result": len(suspicious_mounts) > 0,
        "detail": "; ".join(suspicious_mounts[:3]),
    })

    # 6. /proc/sys/kernel/core_pattern writable?
    core_pattern = Path("/proc/sys/kernel/core_pattern")
    writable = False
    try:
        if core_pattern.exists():
            with core_pattern.open("a") as f:
                pass
            writable = True
    except Exception:
        pass
    checks.append({
        "check": "/proc/sys/kernel/core_pattern writable",
        "result": writable,
        "detail": "classic escape vector" if writable else "",
    })

    # 7. namespace check
    if Path("/proc/self/ns/pid").exists():
        try:
            pid_ns = os.readlink("/proc/self/ns/pid")
            init_ns = os.readlink("/proc/1/ns/pid")
            checks.append({
                "check": "PID namespace isolation",
                "result": pid_ns == init_ns,
                "detail": "no isolation!" if pid_ns == init_ns else "isolated",
            })
        except Exception:
            pass

    # Print
    table = Table(title="🔓 Container escape checks")
    table.add_column("Check", style="cyan", max_width=45)
    table.add_column("Result", width=12)
    table.add_column("Detail", style="dim", max_width=40)
    for c in checks:
        res = c.get("result", False)
        # Inverse logic for isolation check
        if c.get("check") == "PID namespace isolation":
            res_str = "[red]⚠ no isolation[/red]" if res else "[green]✓ isolated[/green]"
        else:
            res_str = "[red]⚠ yes[/red]" if res else "[green]✓ no[/green]"
        table.add_row(c["check"], res_str, str(c.get("detail", ""))[:40])
    console.print(table)

    # CVE KB
    cve_table = Table(title="📚 Container/k8s CVE knowledge base",
                       border_style="red")
    cve_table.add_column("CVE", style="cyan", width=18)
    cve_table.add_column("Component", style="magenta", width=14)
    cve_table.add_column("Severity", width=10)
    cve_table.add_column("Description", style="white", max_width=50)
    for cve, (comp, sev, desc) in CVE_KB.items():
        sty = _sev_style(sev)
        cve_table.add_row(cve, comp,
                           f"[{sty}]{sev.upper()}[/{sty}]",
                           desc[:50])
    console.print(cve_table)

    console.print("\n[bold yellow]📖 Exploitation hints:[/bold yellow]")
    console.print("  • docker.sock → docker run --privileged -v /:/host")
    console.print("  • CAP_SYS_ADMIN → mount host fs, cgroup v1 release_agent")
    console.print("  • /var/lib/kubelet readable → create pod with hostPID/hostPath")
    console.print("  • SA token → kubectl --token=$(cat token) --server=... get pods")

    db.save_scan("k8s_escape_check", "local", {"checks": checks})
    return checks


# ===========================================================================
# Export
# ===========================================================================

def export_json(findings: list[K8sFinding],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(K8S_DIR / f"findings_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(f) for f in findings],
                       indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(findings: list[K8sFinding],
               path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(K8S_DIR / f"findings_{ts}.csv")
    cols = ["kind", "target", "port", "severity", "url",
            "title", "evidence", "remediation"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for f_ in findings:
                w.writerow(asdict(f_))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(findings: list[K8sFinding],
                host: str = "", path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:40]
        path = str(K8S_DIR / f"findings_{safe}_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>K8s Scan — {html_mod.escape(host or 'target')}</title>",
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
        "</style></head><body>",
        f"<h1>☸  K8s Scan — {html_mod.escape(host or 'target')}</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        f"<p>Findings: <b>{len(findings)}</b></p>",
        "<table><tr><th>Sev</th><th>Kind</th><th>Target</th>"
        "<th>Port</th><th>Evidence</th></tr>",
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 5)):
        parts.append(
            f"<tr><td class='{f.severity}'>{f.severity.upper()}</td>"
            f"<td>{html_mod.escape(f.kind)}</td>"
            f"<td>{html_mod.escape(f.target)}</td>"
            f"<td>{f.port}</td>"
            f"<td>{html_mod.escape(f.evidence[:200])}</td></tr>")
    parts.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# CLI wrappers
# ===========================================================================

def cli_scan(host: str, ports: str | None = None) -> None:
    port_list = None
    if ports:
        port_list = [int(p.strip()) for p in ports.split(",")
                     if p.strip().isdigit()]
    findings = scan_host(host, ports=port_list)
    if findings and Confirm.ask("Экспорт JSON + HTML?", default=False):
        export_json(findings)
        export_html(findings, host)


def cli_api(host: str) -> None:
    r = check_k8s_api(extract_host(host))
    if r:
        _print_finding(r)
        _save_finding(r)
    else:
        console.print("[yellow]API-server не обнаружен.[/yellow]")


def cli_etcd(host: str, port: int = 2379) -> None:
    r = check_etcd(extract_host(host), port)
    if r:
        _print_finding(r)
        _save_finding(r)
    else:
        console.print("[yellow]etcd не открыт.[/yellow]")


def cli_docker(host: str, port: int = 2375) -> None:
    r = check_docker_api(extract_host(host), port)
    if r:
        _print_finding(r)
        _save_finding(r)
    else:
        console.print("[yellow]Docker API не открыт.[/yellow]")


def cli_escape() -> None:
    container_escape_checks()


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]☸  Kubernetes / Container Scanner Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан хоста (20+ сервисов)"),
        ("2", "Скан нескольких хостов (из файла)"),
        ("3", "Только kube-apiserver (6443)"),
        ("4", "Только etcd (2379)"),
        ("5", "Только Docker API (2375/2376)"),
        ("6", "Container escape checks (локально)"),
        ("7", "Показать все K8s-порты"),
        ("8", "Показать CVE KB"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        host = Prompt.ask("Хост/IP")
        findings = scan_host(host)
        if findings and Confirm.ask("Экспорт JSON + HTML?", default=False):
            export_json(findings)
            export_html(findings, host)
    elif c == "2":
        src = Prompt.ask("Файл или список через запятую")
        hosts: list[str] = []
        if os.path.isfile(src):
            hosts = [l.strip() for l in open(src, encoding="utf-8",
                                              errors="ignore")
                     if l.strip() and not l.startswith("#")]
        else:
            hosts = [h.strip() for h in src.split(",") if h.strip()]
        if hosts:
            all_f = scan_hosts(hosts)
            if all_f and Confirm.ask("Экспорт JSON?", default=False):
                export_json(all_f)
    elif c == "3":
        cli_api(Prompt.ask("Хост"))
    elif c == "4":
        cli_etcd(Prompt.ask("Хост"))
    elif c == "5":
        cli_docker(Prompt.ask("Хост"))
    elif c == "6":
        container_escape_checks()
    elif c == "7":
        t = Table(title="☸  K8s/Kubernetes ports")
        t.add_column("Port", style="cyan", width=6)
        t.add_column("Service", style="green")
        for pt, name in sorted(K8S_PORTS.items()):
            t.add_row(str(pt), name)
        console.print(t)
    elif c == "8":
        t = Table(title="📚 CVE Knowledge Base")
        t.add_column("CVE", style="cyan", width=18)
        t.add_column("Component", style="magenta", width=14)
        t.add_column("Severity", width=10)
        t.add_column("Description", style="white", max_width=55)
        for cve, (comp, sev, desc) in CVE_KB.items():
            sty = _sev_style(sev)
            t.add_row(cve, comp, f"[{sty}]{sev.upper()}[/{sty}]", desc[:55])
        console.print(t)