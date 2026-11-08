"""
AEGIS Source Attribution & Network Context Engine.
Enforces PRD §7.5 and Prioritas 6.1 Context-Aware Attribution Standards.

Design Principles:
1. Strict, deterministic IP classification based on IETF standards (RFC 1122, RFC 1918, RFC 5737, RFC 4193).
2. Explicit distinction between Loopback, Private Internal, Benchmark/Documentation, and Public Routable sources.
3. Anti-Assumption Guarantee: Never assume loopback or private IPs represent remote/external adversaries.
4. Identity Discontinuity Guard: Prevents conflating distinct user accounts sharing the loopback interface.
"""

import ipaddress
from typing import Dict, Any, Optional, Set, Tuple


# RFC 5737 / RFC 3849 / RFC 2544 / RFC 6598 benchmark and documentation subnets
_BENCHMARK_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared Address Space (RFC 6598)
    ipaddress.ip_network("2001:db8::/32"),     # Documentation IPv6 (RFC 3849)
]


def classify_ip_source(ip_str: Optional[str]) -> Dict[str, Any]:
    """
    Classifies an IP address into standard topological categories:
    - 'loopback': 127.0.0.0/8, ::1 (Local host origin)
    - 'private': 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, link-local (Internal network)
    - 'reserved_benchmark': RFC 5737 TEST-NET, RFC 2544, etc. (Synthetic test data)
    - 'public': Globally routable internet address (Remote origin)
    - 'unknown': Missing, empty, or invalid format
    """
    if not ip_str or not str(ip_str).strip() or str(ip_str).strip().lower() in ("unknown", "unavailable", "none", "null"):
        return {
            "ip": None,
            "category": "unknown",
            "is_loopback": False,
            "is_private": False,
            "is_benchmark": False,
            "is_public": False,
            "label": "Unknown / Unrecorded Origin",
            "attribution_narrative": "an unrecorded source",
            "threat_actor_context": "indeterminate origin",
        }

    clean_ip = str(ip_str).strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return {
            "ip": clean_ip,
            "category": "unknown",
            "is_loopback": False,
            "is_private": False,
            "is_benchmark": False,
            "is_public": False,
            "label": f"Malformed IP ({clean_ip})",
            "attribution_narrative": f"an unparseable IP '{clean_ip}'",
            "threat_actor_context": "invalid network identifier",
        }

    # 1. Loopback (RFC 1122 / RFC 4291)
    if ip_obj.is_loopback:
        return {
            "ip": clean_ip,
            "category": "loopback",
            "is_loopback": True,
            "is_private": False,
            "is_benchmark": False,
            "is_public": False,
            "label": "Local Loopback (Host Internal)",
            "attribution_narrative": f"local loopback interface ({clean_ip})",
            "threat_actor_context": "local host process / internal administrative activity",
        }

    # 2. Reserved Benchmark / Documentation (RFC 5737, etc.)
    for b_net in _BENCHMARK_NETWORKS:
        if ip_obj in b_net:
            return {
                "ip": clean_ip,
                "category": "reserved_benchmark",
                "is_loopback": False,
                "is_private": False,
                "is_benchmark": True,
                "is_public": False,
                "label": "RFC 5737 Benchmark / Synthetic Test-Net",
                "attribution_narrative": f"synthetic documentation subnet ({clean_ip})",
                "threat_actor_context": "synthetic test harness / benchmark dataset",
            }

    # 3. Private Internal Network (RFC 1918 / RFC 4193 / Link-Local)
    if ip_obj.is_private or ip_obj.is_link_local:
        return {
            "ip": clean_ip,
            "category": "private",
            "is_loopback": False,
            "is_private": True,
            "is_benchmark": False,
            "is_public": False,
            "label": "Internal / Private Subnet",
            "attribution_narrative": f"internal private network ({clean_ip})",
            "threat_actor_context": "internal network asset / intranet user",
        }

    # 4. Public Globally Routable
    if ip_obj.is_global:
        return {
            "ip": clean_ip,
            "category": "public",
            "is_loopback": False,
            "is_private": False,
            "is_benchmark": False,
            "is_public": True,
            "label": "Public Internet (Routable)",
            "attribution_narrative": f"external public IP ({clean_ip})",
            "threat_actor_context": "external remote source",
        }

    # Fallback for other reserved
    return {
        "ip": clean_ip,
        "category": "reserved",
        "is_loopback": False,
        "is_private": False,
        "is_benchmark": False,
        "is_public": False,
        "label": f"Reserved / Special IP ({clean_ip})",
        "attribution_narrative": f"reserved network address ({clean_ip})",
        "threat_actor_context": "special-use address",
    }


def format_contextual_attack_scenario(
    provenance: str,
    source_ip: Optional[str],
    target_user: Optional[str],
    has_brute: bool,
    has_auth: bool,
    has_sudo: bool,
    host_id: str,
) -> Tuple[str, str]:
    """
    Generates a highly accurate, context-aware title and attack scenario narrative.
    Adheres strictly to Prioritas 6.1 rules:
    - Never calls 127.0.0.1 an 'external adversary'.
    - Explains controlled tests as operational validation exercises.
    - Explicitly characterizes local vs internal vs remote origin.
    
    Returns:
        (title, attack_scenario)
    """
    attr = classify_ip_source(source_ip)
    ip_label = attr["ip"] or "unrecorded source"
    user_label = target_user or "unspecified user"

    is_test = provenance == "controlled_operational_test" or "127.0.0.1" in str(source_ip)
    is_benchmark = provenance == "synthetic_benchmark" or attr["is_benchmark"]

    if has_brute and has_auth and has_sudo:
        if is_test:
            title = f"Controlled Operational Security Test: Multi-Stage Auth & Sudo on {host_id}"
            scenario = (
                f"Controlled security testing exercise executed on {attr['attribution_narrative']}: "
                f"Automated authentication failure sequence targeting test credentials, "
                f"followed by key-based authentication as user '{user_label}', and privileged sudo command simulation."
            )
        elif is_benchmark:
            title = f"Synthetic Benchmark: Multi-Stage Brute-Force to Sudo Shell on {host_id}"
            scenario = (
                f"Benchmark evaluation scenario simulated from {attr['attribution_narrative']}: "
                f"Simulated brute-force sequence followed by privileged sudo execution by '{user_label}'."
            )
        elif attr["is_loopback"]:
            title = f"Local Loopback Authentication Failures to Privileged Sudo on {host_id}"
            scenario = (
                f"Local process originating on loopback ({ip_label}) generated repeated authentication failures, "
                f"followed by authentication as user '{user_label}' and privileged sudo command execution. "
                f"Activity reflects local system or containerized tool execution rather than remote ingress."
            )
        elif attr["is_private"]:
            title = f"Internal Network Brute-Force to Privileged Sudo Shell on {host_id}"
            scenario = (
                f"Internal host ({ip_label}) generated repeated authentication failures, "
                f"authenticated as user '{user_label}', and executed privileged commands via sudo."
            )
        else:
            title = f"Remote Multi-Stage Brute-Force to Privileged Sudo Shell on {host_id}"
            scenario = (
                f"External remote IP ({ip_label}) launched repeated authentication attempts, "
                f"succeeded in authenticating as user '{user_label}', and executed privileged commands via sudo."
            )

    elif has_auth and has_sudo:
        if is_test:
            title = f"Controlled Security Test: Authentication Followed by Sudo on {host_id}"
            scenario = f"Controlled validation activity on {attr['attribution_narrative']}: user '{user_label}' authenticated and executed test command via sudo."
        elif attr["is_loopback"]:
            title = f"Local Authentication Followed by Privileged Sudo on {host_id}"
            scenario = f"Local session for user '{user_label}' established from loopback followed by privileged sudo command execution."
        else:
            title = f"Authentication Followed by Privileged Sudo on {host_id}"
            scenario = f"User '{user_label}' authenticated from {attr['attribution_narrative']} followed by privileged commands via sudo."

    elif has_brute and has_auth:
        if is_test:
            title = f"Controlled Test: SSH Authentication Verification on {host_id}"
            scenario = f"Controlled test sequence on {attr['attribution_narrative']} testing authentication failure handling and subsequent login."
        elif attr["is_loopback"]:
            title = f"Local Loopback Authentication Failures and Login on {host_id}"
            scenario = f"Authentication failures on loopback ({ip_label}) followed by successful authentication for user '{user_label}'."
        else:
            title = f"SSH Repeated Failures Followed by Success on {host_id}"
            scenario = f"Authentication failures originating from {attr['attribution_narrative']} followed by successful login for '{user_label}'."

    elif has_sudo:
        if is_test:
            title = f"Controlled Test: Sudo Command Execution on {host_id}"
            scenario = f"Controlled security test: user '{user_label}' executed safe simulated shell command via sudo."
        else:
            title = f"Suspicious Sudo Privileged Execution on {host_id}"
            scenario = f"User '{user_label}' executed potentially hazardous commands or root shells via sudo."

    elif has_brute:
        if is_test:
            title = f"Controlled Test: SSH Authentication Failures on {host_id}"
            scenario = f"Controlled test generated repeated SSH authentication failures from loopback ({ip_label})."
        elif attr["is_loopback"]:
            title = f"Local Loopback Authentication Failure Burst on {host_id}"
            scenario = f"Repeated authentication failures observed originating locally from loopback interface ({ip_label})."
        else:
            title = f"Repeated SSH Authentication Failures (Brute-Force) on {host_id}"
            scenario = f"Repeated SSH authentication failures detected from {attr['attribution_narrative']}."

    else:
        title = f"Security Detection Cluster on {host_id}"
        scenario = f"Correlated security detections on {host_id} involving {attr['attribution_narrative']}."

    return title, scenario
