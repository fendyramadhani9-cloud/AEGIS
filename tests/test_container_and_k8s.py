"""Tests for Container (Docker/CRI) and Kubernetes Telemetry Parsing, Rules, and Posture Checks."""

import json
from aegis_agent.linux_parser import LinuxTelemetryParser
from aegis_agent.security_checker import ReadOnlySecurityChecker
from aegis_backend.rules_engine import RulesEngine


def test_docker_json_and_k8s_cri_log_unwrapping():
    parser = LinuxTelemetryParser()

    docker_web = json.dumps({
        "log": '203.0.113.44 - - [13/Nov/2026:10:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 162 "-" "curl/8.0"\n',
        "stream": "stdout",
        "time": "2026-11-13T10:00:00Z",
        "container_name": "edge-nginx",
    })
    ev1 = parser.parse_line(docker_web)
    assert ev1 is not None
    assert ev1.event_type == "web_attack_probe"
    assert ev1.details["container_runtime"] == "docker"
    assert ev1.details["container_name"] == "edge-nginx"

    cri_line = '2026-11-13T10:01:00Z stdout F 198.51.100.20 - - [13/Nov/2026:10:01:00 +0000] "GET /.env HTTP/1.1" 403 118 "-" "Mozilla/5.0"'
    ev2 = parser.parse_line(cri_line)
    assert ev2 is not None
    assert ev2.event_type == "web_attack_probe"
    assert ev2.details["container_runtime"] == "kubernetes_cri"


def test_container_runtime_and_k8s_audit_parsers_and_rules():
    parser = LinuxTelemetryParser()
    engine = RulesEngine()

    raw_lines = [
        json.dumps({
            "Type": "container",
            "Action": "exec_start: /bin/sh",
            "Actor": {"ID": "abc123456789", "Attributes": {"name": "payment-api", "image": "bank/api:1.2"}},
            "time": 1794570000,
        }),
        json.dumps({
            "Type": "container",
            "Action": "start",
            "Actor": {"ID": "def987654321", "Attributes": {"name": "rogue-ctr", "image": "alpine:latest", "privileged": "true"}},
            "time": 1794570010,
        }),
        json.dumps({
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "verb": "create",
            "user": {"username": "ops-compromised"},
            "sourceIPs": ["10.20.30.40"],
            "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod-banking", "name": "core-ledger-0"},
            "requestReceivedTimestamp": "2026-11-13T10:05:00Z",
        }),
        json.dumps({
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "verb": "create",
            "user": {"username": "attacker-sa"},
            "sourceIPs": ["10.20.30.41"],
            "objectRef": {"resource": "clusterrolebindings", "name": "evil-cluster-admin"},
            "requestReceivedTimestamp": "2026-11-13T10:06:00Z",
        }),
        json.dumps({
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "verb": "get",
            "user": {"username": "unknown-pod"},
            "sourceIPs": ["10.20.30.42"],
            "objectRef": {"resource": "secrets", "namespace": "prod-banking", "name": "db-master-key"},
            "requestReceivedTimestamp": "2026-11-13T10:07:00Z",
        }),
    ]

    parsed = parser.parse_batch(raw_lines, prefix="EVT-CK")
    assert len(parsed) == 5

    db_events = [
        {
            "id": p.event_id,
            "host_id": "node-prod-01",
            "event_type": p.event_type,
            "event_timestamp": p.timestamp,
            "source_ip": p.source_ip,
            "user_name": p.user,
            "details": p.details,
        }
        for p in parsed
    ]
    alerts, links = engine.evaluate_events(db_events)
    rule_ids = {a["rule_id"] for a in alerts}
    assert "RULE-CONTAINER-EXEC" in rule_ids
    assert "RULE-CONTAINER-ESCAPE-RISK" in rule_ids
    assert "RULE-K8S-POD-EXEC" in rule_ids
    assert "RULE-K8S-RBAC-ESCALATION" in rule_ids
    assert "RULE-K8S-SECRET-ACCESS" in rule_ids
    assert len(links) == 5


def test_cis_docker_and_k8s_posture_checks():
    checker = ReadOnlySecurityChecker()
    bad_docker = checker.check_container_runtime_posture(daemon_json_content='{"hosts": ["tcp://0.0.0.0:2375"]}')
    assert bad_docker["status"] == "fail"
    assert bad_docker["check_id"] == "CIS-DOCKER-5.1"

    bad_k8s = checker.check_kubernetes_audit_posture(apiserver_manifest="spec:\n  containers:\n  - command:\n    - --anonymous-auth=true\n")
    assert bad_k8s["status"] == "fail"
    assert bad_k8s["check_id"] == "CIS-K8S-1.2"

    good_k8s = checker.check_kubernetes_audit_posture(apiserver_manifest="spec:\n  - --anonymous-auth=false\n  - --audit-log-path=/var/log/k8s/audit.log\n")
    assert good_k8s["status"] == "pass"
