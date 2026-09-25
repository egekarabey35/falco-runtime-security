# Cloud-Native Runtime Security & Automated Remediation Engine

An eBPF-driven runtime security and active defense architecture designed for high-risk fintech environments. Tailored to protect and isolate compromised workloads running the TRC-20 Vault Webhook Gateway.

---

## Architecture Overview

1. Detection: Falco monitors Linux kernel syscalls via eBPF driver.
2. Trigger: CRITICAL priority events are forwarded via HTTP webhook.
3. Remediation: Go worker patches target pod with security.quarantine=true.
4. Isolation: Deny-All NetworkPolicy matches quarantine label and cuts all traffic.
5. Forensics: Container remains alive without network access for incident response.

### Detection Rules
- Unauthorized Shell Spawn in TRC20 Gateway (sh, bash, ash)
- Unauthorized Read of Injected Vault Secret (/vault/secrets/webhook-secret)
- Outbound Network Connection to Non-Whitelisted Endpoint

---

## Alert Noise Tuning

| Metric | Default Falco | Hardened Ruleset | Delta |
|---|---|---|---|
| Alert Frequency | ~142 alerts/hr | < 2 alerts/hr | -98.5% |
| False-Positive Noise | High | Near Zero | Scannable |
| Actionable Precision | Low | High | High Fidelity |

---

## Attack Simulation

Execute the automated simulation script:
./scripts/simulate-attack.sh

### Operational Portability Note
> **ClusterIP Customization:** The API Server CIDR `10.96.0.1/32` in `remediation-networkpolicy.yaml` reflects standard local/kind environments. In managed environments (EKS/GKE), extract the exact ClusterIP via:
> `kubectl get svc kubernetes -n default -o jsonpath="{.spec.clusterIP}"` and patch the CIDR accordingly.
