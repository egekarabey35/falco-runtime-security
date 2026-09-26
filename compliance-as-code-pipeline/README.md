# Compliance-as-Code & Automated Audit Pipeline

Shift-Left regulatory compliance pipeline designed to continuously enforce **PCI-DSS v4.0** and **SOC 2 Type II** controls. Automatically compiles audit evidence on every git event.

## Verification Gates
1. **Gitleaks:** Secret leakage and credential exfiltration prevention (PCI-DSS 3.4).
2. **Checkov & OPA/Rego:** Infrastructure as Code (Terraform) and K8s configuration guardrails (PCI-DSS 2.2).
3. **Trivy:** Base container vulnerability and SBOM attestations (PCI-DSS 6.2).
4. **Audit Aggregator:** Generates an automated, tamper-evident audit evidence pack (`AUDIT_EVIDENCE.md`).

## Local Verification
```bash
python3 scripts/generate-audit-pack.py
cat reports/AUDIT_EVIDENCE.md
```
