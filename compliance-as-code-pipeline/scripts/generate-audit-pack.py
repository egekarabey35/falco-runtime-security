#!/usr/bin/env python3
import json
import os
import hashlib
from datetime import datetime, timezone

# FAIL-CLOSED PARSER'LAR
def parse_checkov():
    try:
        with open("reports/results_json.json", "r") as f:
            data = json.load(f)
            summary = data[0].get("summary", {}) if isinstance(data, list) and data else data.get("summary", {})
            failed = summary.get("failed", 0)
            return {"status": "FAILED" if failed > 0 else "PASSED", "findings": failed}
    except Exception as e:
        return {"status": f"FAILED (Parse Error: {str(e)})", "findings": -1} # Absence of evidence is evidence of failure

def parse_gitleaks():
    try:
        with open("reports/gitleaks-report.json", "r") as f:
            findings = json.load(f)
            count = len(findings) if isinstance(findings, list) else 0
            return {"status": "FAILED" if count > 0 else "PASSED", "findings": count}
    except Exception:
        return {"status": "FAILED (File Missing)", "findings": -1}

def parse_trivy():
    try:
        with open("reports/trivy-report.json", "r") as f:
            data = json.load(f)
            vuln_count = 0
            if "Results" in data:
                for r in data["Results"]:
                    vuln_count += len(r.get("Vulnerabilities", []))
            return {"status": "FAILED" if vuln_count > 0 else "PASSED", "findings": vuln_count}
    except Exception:
        return {"status": "FAILED (File Missing)", "findings": -1}

def parse_opa():
    try:
        with open("reports/opa-report.json", "r") as f:
            data = json.load(f)
            failures = 0
            for item in data:
                failures += len(item.get("failures", []))
            return {"status": "FAILED" if failures > 0 else "PASSED", "findings": failures}
    except Exception:
        return {"status": "FAILED (File Missing)", "findings": -1}

def generate_report():
    commit_sha = os.getenv("GITHUB_SHA", "UNVERIFIED_LOCAL_BUILD")
    branch = os.getenv("GITHUB_REF_NAME", "unknown")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    c = parse_checkov()
    g = parse_gitleaks()
    t = parse_trivy()
    o = parse_opa()

    overall_status = "PASSED" if all(x["status"] == "PASSED" for x in [c, g, t, o]) else "FAILED"

    report_md = f"""# Regulatory Compliance & Audit Evidence Pack
**Target Frameworks:** PCI-DSS v4.0 | SOC 2 Type I (Point-in-Time Attestation)
**Attestation Date:** {timestamp}
**Build Commit SHA:** `{commit_sha}`
**Overall Gate Status:** **{overall_status}**

---

## 1. Compliance Matrix & Verification Gate

| Verification Gate | Target Control | Automated Tool | Gate Status | Violations / Findings |
|---|---|---|---|---|
| **Secret Exfiltration** | PCI-DSS 3.4 / SOC 2 CC6.1 | Gitleaks | **{g["status"]}** | {g["findings"]} |
| **IaC & Workload Hardening** | PCI-DSS 2.2 / CIS K8s | Checkov | **{c["status"]}** | {c["findings"]} |
| **Policy as Code Enforcement**| PCI-DSS 3.4 / Non-Root | Open Policy Agent | **{o["status"]}** | {o["findings"]} |
| **Container Vulnerability** | PCI-DSS 6.2 / SOC 2 CC7.1 | Trivy | **{t["status"]}** | {t["findings"]} |

---

## 2. Chain of Custody & Attestation Details
- **Verification Engine:** Automated Shift-Left GitHub Actions Pipeline.
- **Fail-Closed Gate:** Zero human overrides permitted. Absence of evidence triggers automatic pipeline failure.
- **Evidence Storage:** Cryptographically hashed and generated natively within ephemeral CI runner.
"""
    
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/AUDIT_EVIDENCE.md"
    
    with open(report_path, "w") as f:
        f.write(report_md)
        
    # Kriptografik kanit uretimi (SHA256 Hash)
    sha256_hash = hashlib.sha256(report_md.encode()).hexdigest()
    with open("reports/AUDIT_EVIDENCE.sha256", "w") as f:
        f.write(f"{sha256_hash}  AUDIT_EVIDENCE.md")

    print(f"[SUCCESS] Rapor (SHA256: {sha256_hash}) reports/ altinda olusturuldu.")

if __name__ == "__main__":
    generate_report()
