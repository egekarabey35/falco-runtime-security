# Compliance-as-Code & Automated Audit Pipeline

Shift-Left regulatory compliance pipeline designed to continuously enforce **PCI-DSS v4.0** and **SOC 2 Type I** controls.

## Architectural Notes
* **Collect-Then-Gate Pattern:** Step-level exit codes (like Checkov or Trivy) are intentionally soft-failed (`continue-on-error: true`). The absolute and sole authority to break the pipeline is the Evidence Aggregator script (`generate-audit-pack.py`). It parses all JSON outputs and triggers a `sys.exit(1)` if any control fails. This ensures a failure in step 1 does not prevent the collection of evidence for step 4.
* **Infrastructure-as-Deployed:** The Terraform scanning step uses GitHub OIDC (`configure-aws-credentials`) to authenticate with AWS, initializes a remote S3 backend, and evaluates the dynamic `terraform plan` against the actual AWS state, rather than just linting static code.
* **Evidence Survivability:** Artifact generation and Cosign signing steps use `if: always()`, guaranteeing that even when a PR is blocked (failed gate), the cryptographic evidence of the failure is preserved and signed for auditors.

## Cryptographic Attestation Verification
Auditors (QSA) can cryptographically verify that the `AUDIT_EVIDENCE.md` was generated securely by this exact GitHub repository's CI/CD pipeline using Sigstore Keyless signing.

Due to enterprise privacy constraints (`--tlog-upload=false`), the signature is embedded with an RFC3161 timestamp from DigiCert's Timestamp Authority (`http://timestamp.digicert.com`). 

    cosign verify-blob \
      --certificate-identity="https://github.com/egekarabey35/compliance-as-code-pipeline/.github/workflows/compliance.yaml@refs/heads/main" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
      --timestamp-certificate-chain=digicert-tsa-root.pem \
      --signature reports/AUDIT_EVIDENCE.md.sig \
      --certificate reports/AUDIT_EVIDENCE.md.crt \
      reports/AUDIT_EVIDENCE.md
