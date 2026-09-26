# Compliance-as-Code & Automated Audit Pipeline

Shift-Left regulatory compliance pipeline designed to continuously enforce **PCI-DSS v4.0** and **SOC 2 Type I** controls.

## Cryptographic Attestation Verification
Auditors (QSA) can cryptographically verify that the `AUDIT_EVIDENCE.md` was generated securely by this exact GitHub repository's CI/CD pipeline using Sigstore Keyless signing.

Due to enterprise privacy constraints (`--tlog-upload=false`), the signature is embedded with an RFC3161 timestamp from DigiCert's Timestamp Authority (`http://timestamp.digicert.com`). 

*⚠️ **Known Limitation (Portfolio/Demo Constraint):** Using a public free TSA endpoint in a high-volume CI pipeline risks rate-limiting and creates a Single Point of Failure (SPOF). In a true production environment, this should be replaced with a commercial SLA-backed TSA or an internal corporate RFC3161 server.*

To verify the timestamp offline, the auditor must provide the TSA's root certificate chain:

    cosign verify-blob \
      --certificate-identity="https://github.com/egekarabey35/compliance-as-code-pipeline/.github/workflows/compliance.yaml@refs/heads/main" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
      --timestamp-certificate-chain=digicert-tsa-root.pem \
      --signature reports/AUDIT_EVIDENCE.md.sig \
      --certificate reports/AUDIT_EVIDENCE.md.crt \
      reports/AUDIT_EVIDENCE.md

*Note: This pipeline is designed for internal, private enterprise repositories where fork-based Pull Requests are disabled, ensuring OIDC token integrity.*
