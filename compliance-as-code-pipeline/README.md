# Compliance-as-Code & Automated Audit Pipeline

Shift-Left regulatory compliance pipeline designed to continuously enforce **PCI-DSS v4.0** and **SOC 2 Type I** controls.

## Cryptographic Attestation Verification
Auditors (QSA) can cryptographically verify that the `AUDIT_EVIDENCE.md` was generated securely by this exact GitHub repository's CI/CD pipeline using Sigstore Keyless signing.

    cosign verify-blob \
      --certificate-identity="[https://github.com/egekarabey35/compliance-as-code-pipeline/.github/workflows/compliance.yaml@refs/heads/main](https://github.com/egekarabey35/compliance-as-code-pipeline/.github/workflows/compliance.yaml@refs/heads/main)" \
      --certificate-oidc-issuer="[https://token.actions.githubusercontent.com](https://token.actions.githubusercontent.com)" \
      --signature reports/AUDIT_EVIDENCE.md.sig \
      --certificate reports/AUDIT_EVIDENCE.md.crt \
      reports/AUDIT_EVIDENCE.md

*Note: This pipeline is designed for internal, private enterprise repositories where fork-based Pull Requests are disabled, ensuring OIDC token integrity.*
