# Compliance-as-Code & Automated Audit Pipeline

Shift-Left regulatory compliance pipeline designed to continuously enforce **PCI-DSS v4.0** and **SOC 2 Type I** controls.

## Cryptographic Attestation Verification
Auditors (QSA) can cryptographically verify that the `AUDIT_EVIDENCE.md` was generated securely by this exact GitHub repository's CI/CD pipeline using Sigstore Keyless signing.

Due to enterprise privacy constraints (`--tlog-upload=false`), the signature is embedded with an RFC3161 timestamp from DigiCert's Timestamp Authority (`http://timestamp.digicert.com`). 

*⚠️ **Known Limitation (Portfolio/Demo Constraint):** Using a public free TSA endpoint in a high-volume CI pipeline risks rate-limiting and creates a Single Point of Failure (SPOF).*

### Verifying the Artifact (QSA Instructions)
To verify the timestamp offline, the auditor must provide the TSA's root certificate chain (`digicert-tsa-root.pem`):

    cosign verify-blob \
      --certificate-identity="https://github.com/egekarabey35/compliance-as-code-pipeline/.github/workflows/compliance.yaml@refs/heads/main" \
      --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
      --timestamp-certificate-chain=digicert-tsa-root.pem \
      --signature reports/AUDIT_EVIDENCE.md.sig \
      --certificate reports/AUDIT_EVIDENCE.md.crt \
      reports/AUDIT_EVIDENCE.md

*⚠️ **Day 2 Operations Note:** The `digicert-tsa-root.pem` file must be manually downloaded from DigiCert's trusted root repository. Certificate rotation and tracking of DigiCert's PKI lifecycle is a manual administrative process not covered by this automation.*
