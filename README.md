# Falco Runtime Security and Automated Isolation Lab

[![Go remediation checks](https://github.com/egekarabey35/falco-runtime-security/actions/workflows/go-ci.yml/badge.svg)](https://github.com/egekarabey35/falco-runtime-security/actions/workflows/go-ci.yml)

A **Kubernetes runtime-security reference project** combining Falco eBPF/sycall detection rules with a Go webhook receiver that can label matching pods for isolation by NetworkPolicy.

## Architecture in this repository

1. Falco rule definitions under [`falco/rules/`](falco/rules/) describe suspicious process execution, secret-file access and abnormal connections.
2. A webhook listener in [`remediation/main.go`](remediation/main.go) authenticates an `X-Falco-Token` header, reads bounded JSON and processes critical events.
3. If a critical event concerns a pod in the configured `fintech-gateway` namespace, the worker attempts to patch `security.quarantine=true`.
4. [`k8s/quarantine-networkpolicy.yaml`](k8s/quarantine-networkpolicy.yaml) contains a matching deny policy. Actual packet isolation **depends on a NetworkPolicy-enforcing CNI and correct policy deployment**.
5. Authentication failures and parsing errors are rejected before any quarantine action.

## Verification status

The [Go CI workflow](.github/workflows/go-ci.yml) runs build/tests and `go vet`, including tests for rejected unauthorized requests, oversized webhook bodies and accepted noncritical events. This does not prove end-to-end cluster isolation or real-world alert precision.

The previously reported alert-frequency and latency figures were **not reproduced in the current automated tests** and are intentionally omitted. Production-like metrics require a documented test environment, workload, baseline and raw measurements.

## Development and controlled simulation

```bash
cd remediation
go test ./...
go vet ./...
cd ..
# Only after deploying this demo to a lab cluster:
./scripts/simulate-attack.sh
```

The simulation script attempts controlled accesses against a test pod and now **discards secret file content instead of printing it**. The demo TRC-20 image may be distroless, with no `sh` or `cat`, so these commands may fail without generating the intended Falco event. Use a disposable lab environment and verify results from Falco and Kubernetes logs.

## Remaining requirements

- Configure a genuine authenticated Falco webhook path and verify TLS/network segmentation.
- Install a CNI that enforces the deny policy.
- Review the currently broad remediation API egress exception in [`k8s/remediation-networkpolicy.yaml`](k8s/remediation-networkpolicy.yaml) and constrain it to the cluster's actual control-plane endpoints.
- Test quarantine actions using Kubernetes fake-client or integration tests; compilation alone does not establish that pods are actually isolated.
- Avoid marketing this as independently audited or production-ready software.

Related repositories: [TRC-20 webhook gateway](https://github.com/egekarabey35/trc20-vault-webhook-gateway) and [Compliance-as-Code](https://github.com/egekarabey35/compliance-as-code-pipeline).
