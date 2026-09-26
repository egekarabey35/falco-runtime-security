package compliance.pci_dss

default allow = false

# 1. K8s Pod Güvenliği: root kullanıcısı ve privileged container yasak
violation[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot == true
    msg := sprintf("PCI-DSS 2.2 IHLAHLI: '%v' container'i 'runAsNonRoot: true' icermelidir.", [container.name])
}

violation[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("PCI-DSS 2.2 IHLAHLI: '%v' container'i privileged olarak calisamaz.", [container.name])
}

# 2. Terraform S3 Bucket Kontrolü: KMS Sifrelemesi Zorunlu
violation[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    rule := resource.change.after.rule[_]
    not rule.apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
    msg := sprintf("PCI-DSS 3.4 IHLAHLI: '%v' kaynaginda KMS sifrelemesi zorunludur.", [resource.address])
}

allow {
    count(violation) == 0
}
