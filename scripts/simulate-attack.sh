#!/bin/bash
set -e

NAMESPACE="fintech-gateway"
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=trc20-gateway -o jsonpath="{.items[0].metadata.name}" 2>/dev/null || echo "")

if [ -z "$POD_NAME" ]; then
  echo "[ERROR] $NAMESPACE icinde calisan trc20-gateway pod'u bulunamadi!"
  exit 1
fi

echo "=========================================================="
echo "[ADVERSARY SIMULATION] Hedef Pod: $POD_NAME"
echo "=========================================================="

echo "[1] Test: Pod icinde yetkisiz interaktif shell spawn..."
kubectl exec -n $NAMESPACE $POD_NAME -- sh -c "echo '[ATTACK] Shell spawned inside container'" || true

echo "[2] Test: /vault/secrets/webhook-secret dosyasina cat ile erisim..."
kubectl exec -n $NAMESPACE $POD_NAME -- cat /vault/secrets/webhook-secret || true

echo "----------------------------------------------------------"
echo "[DOGRULAMA] Karantina label'i (security.quarantine=true) kontrol ediliyor..."
sleep 3
kubectl get pod -n $NAMESPACE $POD_NAME --show-labels | grep "security.quarantine=true" && \
  echo "[PASSED] Tehdit yakalandi ve pod NetworkPolicy ile izole edildi!" || \
  echo "[FAILED] Pod karantina etiketi almadi."
