#!/bin/bash
set -e

NAMESPACE="fintech-gateway"
POD_NAME=$1

if [ -z "$POD_NAME" ]; then
  echo "Kullanim: ./scripts/unquarantine.sh <pod-adi>"
  echo "Mevcut karantinadaki pod'lar:"
  kubectl get pods -n $NAMESPACE -l security.quarantine=true --no-headers -o custom-columns=":metadata.name"
  exit 1
fi

echo "[RECOVERY] Pod karantinadan cikariliyor: $NAMESPACE/$POD_NAME"
kubectl label pod -n $NAMESPACE$POD_NAME security.quarantine-

echo "[SUCCESS] Pod karantinadan basariyla cikarildi ve NetworkPolicy izolasyonu kaldirildi."
