#!/usr/bin/env bash
# Installs Kyverno (pinned version, manifest integrity checked) and the AmCart admission policy.
# Usage (repository root, on the VM): deploy/scripts/install-kyverno.sh
set -euo pipefail

KYVERNO_VERSION="v1.20.0"
# SHA-256 of https://github.com/kyverno/kyverno/releases/download/v1.20.0/install.yaml
KYVERNO_SHA256="a93cbe980ce77142f6a5b2c0fdee72a2aaa7b1d0434116d2adbed1909dc9483e"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
manifest="$(mktemp)"
trap 'rm -f "$manifest"' EXIT

echo "==> Downloading Kyverno $KYVERNO_VERSION"
curl -fsSL --retry 3 -o "$manifest" \
  "https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VERSION/install.yaml"
echo "$KYVERNO_SHA256  $manifest" | sha256sum -c - \
  || { echo "Kyverno manifest checksum mismatch, refusing to install." >&2; exit 1; }

echo "==> Installing Kyverno"
# Server-side apply: Kyverno's CRDs are too large for client-side apply annotations.
kubectl apply --server-side -f "$manifest" >/dev/null
for d in kyverno-admission-controller kyverno-background-controller \
         kyverno-cleanup-controller kyverno-reports-controller; do
  kubectl -n kyverno rollout status "deploy/$d" --timeout=600s
done

echo "==> Applying AmCart admission policy"
kubectl apply -f "$ROOT/deploy/k8s/policies/"
kubectl get validatingpolicies.policies.kyverno.io
