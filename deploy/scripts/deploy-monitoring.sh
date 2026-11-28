#!/usr/bin/env bash
# Deploys the observability stack (section 4.7) next to the application:
#   Alloy (collects pod logs) -> Loki (stores them, evaluates the detection rules) -> Grafana.
#
#   deploy/scripts/deploy-monitoring.sh            # after deploy/scripts/deploy.sh
#
# Grafana's admin password is generated once (CSPRNG) into the same secrets file as the
# application secrets, mode 600, outside the repository; it is never printed.
set -euo pipefail

CLUSTER="${CLUSTER:-minikube}"           # minikube | kind
PROFILE="${PROFILE:-amcart}"
SECRETS_FILE="${SECRETS_FILE:-$HOME/.config/amcart/secrets.env}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

case "$CLUSTER" in
  minikube) CONTEXT="$PROFILE" ;;
  kind)     CONTEXT="kind-$PROFILE" ;;
  *) echo "CLUSTER must be minikube or kind" >&2; exit 2 ;;
esac
kubectl config use-context "$CONTEXT" >/dev/null

IMAGES=(grafana/loki:3.7.11 grafana/alloy:v1.22.0 grafana/grafana:13.2.6)
echo "==> Images"
for img in "${IMAGES[@]}"; do
  if [ "$CLUSTER" = kind ]; then
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img"
    kind load docker-image "$img" --name "$PROFILE" >/dev/null
  elif minikube -p "$PROFILE" image ls | grep -q "${img}$"; then
    echo "    $img already loaded"; continue
  else
    # The VM's network is slow: pull once on the host, then copy into the cluster.
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img"
    minikube -p "$PROFILE" image load "$img"
  fi
  echo "    $img loaded"
done

echo "==> Grafana admin secret"
touch "$SECRETS_FILE" && chmod 600 "$SECRETS_FILE"
if ! grep -q '^GRAFANA_ADMIN_PASSWORD=' "$SECRETS_FILE"; then
  echo "GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 24)" >> "$SECRETS_FILE"
  echo "    generated (stored in $SECRETS_FILE)"
fi
GRAFANA_ADMIN_PASSWORD="$(grep '^GRAFANA_ADMIN_PASSWORD=' "$SECRETS_FILE" | cut -d= -f2-)"
kubectl apply -f deploy/k8s/monitoring/namespace.yaml >/dev/null
kubectl -n amcart-monitoring create secret generic grafana-admin \
  --from-literal="password=$GRAFANA_ADMIN_PASSWORD" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
unset GRAFANA_ADMIN_PASSWORD

echo "==> Applying the stack"
# Alloy must reach the Kubernetes API. Its real address (after the Service's DNAT, which is what the
# network policy sees) depends on the cluster, so the allow rule is generated here.
GEN="$ROOT/deploy/k8s/overlays/.generated-monitoring"   # git-ignored
mkdir -p "$GEN"
API_IPS="$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{range .items[*].endpoints[*]}{.addresses[0]}{"\n"}{end}' | sort -u)"
API_PORT="$(kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
  -o jsonpath='{.items[0].ports[0].port}')"
[ -n "$API_IPS" ] && [ -n "$API_PORT" ] || { echo "cannot find the API server endpoints" >&2; exit 1; }
{
  cat <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: alloy-allow-egress-to-apiserver
  namespace: amcart-monitoring
spec:
  podSelector:
    matchLabels: { app: alloy }
  policyTypes: [Egress]
  egress:
    - to:
EOF
  for ip in $API_IPS; do echo "        - ipBlock: { cidr: $ip/32 }"; done
  cat <<EOF
      ports:
        - { protocol: TCP, port: $API_PORT }
EOF
} > "$GEN/apiserver-egress.yaml"
cat > "$GEN/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../monitoring
  - apiserver-egress.yaml
EOF
echo "    API server for Alloy: $(echo $API_IPS) port $API_PORT"
kubectl apply -k "$GEN"

echo "==> Waiting for rollouts"
for d in loki alloy grafana; do
  kubectl -n amcart-monitoring rollout status "deploy/$d" --timeout=300s
done

echo
echo "Observability stack ready."
echo "Grafana:  kubectl -n amcart-monitoring port-forward svc/grafana 3000:3000   (user admin, password in $SECRETS_FILE)"
echo "Replay:   tests/detection/replay-attacks.sh"
