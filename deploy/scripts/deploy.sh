#!/usr/bin/env bash
# Builds the images, loads them into the cluster, creates the runtime secrets and applies the manifests.
#
#   deploy/scripts/deploy.sh                          # VM: minikube profile "amcart", base manifests
#   CLUSTER=kind OVERLAY=dast deploy/scripts/deploy.sh  # CI: disposable kind cluster for DAST
#
# Secrets (section 4.4): generated once with a CSPRNG into $SECRETS_FILE (mode 600, outside the
# repository), then pushed to the cluster as Kubernetes Secrets. They never appear in Git, in
# an image, or in this script's output.
set -euo pipefail

CLUSTER="${CLUSTER:-minikube}"           # minikube | kind
PROFILE="${PROFILE:-amcart}"             # minikube profile / kind cluster name
OVERLAY="${OVERLAY:-base}"               # base | dast
SECRETS_FILE="${SECRETS_FILE:-$HOME/.config/amcart/secrets.env}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

case "$CLUSTER" in
  minikube) CONTEXT="$PROFILE" ;;
  kind)     CONTEXT="kind-$PROFILE" ;;
  *) echo "CLUSTER must be minikube or kind" >&2; exit 2 ;;
esac
case "$OVERLAY" in
  base) RESOURCE="../../base" ;;
  dast) RESOURCE="../dast" ;;
  *) echo "OVERLAY must be base or dast" >&2; exit 2 ;;
esac

TAG="$(git rev-parse --short=12 HEAD)"
git diff --quiet HEAD -- src || TAG="$TAG-dirty"
kubectl config use-context "$CONTEXT" >/dev/null

echo "==> Building images (tag $TAG)"
docker build -q -t "amcart/user-service:$TAG"    -f src/Services/UserService/Dockerfile src
docker build -q -t "amcart/product-service:$TAG" -f src/Services/ProductService/Dockerfile src
docker build -q -t "amcart/ui:$TAG"              src/Frontends/ui-app

echo "==> Loading images into $CLUSTER ($PROFILE)"
for img in "amcart/user-service:$TAG" "amcart/product-service:$TAG" "amcart/ui:$TAG"; do
  if [ "$CLUSTER" = kind ]; then
    kind load docker-image "$img" --name "$PROFILE" >/dev/null
  elif minikube -p "$PROFILE" image ls | grep -q "${img}$"; then
    echo "    $img already loaded"; continue
  else
    minikube -p "$PROFILE" image load "$img"
  fi
  echo "    $img loaded"
done
# minikube on the VM: reuse the local postgres image (slow network); kind pulls it itself.
if [ "$CLUSTER" = minikube ] && ! minikube -p "$PROFILE" image ls | grep -q 'postgres:16-alpine$'; then
  docker image inspect postgres:16-alpine >/dev/null 2>&1 || docker pull -q postgres:16-alpine
  minikube -p "$PROFILE" image load postgres:16-alpine
fi

echo "==> Runtime secrets"
if [ ! -f "$SECRETS_FILE" ]; then
  mkdir -p "$(dirname "$SECRETS_FILE")"
  ( umask 077
    { echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
      echo "USERS_DB_PASSWORD=$(openssl rand -hex 24)"
      echo "PRODUCTS_DB_PASSWORD=$(openssl rand -hex 24)"
      echo "JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')"
    } > "$SECRETS_FILE" )
  echo "    generated $SECRETS_FILE (mode 600)"
else
  echo "    reusing $SECRETS_FILE"
fi
set -a; . "$SECRETS_FILE"; set +a

kubectl apply -f deploy/k8s/base/namespaces.yaml >/dev/null
PG_HOST=postgres.amcart-databases.svc.cluster.local
apply_secret() {   # namespace name key=value...
  local ns="$1" name="$2"; shift 2
  local args=()
  for kv in "$@"; do args+=("--from-literal=$kv"); done
  kubectl -n "$ns" create secret generic "$name" "${args[@]}" --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null
  echo "    secret $ns/$name applied"
}
apply_secret amcart-databases postgres-credentials \
  "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  "USERS_DB_PASSWORD=$USERS_DB_PASSWORD" \
  "PRODUCTS_DB_PASSWORD=$PRODUCTS_DB_PASSWORD"
apply_secret amcart-services user-service-secret \
  "ConnectionStrings__DefaultConnection=Host=$PG_HOST;Port=5432;Database=amcart_users;Username=users_app;Password=$USERS_DB_PASSWORD" \
  "Jwt__Secret=$JWT_SECRET"
apply_secret amcart-services product-service-secret \
  "ConnectionStrings__DefaultConnection=Host=$PG_HOST;Port=5432;Database=amcart_products;Username=products_app;Password=$PRODUCTS_DB_PASSWORD" \
  "Jwt__Secret=$JWT_SECRET"

echo "==> Applying manifests ($OVERLAY)"
GEN="$ROOT/deploy/k8s/overlays/.generated"   # git-ignored, only pins the image tag
mkdir -p "$GEN"
cat > "$GEN/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - $RESOURCE
images:
  - { name: amcart/user-service,    newTag: "$TAG" }
  - { name: amcart/product-service, newTag: "$TAG" }
  - { name: amcart/ui,              newTag: "$TAG" }
EOF
kubectl apply -k "$GEN"

echo "==> Waiting for rollouts"
kubectl -n amcart-databases rollout status deploy/postgres        --timeout=300s
kubectl -n amcart-services  rollout status deploy/user-service    --timeout=300s
kubectl -n amcart-services  rollout status deploy/product-service --timeout=300s
kubectl -n amcart-web       rollout status deploy/ui              --timeout=300s

echo
echo "Deployed $TAG ($OVERLAY) on $CLUSTER/$PROFILE."
echo "Reach the shop:  kubectl -n amcart-web port-forward --address 0.0.0.0 svc/ui 8080:8080"
