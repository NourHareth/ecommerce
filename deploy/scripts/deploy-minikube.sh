#!/usr/bin/env bash
# Builds the images on this machine, loads them into the minikube "amcart" cluster,
# creates the runtime secrets and applies the manifests.
# Usage (repository root, on the VM): deploy/scripts/deploy-minikube.sh
#
# Secrets (section 4.4): generated once with a CSPRNG into $SECRETS_FILE (mode 600, outside the
# repository), then pushed to the cluster as Kubernetes Secrets. They never appear in Git, in
# an image, or in this script's output.
set -euo pipefail

PROFILE="${PROFILE:-amcart}"
SECRETS_FILE="${SECRETS_FILE:-$HOME/.config/amcart/secrets.env}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TAG="$(git rev-parse --short=12 HEAD)"
git diff --quiet HEAD -- src || TAG="$TAG-dirty"

kubectl config use-context "$PROFILE" >/dev/null

echo "==> Building images (tag $TAG)"
docker build -q -t "amcart/user-service:$TAG"    -f src/Services/UserService/Dockerfile src
docker build -q -t "amcart/product-service:$TAG" -f src/Services/ProductService/Dockerfile src
docker build -q -t "amcart/ui:$TAG"              src/Frontends/ui-app

echo "==> Loading images into minikube profile $PROFILE"
for img in "amcart/user-service:$TAG" "amcart/product-service:$TAG" "amcart/ui:$TAG" postgres:16-alpine; do
  if minikube -p "$PROFILE" image ls | grep -q "${img}$"; then
    echo "    $img already loaded"
  else
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img"
    minikube -p "$PROFILE" image load "$img"
    echo "    $img loaded"
  fi
done

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

echo "==> Applying manifests"
OVERLAY="$ROOT/deploy/k8s/overlays/.generated"   # git-ignored
mkdir -p "$OVERLAY"
cat > "$OVERLAY/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
images:
  - { name: amcart/user-service,    newTag: "$TAG" }
  - { name: amcart/product-service, newTag: "$TAG" }
  - { name: amcart/ui,              newTag: "$TAG" }
EOF
kubectl apply -k "$OVERLAY"

echo "==> Waiting for rollouts"
kubectl -n amcart-databases rollout status deploy/postgres        --timeout=300s
kubectl -n amcart-services  rollout status deploy/user-service    --timeout=300s
kubectl -n amcart-services  rollout status deploy/product-service --timeout=300s
kubectl -n amcart-web       rollout status deploy/ui              --timeout=300s

cat <<EOF

Deployed $TAG. To reach the shop from another machine on the LAN:
  kubectl -n amcart-web port-forward --address 0.0.0.0 svc/ui 8080:8080
  then open http://<VM-IP>:8080
EOF
