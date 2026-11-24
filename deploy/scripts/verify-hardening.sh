#!/usr/bin/env bash
# Evidence for section 4.5 (run on the VM after deploy.sh and install-kyverno.sh):
#   A. a non-hardened workload is REJECTED at admission (PSA and Kyverno);
#   B. network segmentation blocks forbidden flows and allows the needed ones;
#   C. the application is still reachable end to end after segmentation.
set -uo pipefail

pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
ko()  { echo "  FAIL  $*"; fail=$((fail+1)); }

# expect_rejected <description> <manifest on stdin>
expect_rejected() {
  local out
  if out="$(kubectl apply -f - 2>&1)"; then
    ko "$1 was ADMITTED"; echo "$out" | sed 's/^/        /'
  else
    ok "$1 was rejected"; echo "$out" | grep -oE '(R[0-9] [^.]*\.|violates PodSecurity[^:]*:[^;]*)' | head -6 | sed 's/^/        /'
  fi
}

echo "== A. Admission control =================================================="
expect_rejected "root + privileged pod (blocked by Pod Security Admission)" <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: evil-root, namespace: amcart-web }
spec:
  containers:
    - name: c
      image: nginx:1.29
      securityContext: { privileged: true, runAsUser: 0 }
EOF

expect_rejected "PSA-compliant pod with :latest image, writable root FS, no limits (blocked by Kyverno)" <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: sloppy, namespace: amcart-web }
spec:
  securityContext: { runAsNonRoot: true, runAsUser: 1000, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: busybox:latest
      command: [sleep, "3600"]
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
EOF

expect_rejected "non-hardened Deployment (Kyverno autogen rule)" <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: sloppy-deploy, namespace: amcart-services }
spec:
  selector: { matchLabels: { app: sloppy } }
  template:
    metadata: { labels: { app: sloppy } }
    spec:
      containers: [ { name: c, image: busybox } ]
EOF

# Positive control: the same policies admit a correctly hardened pod.
if kubectl apply -f - >/dev/null 2>&1 <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: hardened-probe, namespace: amcart-web, labels: { app: probe } }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 1000, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: c
      image: busybox:1.37
      command: [sleep, "60"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
      resources: { requests: { memory: 8Mi }, limits: { cpu: 50m, memory: 16Mi } }
EOF
then ok "hardened pod admitted (positive control)"; kubectl -n amcart-web delete pod hardened-probe --wait=false >/dev/null
else ko "hardened pod was refused"; fi

echo
echo "== B. Network segmentation ==============================================="
UI="$(kubectl -n amcart-web get pod -l app=ui -o jsonpath='{.items[0].metadata.name}')"
PG="$(kubectl -n amcart-databases get pod -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
SVC=amcart-services.svc.cluster.local
DB=postgres.amcart-databases.svc.cluster.local

# can <ns> <pod> <host> <port>: TCP connect with a 3 s timeout (busybox nc in both images)
can() { kubectl -n "$1" exec "$2" -- nc -z -w 3 "$3" "$4" >/dev/null 2>&1; }
allowed() { if can "$@"; then ok "$2 -> $3:$4 allowed (needed)"; else ko "$2 -> $3:$4 blocked but needed"; fi; }
denied()  { if can "$@"; then ko "$2 -> $3:$4 OPEN but should be blocked"; else ok "$2 -> $3:$4 blocked"; fi; }

allowed amcart-web       "$UI" "user-service.$SVC"    8080
allowed amcart-web       "$UI" "product-service.$SVC" 8080
denied  amcart-web       "$UI" "$DB"                  5432
denied  amcart-web       "$UI" 1.1.1.1                443
denied  amcart-databases "$PG" "product-service.$SVC" 8080
denied  amcart-databases "$PG" 1.1.1.1                443

echo
echo "== C. Application still reachable after segmentation ====================="
kubectl -n amcart-web port-forward svc/ui 18080:8080 >/dev/null 2>&1 &
pf=$!; trap 'kill $pf 2>/dev/null' EXIT; sleep 3
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code http://127.0.0.1:18080/)" = 200 ]                        && ok "GET / (SPA) = 200"               || ko "GET / failed"
[ "$(code http://127.0.0.1:18080/api/v1/products)" = 200 ]         && ok "GET /api/v1/products = 200 (ui -> product-service -> postgres)" || ko "products API failed"
[ "$(code http://127.0.0.1:18080/health)" = 200 ]                  && ok "GET /health = 200 (ui -> user-service -> postgres)"           || ko "user-service health failed"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
