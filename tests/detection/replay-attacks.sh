#!/usr/bin/env bash
# Section 4.7, "une attaque rejouée apparaît dans les journaux et déclenche le plan de réponse".
#
# Replays three attacks against OUR OWN test deployment (cahier §6), then checks the whole chain:
#   request -> structured log line with a correlation ID -> Loki -> detection rule -> alert FIRING.
#
#   A. injection patterns on the product search          -> AmcartInjectionAttempt
#   B. a customer asks for orders that are not theirs    -> AmcartOrderEnumeration
#   C. repeated failed sign-ins on one account           -> AmcartLoginBruteForce
#
# It also checks that the attack values themselves (payloads, e-mail, token) are NOT in the logs.
# Output: $OUT_DIR/detection-replay.md (evidence). Exit code 0 only if every check passes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export OUT_DIR="${OUT_DIR:-$HERE/out}"
. "$HERE/../dast/lib.sh"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:3100}"
ALERT_TIMEOUT="${ALERT_TIMEOUT:-240}"
REPORT="$OUT_DIR/detection-replay.md"
RUN="$(date +%s)"
FAILED=0

PF_PIDS=()
cleanup() { for p in "${PF_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
forward() {   # namespace service port health-url
  curl -fsS -o /dev/null "$4" 2>/dev/null && return 0
  kubectl -n "$1" port-forward "svc/$2" "$3:$3" >/dev/null 2>&1 & PF_PIDS+=($!)
  for _ in $(seq 1 30); do curl -fsS -o /dev/null "$4" 2>/dev/null && return 0; sleep 1; done
  echo "cannot reach $2 on port $3" >&2; exit 1
}
forward amcart-web ui 8080 "$BASE_URL/healthz"
forward amcart-monitoring loki 3100 "$LOKI_URL/ready"

check() {   # description condition-result(0/1)
  if [ "$2" = 0 ]; then echo "| PASS | $1 |" >> "$REPORT"; echo "  PASS  $1"
  else echo "| **FAIL** | $1 |" >> "$REPORT"; echo "  FAIL  $1"; FAILED=1; fi
}
# send METHOD PATH [curl args...] -> "status correlation-id"
send() {
  curl -sS -o /dev/null -D - -X "$1" "$BASE_URL$2" "${@:3}" \
    | tr -d '\r' | awk 'tolower($1) ~ /^http\// {s=$2} tolower($1) == "x-correlation-id:" {c=$2} END {print s, c}'
}
loki_lines() {   # LogQL -> number of matching lines since the start of this run
  curl -fsS -G "$LOKI_URL/loki/api/v1/query_range" --data-urlencode "query=$1" \
    --data-urlencode "start=$START_NS" --data-urlencode "limit=5000" \
    | jq '[.data.result[].values | length] | add // 0'
}

echo "==> Test data (seed.sh: random accounts, one order placed by alice)"
"$HERE/../dast/seed.sh" >/dev/null
. "$OUT_DIR/seed.env"
START_NS="$(( $(date +%s) - 5 ))000000000"

{
  echo "# Rejeu d'attaques et détection ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo
  echo "Cible : déploiement de test (minikube, VM). Démarrage du rejeu : run $RUN."
  echo
} > "$REPORT"

echo "==> A. Injection patterns on the product search"
declare -a A_CIDS=()
echo "## A. Tentative d'injection (recherche produit)" >> "$REPORT"
echo >> "$REPORT"; echo "| Requête | Statut | Correlation ID |" >> "$REPORT"; echo "|---|---|---|" >> "$REPORT"
i=0
for payload in "' OR '1'='1" "x' UNION SELECT 1--" "<script>alert(1)</script>"; do
  i=$((i + 1))
  read -r st cid < <(send GET /api/v1/products/quick-search -G --data-urlencode "q=$payload")
  A_CIDS+=("$cid"); echo "    request $i -> HTTP $st, correlation $cid"
  echo "| A$i (motif $i) | $st | \`$cid\` |" >> "$REPORT"
done

echo "==> B. Bob asks for alice's order, then for 5 random order ids"
B_CID=""
read -r st B_CID < <(send GET "/api/v1/orders/$ALICE_ORDER_ID" -H "$(auth "$BOB_TOKEN")")
echo "    alice's order as bob -> HTTP $st (correlation $B_CID)"
B_STATUSES="$st"
for _ in 1 2 3 4 5; do
  read -r st _cid < <(send GET "/api/v1/orders/$(cat /proc/sys/kernel/random/uuid)" -H "$(auth "$BOB_TOKEN")")
  B_STATUSES="$B_STATUSES $st"
done
{ echo; echo "## B. Énumération de commandes"; echo
  echo "Bob demande la commande d'Alice puis 5 identifiants aléatoires. Statuts : \`$B_STATUSES\`."
  echo "Correlation ID de la première requête : \`$B_CID\`."; } >> "$REPORT"

echo "==> C. 12 failed sign-ins on one account"
VICTIM="replay-victim-$RUN@example.test"
C_STATUSES=""
for _ in $(seq 1 12); do
  read -r st _cid < <(send POST /api/v1/auth/login -H 'Content-Type: application/json' \
    -d "$(jq -n --arg e "$VICTIM" --arg p "wrong-$(openssl rand -hex 4)" '{email:$e, password:$p}')")
  C_STATUSES="$C_STATUSES $st"; sleep 0.3   # stay under nginx's sign-in rate limit
done
{ echo; echo "## C. Force brute sur un compte"; echo
  echo "12 connexions avec un mauvais mot de passe sur le même compte. Statuts :\`$C_STATUSES\`."; } >> "$REPORT"

echo "==> Checks"
{ echo; echo "## Vérifications"; echo; echo "| Résultat | Vérification |"; echo "|---|---|"; } >> "$REPORT"

all404=0; for s in $B_STATUSES; do [ "$s" = 404 ] || all404=1; done
check "B: every foreign order lookup answered 404, F2 fix holds (got:$B_STATUSES)" "$all404"

# 1. The same correlation ID is in the gateway's line AND the service's lines (end-to-end tracing).
cid="${A_CIDS[0]}"
gw=0; svc=0
for _ in $(seq 1 30); do
  gw="$(loki_lines "{namespace=\"amcart-web\", app=\"ui\"} |= \"$cid\"")"
  svc="$(loki_lines "{namespace=\"amcart-services\", app=\"product-service\"} |= \"$cid\"")"
  [ "$gw" -ge 1 ] && [ "$svc" -ge 2 ] && break; sleep 2
done
check "A1: correlation ID \`$cid\` found in the gateway log ($gw line) and the product-service log ($svc lines: request + security event)" \
  "$([ "$gw" -ge 1 ] && [ "$svc" -ge 2 ] && echo 0 || echo 1)"
n="$(loki_lines "{namespace=\"amcart-services\"} |= \"security.injection_attempt\" | json | State_Event=\"security.injection_attempt\"")"
check "A: $n injection_attempt events recorded (expected 3)" "$([ "$n" -ge 3 ] && echo 0 || echo 1)"
n="$(loki_lines "{namespace=\"amcart-services\"} |= \"$B_CID\" |= \"security.access_denied\"")"
check "B: access_denied event carries the correlation ID of bob's request" "$([ "$n" -ge 1 ] && echo 0 || echo 1)"
n="$(loki_lines "{namespace=\"amcart-services\", app=\"user-service\"} |= \"security.auth_failed\" | json | State_Event=\"security.auth_failed\"")"
check "C: $n auth_failed events recorded (expected 12)" "$([ "$n" -ge 12 ] && echo 0 || echo 1)"

# 2. No sensitive value in ANY log line of the run (gateway, services, database).
leak=0
for needle in "UNION SELECT" "<script>" "OR '1'='1" "$VICTIM" "${BOB_TOKEN:0:24}"; do
  c="$(loki_lines "{namespace=~\"amcart-.+\"} |= \"$(printf '%s' "$needle" | sed 's/\\/\\\\/g; s/"/\\"/g')\"")"
  [ "$c" = 0 ] || { leak=1; echo "    found in logs: a value that must not be logged (${#needle} chars)"; }
done
check "No payload, e-mail address or token in the logs (5 values searched in every AmCart namespace)" "$leak"

# 3. The detection rules fire.
echo "    waiting for the alerts (rules evaluated every 15 s, up to ${ALERT_TIMEOUT}s)..."
want="AmcartInjectionAttempt AmcartOrderEnumeration AmcartLoginBruteForce"
deadline=$(( $(date +%s) + ALERT_TIMEOUT ))
while :; do
  alerts="$(curl -fsS "$LOKI_URL/prometheus/api/v1/alerts")"
  missing=""
  for a in $want; do
    jq -e --arg a "$a" '.data.alerts[] | select(.labels.alertname == $a and .state == "firing")' <<<"$alerts" >/dev/null || missing="$missing $a"
  done
  [ -z "$missing" ] && break
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 5
done
for a in $want; do
  line="$(jq -r --arg a "$a" '[.data.alerts[] | select(.labels.alertname == $a)][0]
    | if . == null then "absent" else "\(.state) since \(.activeAt) (severity \(.labels.severity), value \(.value))" end' <<<"$alerts")"
  check "Alert $a: $line" "$([[ "$line" == firing* ]] && echo 0 || echo 1)"
done

{ echo; echo "## Suite"; echo
  echo "Une alerte qui passe à *firing* déclenche le plan de réponse :"
  echo "\`docs/security/06-plan-reponse-incident.md\` (un scénario par règle, lien \`runbook_url\` dans l'alerte)."; } >> "$REPORT"

echo
echo "Report: $REPORT"
[ "$FAILED" = 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
