#!/usr/bin/env bash
# Creates the test data for the DAST stage in a DISPOSABLE environment:
#   - one admin, two customers (alice, bob) with random passwords generated per run;
#   - one active product;
#   - one order placed by alice.
# Ids and tokens are written to $OUT_DIR/seed.env for the next steps (never committed).
#
# Email verification and the admin role cannot be set through the public API, so they are set
# directly in the database of the test cluster (kubectl exec into PostgreSQL).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

RUN="$(date +%s)"
newpw() { echo "$(openssl rand -hex 12)Aa1!"; }

register() {   # email password first
  api POST /api/v1/auth/register "$(jq -n --arg e "$1" --arg p "$2" --arg f "$3" \
    '{firstName:$f, lastName:"Dast", email:$e, password:$p, confirmPassword:$p, phone:"+21650000000"}')" >/dev/null
}
login() {      # email password -> access token
  api POST /api/v1/auth/login "$(jq -n --arg e "$1" --arg p "$2" '{email:$e, password:$p}')" \
    | jq -er '.data.tokens.accessToken'
}

ADMIN_EMAIL="dast-admin-$RUN@example.test"; ADMIN_PW="$(newpw)"
ALICE_EMAIL="dast-alice-$RUN@example.test"; ALICE_PW="$(newpw)"
BOB_EMAIL="dast-bob-$RUN@example.test";     BOB_PW="$(newpw)"
for v in "$ADMIN_PW" "$ALICE_PW" "$BOB_PW"; do mask "$v"; done

echo "==> Registering test accounts"
register "$ADMIN_EMAIL" "$ADMIN_PW" Admin
register "$ALICE_EMAIL" "$ALICE_PW" Alice
register "$BOB_EMAIL"   "$BOB_PW"   Bob

echo "==> Verifying emails and promoting the admin (test database only)"
kubectl -n amcart-databases exec deploy/postgres -- psql -q -v ON_ERROR_STOP=1 -U postgres -d amcart_users -c \
  "UPDATE users SET is_email_verified = true WHERE email IN ('$ADMIN_EMAIL','$ALICE_EMAIL','$BOB_EMAIL');
   UPDATE users SET role = 'admin' WHERE email = '$ADMIN_EMAIL';"

ADMIN_TOKEN="$(login "$ADMIN_EMAIL" "$ADMIN_PW")"; mask "$ADMIN_TOKEN"
ALICE_TOKEN="$(login "$ALICE_EMAIL" "$ALICE_PW")"; mask "$ALICE_TOKEN"
BOB_TOKEN="$(login "$BOB_EMAIL" "$BOB_PW")";       mask "$BOB_TOKEN"

echo "==> Creating a product"
PRODUCT_PRICE="49.99"
PRODUCT_ID="$(api POST /api/v1/products "$(jq -n --arg s "DAST-$RUN" --argjson p "$PRODUCT_PRICE" \
  '{name:("DAST test shirt " + $s), sku:$s, price:$p, quantity:100, trackInventory:true, status:"active"}')" \
  -H "$(auth "$ADMIN_TOKEN")" | jq -er '.data.id')"

echo "==> Alice orders it"
api POST /api/v1/cart/items "$(jq -n --arg id "$PRODUCT_ID" '{productId:$id, quantity:1}')" \
  -H "$(auth "$ALICE_TOKEN")" >/dev/null
ADDRESS='{"firstName":"Alice","lastName":"Dast","country":"TN","street":"1 Test Street","apartment":"A1",
          "city":"Tunis","state":"Tunis","zip":"1000","phone":"+21650000001","email":"alice@example.test"}'
ALICE_ORDER_ID="$(api POST /api/v1/checkout/orders \
  "$(jq -n --argjson a "$ADDRESS" '{billing:$a, sameAsBilling:true, paymentMethod:"PayPal"}')" \
  -H "$(auth "$ALICE_TOKEN")" | jq -er '.data.orderId')"

umask 077
cat > "$OUT_DIR/seed.env" <<EOF
ADMIN_TOKEN=$ADMIN_TOKEN
ALICE_TOKEN=$ALICE_TOKEN
BOB_TOKEN=$BOB_TOKEN
PRODUCT_ID=$PRODUCT_ID
PRODUCT_PRICE=$PRODUCT_PRICE
ALICE_ORDER_ID=$ALICE_ORDER_ID
EOF
echo "Seed done: product $PRODUCT_ID, alice's order $ALICE_ORDER_ID"
