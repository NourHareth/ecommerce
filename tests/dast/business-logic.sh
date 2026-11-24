#!/usr/bin/env bash
# Authenticated business-logic checks that a generic scanner cannot perform (it has no notion of
# "whose order is this" or "what is the real price"). Each check is a security regression test:
# PASS means the application behaves safely.
#
#   F2  a customer must not read another customer's order        (expected: 404)
#   F3  the server must ignore a client-supplied unit price      (expected: catalog price)
#
# Needs $OUT_DIR/seed.env from seed.sh. Writes a Markdown report to $OUT_DIR/business-logic.md.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
set -a; . "$OUT_DIR/seed.env"; set +a

REPORT="$OUT_DIR/business-logic.md"
fails=0
row() { echo "| $1 | $2 | $3 | $4 |" >> "$REPORT"; echo "  [$2] $1: $4"; }
{ echo "# DAST business-logic checks"; echo; echo "Target: \`$BASE_URL\` · $(date -u +%FT%TZ)"; echo
  echo "| Check | Result | Expected | Observed |"; echo "|---|---|---|---|"; } > "$REPORT"

echo "== F2 object-level authorization on GET /api/v1/orders/{id}"
own="$(status GET "/api/v1/orders/$ALICE_ORDER_ID" "" -H "$(auth "$ALICE_TOKEN")")"
if [ "$own" = 200 ]; then row "F2 control: owner reads her own order" PASS 200 "$own"
else row "F2 control: owner reads her own order" ERROR 200 "$own"; fails=$((fails+1)); fi

other="$(status GET "/api/v1/orders/$ALICE_ORDER_ID" "" -H "$(auth "$BOB_TOKEN")")"
if [ "$other" = 404 ]; then row "F2 another customer reads it" PASS 404 "$other"
else row "F2 another customer reads it" "FAIL (vulnerable)" 404 "$other"; fails=$((fails+1)); fi

echo "== F3 server-side pricing on POST /api/v1/cart/items"
SID="dast-$(openssl rand -hex 8)"
api POST /api/v1/cart/items "$(jq -n --arg id "$PRODUCT_ID" '{productId:$id, quantity:1, unitPrice:0.01}')" \
  -H "X-Cart-Session-Id: $SID" >/dev/null
charged="$(api GET /api/v1/cart "" -H "X-Cart-Session-Id: $SID" | jq -r --arg id "$PRODUCT_ID" \
  '.data.items[] | select(.productId == $id) | .unitPrice')"
if [ "$(jq -n --arg a "$charged" --arg b "$PRODUCT_PRICE" '($a|tonumber) == ($b|tonumber)')" = true ]; then
  row "F3 client-supplied unitPrice is ignored" PASS "$PRODUCT_PRICE" "$charged"
else
  row "F3 client-supplied unitPrice is ignored" "FAIL (vulnerable)" "$PRODUCT_PRICE" "$charged"; fails=$((fails+1))
fi

echo; echo "business-logic checks: $fails failing"
[ "$fails" -eq 0 ]
