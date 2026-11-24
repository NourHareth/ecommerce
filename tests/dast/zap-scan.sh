#!/usr/bin/env bash
# Authenticated OWASP ZAP API scans of both services, sent through the nginx gateway like real
# traffic, in the disposable DAST environment.
#  - the OpenAPI documents (exposed only in the DAST overlay) tell ZAP every endpoint and parameter;
#  - ZAP_AUTH_HEADER_VALUE adds alice's bearer token to every request (authenticated scan);
#  - policy: any High-risk alert fails the stage (docs/security/03-politique-de-blocage.md).
# Needs $OUT_DIR/seed.env from seed.sh. Reports: $OUT_DIR/{product,user}-zap.{html,json,md}, zap-summary.md
set -uo pipefail
. "$(dirname "$0")/lib.sh"
set -a; . "$OUT_DIR/seed.env"; set +a

ZAP_IMAGE="${ZAP_IMAGE:-zaproxy/zap-stable:2.17.0}"
MAX_MIN="${ZAP_MAX_SCAN_MINUTES:-10}"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"
chmod 777 "$OUT_ABS"   # the ZAP container runs as uid 1000

fetch_spec() {   # service local-port file
  kubectl -n amcart-services port-forward "svc/$1" "$2:8080" >/dev/null 2>&1 &
  local pf=$! rc=1
  for _ in $(seq 1 10); do
    curl -fsS "http://127.0.0.1:$2/swagger/v1/swagger.json" -o "$OUT_ABS/$3" && { rc=0; break; }
    sleep 1
  done
  kill "$pf" 2>/dev/null
  return $rc
}

scan() {         # name spec-file
  echo "==> ZAP API scan: $1"
  docker run --rm --network host -v "$OUT_ABS:/zap/wrk:rw" \
    -e ZAP_AUTH_HEADER_VALUE="Bearer $ALICE_TOKEN" \
    "$ZAP_IMAGE" zap-api-scan.py -t "/zap/wrk/$2" -f openapi -O "$BASE_URL" \
      -J "$1-zap.json" -r "$1-zap.html" -w "$1-zap.md" -I \
      -z "-config scanner.threadPerHost=2 -config scanner.delayInMs=40 -config ascan.maxScanDurationInMins=$MAX_MIN"
  echo "    zap-api-scan exit=$?"
}

fetch_spec product-service 18081 product-openapi.json || { echo "cannot fetch product-service OpenAPI"; exit 3; }
fetch_spec user-service    18082 user-openapi.json    || { echo "cannot fetch user-service OpenAPI"; exit 3; }
scan product product-openapi.json
scan user    user-openapi.json

python3 - "$OUT_ABS" <<'PY'
import json, os, sys
out = sys.argv[1]
risk = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
rows, highs = [], 0
for svc in ("product", "user"):
    path = os.path.join(out, f"{svc}-zap.json")
    if not os.path.exists(path):
        rows.append(f"| {svc} | ERROR | report missing | |"); highs += 1; continue
    for site in json.load(open(path)).get("site", []):
        for a in site.get("alerts", []):
            r = risk.get(a["riskcode"], a["riskcode"])
            highs += r == "High"
            where = sorted({f'{i.get("method","")} {i.get("uri","").split("?")[0]} [{i.get("param","")}]'
                            for i in a.get("instances", [])})[:3]
            rows.append(f'| {svc} | {r} | {a["name"]} (plugin {a["pluginid"]}, CWE-{a.get("cweid","?")}) | {"<br>".join(where)} |')
order = {"ERROR": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
rows.sort(key=lambda r: order.get(r.split("|")[2].strip(), 9))
md = ["# ZAP authenticated API scan", "", f"High-risk alerts: **{highs}** (policy: any High fails the stage)", "",
      "| Service | Risk | Alert | Where (first 3) |", "|---|---|---|---|", *rows]
open(os.path.join(out, "zap-summary.md"), "w").write("\n".join(md) + "\n")
print("\n".join(md))
sys.exit(1 if highs else 0)
PY
