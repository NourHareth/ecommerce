#!/usr/bin/env bash
# Authenticated OWASP ZAP API scans of both services, sent through the nginx gateway like real
# traffic, in the disposable DAST environment.
#  - the OpenAPI documents (exposed only in the DAST overlay) tell ZAP every endpoint and parameter;
#  - ZAP_AUTH_HEADER_VALUE adds alice's bearer token to every request (authenticated scan);
#  - policy (docs/security/03-politique-de-blocage.md): a High-risk finding fails the stage when it
#    has evidence. SQL-injection findings based ONLY on page-comparison inference (boolean or
#    arithmetic payloads, no error, no timing, empty evidence) are reported for triage but do not
#    block: on this JSON API they are false positives (responses vary between requests, model
#    validation rejects both variants alike). See EXC-002.
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
SQLI = "40018"   # ZAP "SQL Injection" (error-based, boolean-based, UNION...)

def inference_only(alert, inst):
    """SQLi instance inferred only by comparing pages (boolean conditions such as `AND 1=1` vs
    `AND 1=2`, or arithmetic expressions such as `22-2` vs `20`): no database error, no timing,
    empty evidence. Error-based findings carry evidence (e.g. "HTTP/1.1 500") and stay blocking."""
    return alert["pluginid"] == SQLI and not (inst.get("evidence") or "").strip()

blocking, triage, other = [], [], []
for svc in ("product", "user"):
    path = os.path.join(out, f"{svc}-zap.json")
    if not os.path.exists(path):
        blocking.append(f"| {svc} | report missing | | |"); continue
    for site in json.load(open(path)).get("site", []):
        for a in site.get("alerts", []):
            r = risk.get(a["riskcode"], a["riskcode"])
            title = f'{a["name"]} (plugin {a["pluginid"]}, CWE-{a.get("cweid","?")})'
            for i in a.get("instances", []):
                where = f'{i.get("method","")} {i.get("uri","").split("?")[0].replace(os.environ.get("BASE_URL",""),"")} [{i.get("param","")}]'
                row = f'| {svc} | {title} | `{where}` | {(i.get("evidence") or "").strip()[:60]} |'
                if r != "High":
                    other.append((r, svc, a["name"]))
                elif inference_only(a, i):
                    triage.append(row)
                else:
                    blocking.append(row)

counts = {}
for r, svc, name in other:
    counts[(r, svc, name)] = counts.get((r, svc, name), 0) + 1
md = ["# ZAP authenticated API scan", "",
      f"**Blocking High findings: {len(blocking)}** (High risk with evidence: error, timing, confirmed payload)", "",
      "| Service | Alert | Where | Evidence |", "|---|---|---|---|", *(blocking or ["| — | none | | |"]), "",
      f"## High, SQLi by inference only (no evidence): {len(triage)} instance(s), triage (EXC-002, not blocking)", "",
      "Endpoints using EF Core LINQ only (parameterized). Kept for review, see docs/security/04-registre-des-exceptions.md.", "",
      "<details><summary>show</summary>", "", "| Service | Alert | Where | Evidence |", "|---|---|---|---|", *triage, "", "</details>", "",
      "## Medium / Low / Info (not blocking)", "", "| Risk | Service | Alert | Instances |", "|---|---|---|---|",
      *[f"| {r} | {s} | {n} | {c} |" for (r, s, n), c in sorted(counts.items(), key=lambda kv: ["High","Medium","Low","Info"].index(kv[0][0]))]]
open(os.path.join(out, "zap-summary.md"), "w").write("\n".join(md) + "\n")
print("\n".join(md[:8 + len(blocking)]))
print(f"\n{len(triage)} inference-only SQLi instance(s) sent to triage; {len(other)} lower-risk instance(s).")
sys.exit(1 if blocking else 0)
PY
