# Shared helpers for the DAST scripts (sourced, not executed).
# Targets ONLY our own disposable test deployment (cahier §6): BASE_URL defaults to a local port-forward.

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
OUT_DIR="${OUT_DIR:-./dast-out}"
mkdir -p "$OUT_DIR"

# Hide a value from GitHub Actions logs (no-op elsewhere).
mask() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$1" || true; }

# api METHOD PATH [JSON] [extra curl args...] -> prints the body; on HTTP >= 400 prints the status
# and the API's error message to stderr and fails.
api() {
  local method="$1" path="$2" body="${3:-}"; shift 3 2>/dev/null || shift $#
  local args=(-sS -X "$method" "$BASE_URL$path" -H 'Content-Type: application/json' -w '\n%{http_code}')
  [ -n "$body" ] && args+=(-d "$body")
  local resp code
  resp="$(curl "${args[@]}" "$@")" || return 1
  code="${resp##*$'\n'}"; resp="${resp%$'\n'*}"
  if [ "$code" -ge 400 ]; then
    echo "HTTP $code on $method $path: $(jq -c '.error // .' <<<"$resp" 2>/dev/null | head -c 300)" >&2
    return 1
  fi
  printf '%s' "$resp"
}

# status METHOD PATH [JSON] [extra curl args...] -> prints only the HTTP status code
status() {
  local method="$1" path="$2" body="${3:-}"; shift 3 2>/dev/null || shift $#
  local args=(-sS -o /dev/null -w '%{http_code}' -X "$method" "$BASE_URL$path" -H 'Content-Type: application/json')
  [ -n "$body" ] && args+=(-d "$body")
  curl "${args[@]}" "$@"
}

auth() { echo "Authorization: Bearer $1"; }
