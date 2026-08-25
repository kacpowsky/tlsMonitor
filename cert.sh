#!/bin/bash
set -euo pipefail

# Resolve paths relative to the script location so it works regardless of CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT="${SCRIPT_DIR}/domains.txt"
TMP_OUTPUT="$(mktemp)"

WARNING_DAYS=15
MAX_RETRIES=3
RETRY_DELAY=2

trap 'rm -f "$TMP_OUTPUT"' EXIT

if ! command -v nmap >/dev/null 2>&1; then
    echo "ERROR: nmap is not installed" >&2
    exit 1
fi

if [[ ! -r "$INPUT" ]]; then
    echo "ERROR: domains file not found: $INPUT" >&2
    exit 1
fi

run_nmap() {
    local domain="$1"
    local attempt=1
    local output

    while (( attempt <= MAX_RETRIES )); do
        output=$(nmap --script ssl-cert -p 443 "$domain" 2>/dev/null || true)

        if echo "$output" | grep -q "Not valid after:"; then
            printf '%s' "$output"
            return 0
        fi

        if (( attempt < MAX_RETRIES )); then
            sleep "$RETRY_DELAY"
        fi

        ((attempt++))
    done

    printf '%s' "$output"
    return 1
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

echo "[" > "$TMP_OUTPUT"
first=true

while IFS= read -r domain || [[ -n "$domain" ]]; do
    domain=$(echo "$domain" | tr -d '[:space:]')
    [[ -z "$domain" ]] && continue

    start=$(date +%s)
    result=$(run_nmap "$domain" || true)
    end=$(date +%s)
    scan_time=$((end - start))

    expiry=$(echo "$result" | awk '/Not valid after:/ {print $5; exit}')

    if [[ -n "$expiry" ]] && expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null); then
        now=$(date +%s)
        days_left=$(( (expiry_epoch - now) / 86400 ))

        if (( days_left < WARNING_DAYS )); then
            status="WARNING"
        else
            status="OK"
        fi
    else
        days_left=-1
        status="ERROR"
        expiry=""
    fi

    [[ "$first" == true ]] || echo "," >> "$TMP_OUTPUT"
    first=false

    cat >> "$TMP_OUTPUT" <<EOF
{
"domain": "$(json_escape "$domain")",
"days_left": $days_left,
"status": "$status",
"scan_time": $scan_time,
"expires": "$(json_escape "$expiry")"
}
EOF

done < "$INPUT"

echo "]" >> "$TMP_OUTPUT"

cat $TMP_OUTPUT

trap - EXIT
