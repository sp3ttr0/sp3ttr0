#!/bin/bash
# unauth_rpc_scan.sh
# Usage: ./unauth_rpc_scan.sh <targets_file>
# Runs `rpcclient -U "" -N <target> -c 'enumprivs'`, prints output to terminal,
# saves each target's full output to unauth_rpc_results/<target>_rpcclient.txt,
# and writes successful targets to unauth_rpc_results/unauth_rpc_vuln_targets.txt

set -o errexit
set -o nounset
set -o pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <targets_file>"
    exit 1
fi

TARGETS_FILE="$1"
OUTPUT_DIR="unauth_rpc_results"
OUTPUT_FILE="$OUTPUT_DIR/unauth_rpc_vuln_targets.txt"
RPC_TIMEOUT=15   # seconds - prevents hanging on slow/unresponsive hosts

# Prepare output directory and file
mkdir -p "$OUTPUT_DIR"
> "$OUTPUT_FILE"

if [ ! -f "$TARGETS_FILE" ]; then
    echo "Error: '$TARGETS_FILE' not found!"
    exit 1
fi

echo "[*] Starting Unauthenticated RPC scan on targets from '$TARGETS_FILE'..."
echo ""

while IFS= read -r target || [ -n "$target" ]; do
    # Remove inline comments and trim whitespace
    target="${target%%[#]*}"   # remove inline comments starting with #
    target="$(echo -n "$target" | xargs)"  # trim leading/trailing whitespace
    [[ -z "$target" ]] && continue

    # sanitize filename (replace slashes/colons with _)
    safe_target="$(echo "$target" | sed -E 's/[:\/\\]/_/g')"
    out_file="$OUTPUT_DIR/${safe_target}_rpcclient.txt"

    echo "------------------------------------------------------------"
    echo "[*] Scanning: $target"
    echo "[*] Output file: $out_file"
    echo "------------------------------------------------------------"

    # Run rpcclient with a timeout so the script doesn't hang indefinitely.
    # Capture stdout+stderr so we can both print it and save it.
    if command -v timeout >/dev/null 2>&1; then
        output="$(timeout "${RPC_TIMEOUT}"s rpcclient -U "" -N "$target" -c 'enumprivs' 2>&1 || true)"
        retcode=$?
    else
        output="$(rpcclient -U "" -N "$target" -c 'enumprivs' 2>&1 || true)"
        retcode=0
    fi

    # Print the raw output to terminal and save to per-target file
    echo "$output"
    printf "%s\n" "$output" > "$out_file"

    # Determine success/failure based on actual enumprivs output
    if echo "$output" | grep -qiE "Cannot connect|NT_STATUS|failed|Connection to host failed|refused|No route to host|Could not initialise lsarpc|ERRSRV|ERRDOS|LSA.*failed|OpenPolicy.*failed"; then
        echo "[-] Failed: $target"
        echo "[-] See $out_file for details."
    elif echo "$output" | grep -qiE "Se[A-Za-z]+Privilege|Privilege"; then
        echo "[+] Success: $target"
        echo "$target" >> "$OUTPUT_FILE"
        echo "[+] Full output saved to $out_file"
    else
        echo "[-] Failed (No privileges returned): $target"
        echo "[-] See $out_file for details."
    fi

    echo ""
done < "$TARGETS_FILE"

echo "[*] Scan complete."
echo ""
echo "[*] Successful targets with enumprivs enabled (saved in $OUTPUT_FILE):"
echo "---------------------------------------------"

if [ -s "$OUTPUT_FILE" ]; then
    cat "$OUTPUT_FILE"
else
    echo "No successful targets found."
fi

echo ""
echo "[*] Per-target outputs saved under: $OUTPUT_DIR/"
echo "[*] Done."
