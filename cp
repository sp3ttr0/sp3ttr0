#!/bin/bash
# ssh_weak_cipher_scan.sh
# Usage: ./ssh_weak_cipher_scan.sh targets.txt

set -o errexit
set -o nounset
set -o pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <targets_file>"
    exit 1
fi

TARGETS_FILE="$1"
OUTPUT_DIR="ssh_weak_results"
OUTPUT_FILE="$OUTPUT_DIR/weak_ssh_targets.txt"
SSH_TIMEOUT=20

mkdir -p "$OUTPUT_DIR"
> "$OUTPUT_FILE"

if ! command -v ssh-audit >/dev/null 2>&1; then
    echo "Install ssh-audit first:"
    echo "pip install ssh-audit"
    exit 1
fi

echo "[*] Starting SSH Weak Cipher Scan..."
echo

while IFS= read -r target || [ -n "$target" ]; do
    target="${target%%[#]*}"
    target="$(echo -n "$target" | xargs)"
    [[ -z "$target" ]] && continue

    safe_target="$(echo "$target" | sed -E 's/[:\/\\]/_/g')"
    out_file="$OUTPUT_DIR/${safe_target}_sshaudit.txt"

    echo "------------------------------------------------"
    echo "[*] Scanning: $target"
    echo "------------------------------------------------"

    if command -v timeout >/dev/null 2>&1; then
        output="$(timeout "${SSH_TIMEOUT}"s ssh-audit "$target" 2>&1 || true)"
    else
        output="$(ssh-audit "$target" 2>&1 || true)"
    fi

    printf "%s\n" "$output" > "$out_file"
    echo "$output"

    # Detect connection failures
    if echo "$output" | grep -qiE "connection refused|timed out|could not resolve|no route to host|failed"; then
        echo "[-] Failed: $target"
        echo
        continue
    fi

    # ONLY check cipher lines explicitly flagged by ssh-audit
    weak_found=$(echo "$output" | grep -Ei '^\s*\(enc\).*fail|^\s*\(enc\).*warn')

    if [ -n "$weak_found" ]; then
        echo "[+] Weak SSH Cipher Found: $target"
        echo "$target" >> "$OUTPUT_FILE"
    else
        echo "[+] Clean: $target"
    fi

    echo
done < "$TARGETS_FILE"

echo "[*] Scan complete."
echo "[*] Vulnerable targets list: $OUTPUT_FILE"

if [ -s "$OUTPUT_FILE" ]; then
    cat "$OUTPUT_FILE"
else
    echo "No weak SSH cipher targets found."
fi
