#!/bin/bash
# ssh_weak_cipher_scan.sh
# Usage: ./ssh_weak_cipher_scan.sh targets.txt

set -o pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <targets_file>"
    exit 1
fi

TARGETS_FILE="$1"
OUTPUT_DIR="ssh_weak_results"
OUTPUT_FILE="$OUTPUT_DIR/weak_ssh_targets.txt"
TIMEOUT=20

mkdir -p "$OUTPUT_DIR"
> "$OUTPUT_FILE"

if ! command -v ssh-audit >/dev/null 2>&1; then
    echo "Install ssh-audit first:"
    echo "pip install ssh-audit"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "Install jq first:"
    echo "sudo apt install jq"
    exit 1
fi

echo "[*] Starting SSH Weak Cipher Scan..."
echo

while IFS= read -r target || [ -n "$target" ]; do
    target="${target%%[#]*}"
    target="$(echo -n "$target" | xargs)"
    [[ -z "$target" ]] && continue

    echo "----------------------------------------"
    echo "[*] Scanning: $target"

    json_file="$OUTPUT_DIR/${target//[^a-zA-Z0-9._-]/_}.json"

    if command -v timeout >/dev/null 2>&1; then
        timeout "${TIMEOUT}"s ssh-audit -jj "$target" > "$json_file" 2>/dev/null
    else
        ssh-audit -jj "$target" > "$json_file" 2>/dev/null
    fi

    if [ ! -s "$json_file" ]; then
        echo "[-] Failed / no response"
        continue
    fi

    weak=$(jq -r '
      .ciphers[]
      | select(
          (.name | test("cbc|3des|blowfish|arcfour|rc4|des"; "i"))
        )
      | .name
    ' "$json_file" 2>/dev/null)

    if [ -n "$weak" ]; then
        echo "[+] Weak Cipher Found: $target"
        echo "$weak"
        echo "$target" >> "$OUTPUT_FILE"
    else
        echo "[+] Clean"
    fi

    echo
done < "$TARGETS_FILE"

echo "========================================"
echo "[*] Vulnerable Targets:"
if [ -s "$OUTPUT_FILE" ]; then
    cat "$OUTPUT_FILE"
else
    echo "None found."
fi
echo "========================================"
