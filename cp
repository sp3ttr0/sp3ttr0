#!/bin/bash
# ssh_weak_cipher_scan.sh
# Usage: ./ssh_weak_cipher_scan.sh <targets_file>
#
# Runs:
#   ssh-audit <target>
#
# Prints output to terminal
# Saves each target full output to:
#   ssh_weak_results/<target>_sshaudit.txt
#
# Saves ONLY vulnerable targets (weak ciphers found) to:
#   ssh_weak_results/weak_ssh_targets.txt

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

if [ ! -f "$TARGETS_FILE" ]; then
    echo "Error: '$TARGETS_FILE' not found!"
    exit 1
fi

if ! command -v ssh-audit >/dev/null 2>&1; then
    echo "Error: ssh-audit not installed."
    echo "Install with: pip install ssh-audit"
    exit 1
fi

echo "[*] Starting SSH Weak Cipher Scan..."
echo "[*] Targets file: $TARGETS_FILE"
echo ""

while IFS= read -r target || [ -n "$target" ]; do
    # remove comments / trim
    target="${target%%[#]*}"
    target="$(echo -n "$target" | xargs)"
    [[ -z "$target" ]] && continue

    safe_target="$(echo "$target" | sed -E 's/[:\/\\]/_/g')"
    out_file="$OUTPUT_DIR/${safe_target}_sshaudit.txt"

    echo "------------------------------------------------------------"
    echo "[*] Scanning: $target"
    echo "[*] Output file: $out_file"
    echo "------------------------------------------------------------"

    if command -v timeout >/dev/null 2>&1; then
        output="$(timeout "${SSH_TIMEOUT}"s ssh-audit "$target" 2>&1 || true)"
        retcode=$?
    else
        output="$(ssh-audit "$target" 2>&1 || true)"
        retcode=0
    fi

    echo "$output"
    printf "%s\n" "$output" > "$out_file"

    # Detect failures
    if echo "$output" | grep -qiE "connection refused|timed out|could not resolve|no route to host|failed to connect|name or service not known"; then
        echo "[-] Failed: $target"
        echo "[-] See $out_file for details."

    # Detect weak SSH ciphers / algorithms
    elif echo "$output" | grep -qiE "3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|blowfish-cbc|cast128-cbc|arcfour|rc4|des-cbc|cbc \(weak\)|weak cipher|legacy cipher"; then
        echo "[+] Weak Cipher Found: $target"
        echo "$target" >> "$OUTPUT_FILE"
        echo "[+] Full output saved to $out_file"

    else
        echo "[+] Clean: $target"
        echo "[+] No weak ciphers detected."
    fi

    echo ""
done < "$TARGETS_FILE"

echo "[*] Scan complete."
echo ""
echo "[*] Vulnerable targets saved in: $OUTPUT_FILE"
echo "---------------------------------------------"

if [ -s "$OUTPUT_FILE" ]; then
    cat "$OUTPUT_FILE"
else
    echo "No vulnerable targets found."
fi

echo ""
echo "[*] Per-target outputs saved under: $OUTPUT_DIR/"
echo "[*] Done."
