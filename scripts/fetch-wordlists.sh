#!/usr/bin/env bash
#
# fetch-wordlists.sh - download a minimal, open-source SecLists subset used by
# APIStrike for endpoint/parameter discovery. SecLists is MIT-licensed and is
# NOT vendored into this repo; run this script to populate ./wordlists/
# (which is git-ignored).
#
# Usage:
#   ./scripts/fetch-wordlists.sh [DEST_DIR]
#
# Env:
#   SECLISTS_REF   git ref to fetch (default: master)
#
set -euo pipefail

DEST="${1:-wordlists}"
REPO="https://github.com/danielmiessler/SecLists.git"
REF="${SECLISTS_REF:-master}"

# Just the files we actually use (keeps this tiny vs the full ~1GB repo).
PATHS=(
  "Discovery/Web-Content/api/api-endpoints.txt"
  "Discovery/Web-Content/api/api-endpoints-res.txt"
  "Discovery/Web-Content/api/objects.txt"
  "Discovery/Web-Content/common-api-endpoints-mazen160.txt"
  "Discovery/Web-Content/swagger.txt"
)

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 1
fi

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

echo "[*] Sparse-cloning SecLists (${REF}) ..."
git clone --depth 1 --filter=blob:none --sparse --branch "$REF" "$REPO" "$tmp/seclists"
(
  cd "$tmp/seclists"
  git sparse-checkout init --no-cone
  git sparse-checkout set "${PATHS[@]}"
)

mkdir -p "$DEST"
count=0
for p in "${PATHS[@]}"; do
  src="$tmp/seclists/$p"
  if [ -f "$src" ]; then
    cp "$src" "$DEST/$(basename "$p")"
    echo "  + $DEST/$(basename "$p")"
    count=$((count + 1))
  else
    echo "  ! not found in SecLists@${REF}: $p" >&2
  fi
done

echo "[*] Done. Copied ${count} wordlist(s) into: ${DEST}/"
echo "    SecLists is MIT-licensed (https://github.com/danielmiessler/SecLists)."
