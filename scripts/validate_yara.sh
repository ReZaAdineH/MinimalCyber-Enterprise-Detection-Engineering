#!/usr/bin/env bash
set -euo pipefail

if ! command -v yara >/dev/null 2>&1; then
  echo "yara command not found. Install YARA first."
  exit 1
fi

find rules -name "*.yar" -print0 | while IFS= read -r -d '' rule; do
  echo "Validating $rule"
  yara "$rule" /dev/null >/dev/null || exit 1
done

echo "All YARA rules validated."
