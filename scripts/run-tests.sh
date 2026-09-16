#!/usr/bin/env bash
# Local test runner (used by CI too).
set -o pipefail
cd "$(dirname "$0")/.."
if [ "$1" = "--full" ]; then
  node --test tests/
else
  node --test tests/ 2>&1 | grep -E '^(ok|not ok|# Subtest|# tests|# pass|# fail)|AssertionError|Error:' | head -80
fi
