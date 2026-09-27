#!/bin/bash
set -eou pipefail
cd "$(dirname "$0")/.."

command -v libcheck >/dev/null || { echo 'libcheck not found; install it with: go install github.com/nathants/libcheck@latest' >&2; exit 1; }

echo libcheck check
libcheck check

echo libcheck security
libcheck security
