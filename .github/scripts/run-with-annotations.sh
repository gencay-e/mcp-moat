#!/usr/bin/env bash
# Usage: run-with-annotations.sh <title> <command...>
# Runs the command. On failure, prints the failing lines as one error annotation
# so they show up in the check-run annotations as well as in the log.
set -o pipefail
title="$1"
shift
log="$(mktemp)"
if "$@" 2>&1 | tee "$log"; then
  exit 0
fi
msg="$(grep -E '^test .* FAILED|panicked at|^error|^warning: unused|^ *--> ' -A2 "$log" | head -80 | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
echo "::error title=${title} failed::${msg}"
exit 1
