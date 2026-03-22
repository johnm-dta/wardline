#!/usr/bin/env bash
# CI check: fail if any yaml.load( call lacks a Loader= argument on the same line.
# Excludes .venv/ directories. Accepts any SafeLoader subclass (not just literal SafeLoader).
set -euo pipefail

VIOLATIONS=$(grep -rn 'yaml\.load(' --include='*.py' --exclude-dir='.venv' --exclude-dir='venv' . \
    | grep -v 'Loader=' \
    || true)

if [ -n "$VIOLATIONS" ]; then
    echo "ERROR: Found yaml.load() calls without Loader= argument:"
    echo "$VIOLATIONS"
    echo ""
    echo "Use yaml.load(stream, Loader=SafeLoader) or a SafeLoader subclass."
    echo "Never use bare yaml.load() — it allows arbitrary code execution."
    exit 1
fi

echo "OK: No unsafe yaml.load() calls found."
