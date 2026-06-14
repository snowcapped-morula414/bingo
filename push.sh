#!/bin/bash
# push.sh — bingo v2.1.0 release helper
# Usage: bash push.sh [commit message]
#
# Quick-push local changes to origin/main.
# Stages all tracked files, commits with optional message, then pushes.

set -e

cd "$(dirname "$0")"

MSG="${1:-chore: update}"

echo "▶ Staging all changes..."
git add -u

echo "▶ Committing: $MSG"
git commit -m "$MSG" || echo "(nothing to commit)"

echo "▶ Pushing to origin/main..."
git push origin main

echo "✅ Done."
