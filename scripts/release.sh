#!/usr/bin/env bash
# Nuova release: incrementa VERSION, tagga, pusha -> la CI compila e pubblica l'APK.
#   ./scripts/release.sh 1.1.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$1"
if [ -z "${VERSION:-}" ]; then
  echo "uso: $0 <versione>   es: $0 1.1.0"; exit 1
fi

cd "$ROOT"
echo "$VERSION" > VERSION
git add VERSION app tools build.sh scripts .github README.md
git commit -m "release: v$VERSION"
git tag -a "v$VERSION" -m "SpyDetector v$VERSION"
git push origin HEAD
git push origin "v$VERSION"
echo "Tag v$VERSION inviato: la GitHub Action compilera' e pubblichera' l'APK."
