#!/usr/bin/env bash
# Nuova release: fa fare TUTTO a GitHub Actions.
#
#   ./scripts/release.sh 1.1.0
#
# Aggiorna VERSION, committa, pusha e avvia la workflow "Release", che:
# compila l'APK, lo verifica, genera l'SBOM, lo attesta e pubblica la release
# (eliminando le versioni precedenti: una sola release online).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "uso: $0 <versione>    es: $0 1.1.0"; exit 1
fi
cd "$ROOT"

echo "$VERSION" > VERSION
git add VERSION
git commit -m "release: v$VERSION" || echo "(nessuna modifica da committare)"
git push origin HEAD

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" != "main" ]; then
  echo
  echo "ATTENZIONE: sei su '$BRANCH'. La release verra' costruita da questo branch,"
  echo "ma la workflow 'Release' deve esistere su main per poter essere avviata."
fi

if command -v gh >/dev/null 2>&1; then
  gh workflow run release.yml --ref "$BRANCH" -f version="$VERSION"
  sleep 3
  gh run list --workflow release.yml --limit 1
  echo
  echo "Release v$VERSION avviata su GitHub Actions. Segui con:"
  echo "  gh run watch"
else
  echo "gh non disponibile: avvia a mano la workflow 'Release' da GitHub con version=$VERSION"
fi
