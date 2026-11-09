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
if [ "$BRANCH" = "main" ]; then
  # la push su main ha gia' avviato la workflow "Release" (trigger push su main)
  echo
  echo "Push su main completata: la workflow 'Release' si sta eseguendo."
  echo "Segui con:"
  echo "  gh run list --workflow release.yml --limit 1"
  echo "  gh run watch"
elif command -v gh >/dev/null 2>&1; then
  echo
  echo "ATTENZIONE: sei su '$BRANCH'. Avvio manuale su main:"
  gh workflow run release.yml --ref main -f version="$VERSION"
  sleep 3
  gh run list --workflow release.yml --limit 1
  echo
  echo "Release v$VERSION avviata su GitHub Actions. Segui con:"
  echo "  gh run watch"
else
  echo "gh non disponibile: avvia a mano la workflow 'Release' su main con version=$VERSION"
fi
