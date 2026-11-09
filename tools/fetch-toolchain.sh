#!/usr/bin/env bash
# SpyDetector — toolchain fetch (versioni pinnate + SHA256 verificato)
#
# Scarica JDK 21, aapt2, d8, ecj, apksigner e android.jar SOLO da registry
# pubblici (npm/PyPI), verificando l'hash di ogni artefatto prima di usarlo.
# Le versioni e i digest stanno in tools/toolchain.env, generato e validato da
# scripts/update-toolchain.py (aggiornato dalla CI ogni giorno).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="$ROOT/.toolchain"
ENVF="$ROOT/tools/toolchain.env"
CACHE="${SPD_CACHE_DIR:-$TC/cache}"

# shellcheck disable=SC1090
[ -f "$ENVF" ] && . "$ENVF"
mkdir -p "$TC/bin" "$TC/lib" "$CACHE"

sha() { sha256sum "$1" | cut -d' ' -f1; }

# download(url, dest, sha256_atteso)
download() {
  local url="$1" dest="$2" want="$3"
  if [ -f "$dest" ] && [ -n "$want" ] && [ "$(sha "$dest")" = "$want" ]; then
    echo "    cache ok: $(basename "$dest")"
    return 0
  fi
  echo "    scarico $(basename "$dest")"
  curl -sSL --retry 3 --fail -o "$dest.part" "$url"
  if [ -n "$want" ]; then
    local got; got="$(sha "$dest.part")"
    if [ "$got" != "$want" ]; then
      echo "    ERRORE: SHA256 di $(basename "$dest") non corrisponde" >&2
      echo "      atteso: $want" >&2
      echo "      ottenuto: $got" >&2
      rm -f "$dest.part"; return 1
    fi
  fi
  mv "$dest.part" "$dest"
}

echo "==> [1/4] JDK 21 portabile (jdk4py ${JDK4PY_VERSION:-?})"
if [ ! -x "$TC/jdk/bin/java" ]; then
  WHEEL="$CACHE/jdk4py.whl"
  download "${JDK4PY_URL:?tools/toolchain.env mancante}" "$WHEEL" "${JDK4PY_SHA256:-}"
  python3 - "$WHEEL" "$TC" <<'PY'
import os, sys, zipfile, shutil
whl, tc = sys.argv[1], sys.argv[2]
tmp = os.path.join(tc, "_jdkx")
shutil.rmtree(tmp, ignore_errors=True)
zipfile.ZipFile(whl).extractall(tmp)
src = os.path.join(tmp, "jdk4py", "java-runtime")
dst = os.path.join(tc, "jdk")
shutil.rmtree(dst, ignore_errors=True)
shutil.move(src, dst)
for f in os.listdir(os.path.join(dst, "bin")):
    os.chmod(os.path.join(dst, "bin", f), 0o755)
shutil.rmtree(tmp, ignore_errors=True)
print("    JDK installato in .toolchain/jdk")
PY
else
  echo "    gia' presente: $("$TC/jdk/bin/java" -version 2>&1 | head -1)"
fi

echo "==> [2/4] aapt2 (npm aaptjs3 ${AAPTJS3_VERSION:-?})"
AAPT_TGZ="$CACHE/aaptjs3.tgz"
download "${AAPTJS3_URL:?}" "$AAPT_TGZ" "${AAPTJS3_SHA256:-}"
if [ ! -x "$TC/bin/aapt2" ] || [ "$(sha "$TC/bin/aapt2")" != "${AAPT2_SHA256:-}" ]; then
  tar xzf "$AAPT_TGZ" -C "$TC" "package/bin/x64/linux/aapt2"
  mv "$TC/package/bin/x64/linux/aapt2" "$TC/bin/aapt2"
  chmod +x "$TC/bin/aapt2"
  rm -rf "$TC/package"
fi
if [ -n "${AAPT2_SHA256:-}" ] && [ "$(sha "$TC/bin/aapt2")" != "$AAPT2_SHA256" ]; then
  echo "    ERRORE: hash di aapt2 non corrisponde" >&2; exit 1
fi
echo "    $("$TC/bin/aapt2" version 2>&1 | head -1)"

echo "==> [3/4] d8 + ecj + apksigner + android.jar (npm minapk ${MINAPK_VERSION:-?})"
MK_TGZ="$CACHE/minapk.tgz"
download "${MINAPK_URL:?}" "$MK_TGZ" "${MINAPK_SHA256:-}"
mkdir -p "$TC/_mk"
tar xzf "$MK_TGZ" -C "$TC/_mk" \
    package/tools/d8.jar package/tools/ecj-3.45.0.jar \
    package/tools/apksigner.jar package/tools/android.jar \
    package/tools/debug.keystore package/LICENSES
cp "$TC/_mk/package/tools/"*.jar "$TC/lib/"
cp "$TC/_mk/package/tools/debug.keystore" "$TC/lib/debug.keystore"
[ -d "$TC/lib/LICENSES" ] || cp -r "$TC/_mk/package/LICENSES" "$TC/lib/LICENSES"
rm -rf "$TC/_mk"

for pair in "d8.jar:D8_SHA256" "ecj-3.45.0.jar:ECJ_SHA256" \
            "apksigner.jar:APKSIGNER_SHA256" "android.jar:ANDROIDJAR_SHA256"; do
  f="${pair%%:*}"; key="${pair##*:}"
  want="${!key:-}"
  if [ -n "$want" ] && [ "$(sha "$TC/lib/$f")" != "$want" ]; then
    echo "    ERRORE: hash di $f non corrisponde" >&2; exit 1
  fi
done
echo "    jar presenti: $(ls "$TC/lib"/*.jar | wc -l)"

echo "==> [4/4] verifica finale"
"$TC/jdk/bin/java" -version 2>&1 | head -1
du -sh "$TC" | awk '{print "    toolchain: " $1}'
echo "OK toolchain"
