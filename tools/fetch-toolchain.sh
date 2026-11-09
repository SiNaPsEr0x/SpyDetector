#!/usr/bin/env bash
# SpyDetector - toolchain fetch
# Scarica aapt2 + d8 + ecj + apksigner (Android build tools) e un JDK portabile
# SOLO da registry npm / PyPI, cosi' la build funziona anche in ambienti
# senza accesso a dl.google.com. Tutto finisce in .toolchain/ (git-ignored).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="$ROOT/.toolchain"
mkdir -p "$TC"

need() { command -v "$1" >/dev/null 2>&1; }
have_java=0
if need java && java -version >/dev/null 2>&1; then have_java=1; fi

echo "==> [1/4] JDK"
if [ ! -x "$TC/jdk/bin/java" ]; then
  if [ "$have_java" = "1" ]; then
    echo "    uso java di sistema: $(command -v java)"
  else
    pip download --no-deps -q -d "$TC/jdkwhl" "jdk4py==21.0.8.2" \
      --only-binary=:all: --platform manylinux_2_17_x86_64 --python-version 3.11
    python3 - "$TC" <<'PY'
import sys, glob, zipfile, os
tc = sys.argv[1]
whl = glob.glob(os.path.join(tc, "jdkwhl", "*.whl"))[0]
zipfile.ZipFile(whl).extractall(os.path.join(tc, "jdkx"))
src = os.path.join(tc, "jdkx", "jdk4py", "java-runtime")
os.rename(src, os.path.join(tc, "jdk"))
for f in glob.glob(os.path.join(tc, "jdk", "bin", "*")):
    os.chmod(f, 0o755)
print("    JDK installato in .toolchain/jdk")
PY
    rm -rf "$TC/jdkwhl" "$TC/jdkx"
  fi
fi

echo "==> [2/4] aapt2 (npm: aaptjs3)"
if [ ! -x "$TC/bin/aapt2" ]; then
  mkdir -p "$TC/bin"
  curl -sSL -o "$TC/aaptjs3.tgz" https://registry.npmjs.org/aaptjs3/-/aaptjs3-2.0.2.tgz
  tar xzf "$TC/aaptjs3.tgz" -C "$TC" package/bin/x64/linux/aapt2
  mv "$TC/package/bin/x64/linux/aapt2" "$TC/bin/aapt2"
  chmod +x "$TC/bin/aapt2"
  rm -rf "$TC/package" "$TC/aaptjs3.tgz"
fi

echo "==> [3/4] d8 + ecj + apksigner + android.jar (npm: @drxiaozhi/minapk)"
if [ ! -f "$TC/lib/d8.jar" ] || [ ! -f "$TC/lib/android.jar" ]; then
  mkdir -p "$TC/lib"
  curl -sSL -o "$TC/minapk.tgz" https://registry.npmjs.org/@drxiaozhi/minapk/-/minapk-0.5.1.tgz
  tar xzf "$TC/minapk.tgz" -C "$TC" \
      package/tools/d8.jar package/tools/ecj-3.45.0.jar \
      package/tools/apksigner.jar package/tools/android.jar \
      package/tools/debug.keystore package/LICENSES
  mv "$TC/package/tools/"*.jar "$TC/lib/"
  mv "$TC/package/tools/debug.keystore" "$TC/lib/debug.keystore"
  mv "$TC/package/LICENSES" "$TC/lib/LICENSES"
  rm -rf "$TC/package" "$TC/minapk.tgz"
fi

echo "==> [4/4] verifica"
"$TC/bin/aapt2" version || true
"$TC/lib/d8.jar" >/dev/null 2>&1 || test -f "$TC/lib/d8.jar"
echo "OK toolchain in $TC"
