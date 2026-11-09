#!/usr/bin/env bash
# =============================================================================
#  SpyDetector - build script (no Gradle, no Android SDK)
#  Compila l'APK di release usando aapt2 + ecj + d8 + apksigner.
#  Output: dist/SpyDetector-release.apk (+ .sha256)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TC="$ROOT/.toolchain"
APP="$ROOT/app/src/main"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
VERSION_NAME="$(cat "$ROOT/VERSION" 2>/dev/null | tr -d '[:space:]')"
[ -z "$VERSION_NAME" ] && VERSION_NAME="1.0.0"
# versionCode monotono: usa il numero di commit se disponibile, altrimenti la data
if [ -z "${VERSION_CODE:-}" ]; then
  if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    VERSION_CODE="$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 1)"
  else
    VERSION_CODE="$(date +%y%m%d)"
  fi
fi
PKG="it.spydetector.app"
MIN_SDK=26
TARGET_SDK=35

# --- toolchain -------------------------------------------------------------
if [ ! -x "$TC/bin/aapt2" ] || [ ! -f "$TC/lib/d8.jar" ]; then
  "$ROOT/tools/fetch-toolchain.sh"
fi
if [ -x "$TC/jdk/bin/java" ]; then
  JAVA="$TC/jdk/bin/java"
  KEYTOOL="$TC/jdk/bin/keytool"
else
  JAVA="java"
  KEYTOOL="keytool"
fi
AAPT2="$TC/bin/aapt2"
ANDROID_JAR="$TC/lib/android.jar"
D8_JAR="$TC/lib/d8.jar"
ECJ_JAR="$TC/lib/ecj-3.45.0.jar"
APKSIGNER_JAR="$TC/lib/apksigner.jar"

# --- pulizia ---------------------------------------------------------------
rm -rf "$BUILD"
mkdir -p "$BUILD/gen" "$BUILD/classes" "$BUILD/dex" "$BUILD/res" "$DIST"

echo "==> [1/6] Risorse (aapt2 compile)"
"$AAPT2" compile --dir "$APP/res" -o "$BUILD/res/resources.zip"

echo "==> [2/6] Link + R.java + base APK (versionName=$VERSION_NAME, code=$VERSION_CODE)"
"$AAPT2" link \
  -o "$BUILD/base.apk" \
  -I "$ANDROID_JAR" \
  --manifest "$APP/AndroidManifest.xml" \
  --java "$BUILD/gen" \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TARGET_SDK" \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  --auto-add-overlay \
  "$BUILD/res/resources.zip"

echo "==> [3/6] Compilazione Java (ecj)"
# BuildConfig generato dallo script: versione sempre allineata a VERSION
mkdir -p "$BUILD/gen/it/spydetector/app"
cat > "$BUILD/gen/it/spydetector/app/BuildConfig.java" <<EOF
package it.spydetector.app;
public final class BuildConfig {
    public static final String VERSION_NAME = "$VERSION_NAME";
    public static final String VERSION_CODE = "$VERSION_CODE";
    public static final String APPLICATION_ID = "$PKG";
    private BuildConfig() {}
}
EOF
# il BuildConfig sorgente nel repo e' solo un fallback per gli IDE
rm -f "$APP/java/it/spydetector/app/BuildConfig.java" 2>/dev/null || true

find "$APP/java" "$BUILD/gen" -name '*.java' > "$BUILD/sources.txt"
set +e
"$JAVA" -jar "$ECJ_JAR" \
  -source 1.8 -target 1.8 -nowarn -proc:none \
  -bootclasspath "$ANDROID_JAR" \
  -d "$BUILD/classes" \
  @"$BUILD/sources.txt" > "$BUILD/ecj.log" 2>&1
ECJ_RC=$?
set -e
grep -E 'ERROR in|problems' "$BUILD/ecj.log" | head -40 || true

if [ "$ECJ_RC" -ne 0 ] || ! find "$BUILD/classes" -name '*.class' | grep -q .; then
  echo "ERRORE: compilazione Java fallita (log: build/ecj.log)"; exit 1
fi
echo "    $(find "$BUILD/classes" -name '*.class' | wc -l) classi compilate"

echo "==> [4/6] Dex (d8, min-api $MIN_SDK)"
find "$BUILD/classes" -name '*.class' > "$BUILD/classes.txt"
"$JAVA" -cp "$D8_JAR" com.android.tools.r8.D8 \
  --lib "$ANDROID_JAR" \
  --min-api "$MIN_SDK" \
  --release \
  --output "$BUILD/dex" \
  @"$BUILD/classes.txt"

echo "==> [5/6] Packaging"
cp "$BUILD/base.apk" "$BUILD/unsigned.apk"
( cd "$BUILD/dex" && zip -q -X "$BUILD/unsigned.apk" ./*.dex )

echo "==> [6/6] Firma release + verifica"
KS="$ROOT/signing/spydetector-release.jks"
KS_PASS="${SPD_KS_PASS:-spydetector}"
KEY_ALIAS="${SPD_KEY_ALIAS:-spydetector}"
KEY_PASS="${SPD_KEY_PASS:-spydetector}"
OUT_APK="$DIST/SpyDetector-v${VERSION_NAME}-release.apk"

"$JAVA" -jar "$APKSIGNER_JAR" sign \
  --ks "$KS" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "pass:$KS_PASS" --key-pass "pass:$KEY_PASS" \
  --min-sdk-version "$MIN_SDK" \
  --out "$OUT_APK" "$BUILD/unsigned.apk" 2>&1 | grep -v 'WARNING' || true

"$JAVA" -jar "$APKSIGNER_JAR" verify --min-sdk-version "$MIN_SDK" --verbose "$OUT_APK" 2>&1 \
  | grep -v 'WARNING' | tee "$BUILD/verify.txt"

( cd "$DIST" && sha256sum "$(basename "$OUT_APK")" > "$(basename "$OUT_APK").sha256" )

echo
echo "=========================================================="
echo " APK: $OUT_APK"
echo " Size: $(du -h "$OUT_APK" | cut -f1)"
echo " SHA256: $(cut -d' ' -f1 "$OUT_APK.sha256")"
echo "=========================================================="
