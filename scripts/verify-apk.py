#!/usr/bin/env python3
"""
Verifica "il funzionamento associato" di un APK SpyDetector appena costruito.

Non si limita a guardare che il file esista: controlla che sia davvero
installabile e che contenga il codice atteso.

  python3 scripts/verify-apk.py dist/SpyDetector-v1.0.0-release.apk
"""
import hashlib
import os
import re
import struct
import sys
import zipfile

REQUIRED_DEX_STRINGS = [
    "it/spydetector/app/MainActivity",
    "it/spydetector/app/DetailActivity",
    "it/spydetector/app/core/Engine",
    "it/spydetector/app/checks/AccessibilityCheck",
    "it/spydetector/app/checks/MessagingCheck",
    "it/spydetector/app/ui/HudBackground",
    "it/spydetector/app/ui/RiskGauge",
]
FORBIDDEN_PERMISSIONS = ["android.permission.INTERNET", "android.permission.READ_SMS",
                         "android.permission.RECORD_AUDIO", "android.permission.CAMERA"]
REQUIRED_PERMISSIONS = ["android.permission.QUERY_ALL_PACKAGES"]


def fail(msg):
    print("  FAIL  " + msg)
    return False


def ok(msg):
    print("  ok    " + msg)
    return True


def dex_strings(dex, limit=6_000_000):
    """Estrae le stringhe dal DEX (u16 length + MUTF-8) senza dipendenze."""
    if len(dex) < 0x70 or not dex.startswith(b"dex\n"):
        return []
    string_ids_size, string_ids_off = struct.unpack_from("<II", dex, 0x38)
    out = []
    for i in range(min(string_ids_size, 200_000)):
        off = struct.unpack_from("<I", dex, string_ids_off + 4 * i)[0]
        if off >= len(dex):
            continue
        # uleb128 lunghezza
        pos, shift, n = off, 0, 0
        while pos < len(dex):
            b = dex[pos]
            n |= (b & 0x7F) << shift
            pos += 1
            shift += 7
            if not b & 0x80:
                break
        end = min(len(dex), pos + n)
        if end - pos > 300:
            continue
        try:
            out.append(dex[pos:end].decode("utf-8", "ignore"))
        except Exception:  # noqa: BLE001
            pass
        if sum(len(s) for s in out) > limit:
            break
    return out


def main(path):
    print("Verifica APK: %s" % path)
    good = True
    if not os.path.isfile(path):
        return fail("file inesistente") and 1

    size = os.path.getsize(path)
    good &= ok("dimensioni %.1f KB" % (size / 1024)) if size > 30_000 else fail(
        "APK troppo piccolo (%d B)" % size)
    if size < 30_000:
        return 1

    with open(path, "rb") as fh:
        raw = fh.read()
    digest = hashlib.sha256(raw).hexdigest()
    print("  sha256 %s" % digest)

    # --- struttura zip -----------------------------------------------------
    try:
        z = zipfile.ZipFile(path)
        bad = z.testzip()
        good &= ok("zip integro (%d voci)" % len(z.namelist())) if bad is None else fail(
            "zip corrotto: %s" % bad)
        names = z.namelist()
    except zipfile.BadZipFile as exc:
        return fail("non e' uno zip: %s" % exc) and 1

    for must in ("AndroidManifest.xml", "classes.dex", "resources.arsc"):
        good &= ok("presente %s" % must) if must in names else fail("manca %s" % must)
    if "AndroidManifest.xml" not in names:
        return 1

    # --- firma v2/v3 -------------------------------------------------------
    if b"APK Sig Block 42" in raw:
        good &= ok("APK Signature Scheme v2/v3 presente")
    else:
        good &= fail("firma APK v2/v3 assente")

    # --- manifest binario --------------------------------------------------
    man = z.read("AndroidManifest.xml")
    text = man.decode("utf-16-le", "ignore")
    flat = re.sub(r"[^\x20-\x7e]", " ", text)
    for perm in REQUIRED_PERMISSIONS:
        good &= ok("permesso %s" % perm) if perm in flat else fail("manca %s" % perm)
    for perm in FORBIDDEN_PERMISSIONS:
        good &= fail("permesso NON ammesso: %s" % perm) if perm in flat else ok(
            "nessun permesso %s" % perm.split(".")[-1])

    if "it.spydetector.app" in flat:
        good &= ok("package: it.spydetector.app")
    else:
        good &= fail("package it.spydetector.app assente dal manifest")

    for act in ("MainActivity", "DetailActivity"):
        good &= ok("activity %s dichiarata" % act) if act in flat else fail("manca %s" % act)

    # --- codice nei dex ----------------------------------------------------
    dexes = [n for n in names if re.match(r"classes\d*\.dex$", n)]
    good &= ok("dex: %s" % ", ".join(dexes)) if dexes else fail("nessun classes.dex")
    joined = []
    for d in dexes:
        joined += dex_strings(z.read(d))
    blob = "\n".join(joined)
    for needle in REQUIRED_DEX_STRINGS:
        good &= ok("classe %s" % needle) if needle in blob else fail("classe assente: %s" % needle)
    for check in ("KNOWN_THREATS", "ACCESSIBILITY", "MESSAGING", "PERSISTENCE"):
        good &= ok("check %s nel dex" % check) if check in blob else fail("check assente: %s" % check)
    good &= ok("%d stringhe nel dex" % len(joined))

    print("\nESITO: %s" % ("OK" if good else "FALLITO"))
    return 0 if good else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
