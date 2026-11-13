#!/usr/bin/env python3
"""
Risolve le versioni piu' recenti del toolchain di build SpyDetector,
le VALIDA davvero (struttura dei jar, eseguibilita' di aapt2, presenza di
keytool nel JDK) e aggiorna tools/toolchain.env con URL + SHA256 pinnati.

  python3 scripts/update-toolchain.py            # aggiorna se trova versioni valide
  python3 scripts/update-toolchain.py --check    # exit 3 se ci sono aggiornamenti (CI)

Fonti: registry npm e PyPI (nessuna dipendenza esterna).
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(ROOT, "tools", "toolchain.env")
WORK = tempfile.mkdtemp(prefix="spd-tc-")

NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"

# gruppo logico -> pacchetto npm (piu' artefatti possono vivere nello stesso tgz)
NPM_GROUPS = {
    "AAPTJS3": ("aaptjs3", ["aapt2"]),
    "MINAPK": ("@drxiaozhi/minapk", ["d8", "ecj", "apksigner", "androidjar"]),
}
NPM_MEMBERS = {
    "aapt2": "package/bin/x64/linux/aapt2",
    "d8": "package/tools/d8.jar",
    "ecj": "package/tools/ecj-3.45.0.jar",
    "apksigner": "package/tools/apksigner.jar",
    "androidjar": "package/tools/android.jar",
}
# file minimi che devono esistere dentro ogni artefatto
PROBES = {
    "aapt2": None,  # eseguibile: probe separato
    "d8": "com/android/tools/r8/D8.class",
    "ecj": "org/eclipse/jdt/internal/compiler/batch/Main.class",
    "apksigner": "com/android/apksigner/ApkSignerTool.class",
    "androidjar": "android/os/Build$VERSION_CODES.class",
}


def log(msg):
    print(msg, flush=True)


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "spydetector-toolchain"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "spydetector-toolchain"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def vkey(v):
    """chiave di ordinamento semver tollerante (-latest, ecc.)."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4]) + (0,) * (4 - min(4, len(parts)))


def npm_versions(pkg):
    data = http_json("%s/%s" % (NPM, pkg.replace("/", "%2F")))
    out = []
    for v, meta in data.get("versions", {}).items():
        dist = meta.get("dist") or {}
        if not dist.get("tarball"):
            continue
        out.append((v, dist["tarball"]))
    out.sort(key=lambda x: vkey(x[0]), reverse=True)
    return out


def npm_latest(pkg):
    data = http_json("%s/%s/latest" % (NPM, pkg.replace("/", "%2F")))
    return data.get("version"), data.get("dist", {}).get("tarball")


def read_env():
    env = {}
    if os.path.exists(ENV_FILE):
        for line in open(ENV_FILE, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def validate_member(data, name):
    """Controlla che l'artefatto scaricato sia davvero quello che serve."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        try:
            member = tar.getmember(NPM_MEMBERS[name])
        except KeyError:
            return None, "membro %s assente" % NPM_MEMBERS[name]
        payload = tar.extractfile(member).read()
    if len(payload) < 20_000:
        return None, "artefatto troppo piccolo (%d B)" % len(payload)
    if name == "aapt2":
        path = os.path.join(WORK, "aapt2-probe")
        open(path, "wb").write(payload)
        os.chmod(path, 0o755)
        try:
            proc = subprocess.run([path, "version"], capture_output=True, timeout=60)
        except Exception as exc:  # noqa: BLE001
            return None, "aapt2 non eseguibile: %s" % exc
        out = (proc.stdout or b"") + (proc.stderr or b"")
        if b"Asset Packaging Tool" not in out:
            return None, "aapt2 non risponde come previsto"
        return payload, "ok (%s)" % out.decode("utf-8", "replace").strip()
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            names = set(z.namelist())
            if PROBES[name] not in names:
                return None, "manca %s" % PROBES[name]
            if name == "androidjar":
                for extra in ("android/app/Activity.class", "android/os/Build$VERSION.class"):
                    if extra not in names:
                        return None, "manca %s" % extra
    except zipfile.BadZipFile:
        return None, "non e' uno zip/jar valido"
    return payload, "ok (%d KB)" % (len(payload) // 1024)


def resolve_npm_group(pkg, names, current_urls):
    """Per gli artefatti che vivono nella stessa release npm: prova le versioni
    dalla piu' recente e tiene la prima in cui TUTTI i membri sono validi."""
    names = list(names)
    candidates = npm_versions(pkg)
    log("\n== %s (npm) — %d versioni disponibili" % (pkg, len(candidates)))
    for version, url in candidates[:12]:
        try:
            data = http_get(url)
        except Exception as exc:  # noqa: BLE001
            log("   %-10s skip: download fallito (%s)" % (version, exc))
            continue
        ok_all, results = True, {}
        for n in names:
            payload, status = validate_member(data, n)
            results[n] = (payload, status)
            if payload is None:
                ok_all = False
            log("   %-10s %-11s %s" % (version, n, status))
        if ok_all:
            log("   -> scelto %s" % version)
            return version, url, sha256(data), {n: results[n][0] for n in names}
        # se la versione in uso e' questa e non passa, e' un problema serio
        if url in current_urls:
            log("   ATTENZIONE: la versione corrente non passa la validazione!")
    return None, None, None, {}


JDK_MAX_MAJOR = int(os.environ.get("SPD_JDK_MAX_MAJOR", "22"))


def resolve_jdk(current_version):
    """JDK portabile che fa girare ecj (compilatore Java 8) senza la module-map
    dei JDK piu' recenti, che rompe la compilazione contro android.jar."""
    log("\n== jdk4py (PyPI)")
    data = http_json("%s/jdk4py/json" % PYPI)
    versions = []
    for v, files in data.get("releases", {}).items():
        major = vkey(v)[0]
        if major > JDK_MAX_MAJOR:
            log("   %-12s skip: major %d > %d (troppo nuovo per ecj)" % (v, major, JDK_MAX_MAJOR))
            continue
        for f in files:
            if f["filename"].endswith("manylinux_2_17_x86_64.whl"):
                versions.append((v, f))
    versions.sort(key=lambda x: vkey(x[0]), reverse=True)
    for version, f in versions[:15]:
        try:
            payload = http_get(f["url"])
        except Exception as exc:  # noqa: BLE001
            log("   %-12s skip: %s" % (version, exc))
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as z:
                names = set(z.namelist())
                has_java = "jdk4py/java-runtime/bin/java" in names
                has_keytool = "jdk4py/java-runtime/bin/keytool" in names
                # il JDK deve poter compilare: serve il runtime di Octane (ecj lo usa)
                has_octane = any("lib/modules" in n for n in names) or any(
                    n.endswith("libjvm.so") for n in names)
        except zipfile.BadZipFile:
            log("   %-12s skip: wheel non valido" % version)
            continue
        status = "java=%s keytool=%s modules=%s" % (has_java, has_keytool, has_octane)
        if has_java and has_keytool and has_octane:
            log("   %-12s ok  %s (%d MB)" % (version, status, len(payload) // 1_000_000))
            return version, f["url"], sha256(payload), payload
        log("   %-12s rifiutato: %s" % (version, status))
    return None, None, None, None


def main():
    check_only = "--check" in sys.argv
    current = read_env()
    updates = {}

    # --- gruppi npm --------------------------------------------------------
    for group, (pkg, names) in NPM_GROUPS.items():
        cur_url = current.get(group + "_URL", "")
        version, url, digest, payloads = resolve_npm_group(pkg, names, {cur_url})
        if version:
            if version != current.get(group + "_VERSION", ""):
                updates[group] = (version, url, digest, payloads, names)
            else:
                log("   gia' aggiornato (%s)" % version)
        else:
            log("   nessuna versione valida per %s: mantengo la corrente" % pkg)

    # --- JDK ---------------------------------------------------------------
    jdk_version, jdk_url, jdk_digest, _ = resolve_jdk(current.get("JDK4PY_VERSION", ""))
    if jdk_version and jdk_version != current.get("JDK4PY_VERSION", ""):
        updates["jdk"] = (jdk_version, jdk_url, jdk_digest)
    elif jdk_version:
        log("   gia' aggiornato (%s)" % jdk_version)

    if not updates:
        log("\nToolchain gia' alla versione piu' recente e validata.")
        return 0

    if check_only:
        log("\nAggiornamenti disponibili: %s" % ", ".join(
            "%s=%s" % (k, v[0]) for k, v in updates.items()))
        return 3

    # --- nessun cambiamento reale: non tocco il file ---------------------
    if all(current.get(k + "_VERSION", "") == v[0] for k, v in updates.items()):
        log("\nNessun cambiamento reale: tools/toolchain.env invariato.")
        return 0

    # --- scrive il nuovo env ----------------------------------------------
    lines = [
        "# Toolchain di build SpyDetector — GENERATO da scripts/update-toolchain.py",
        "# Ogni voce e' pinnata a una versione + SHA256 verificato prima dell'uso.",
        "# Aggiornato: %s" % __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d"),
    ]
    for group, (pkg, names) in NPM_GROUPS.items():
        keys = [group + "_VERSION", group + "_URL", group + "_SHA256"] + \
               ["%s_SHA256" % n.upper() for n in names]
        if group in updates:
            version, url, digest, payloads, _ = updates[group]
            lines += ["%s_VERSION=%s" % (group, version), "%s_URL=%s" % (group, url),
                      "%s_SHA256=%s" % (group, digest)]
            for n in names:
                lines.append("%s_SHA256=%s" % (n.upper(), sha256(payloads[n])))
        else:
            for k in keys:
                lines.append("%s=%s" % (k, current.get(k, "")))
    if "jdk" in updates:
        jv, ju, jd = updates["jdk"]
        lines += ["JDK4PY_VERSION=%s" % jv, "JDK4PY_URL=%s" % ju, "JDK4PY_SHA256=%s" % jd]
    else:
        for k in ("JDK4PY_VERSION", "JDK4PY_URL", "JDK4PY_SHA256"):
            lines.append("%s=%s" % (k, current.get(k, "")))
    with open(ENV_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    log("\nScritto %s" % ENV_FILE)
    for k, v in updates.items():
        log("  %s -> %s" % (k, v[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
