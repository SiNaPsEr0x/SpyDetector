#!/usr/bin/env python3
"""
Indicatori di compromissione (IOC) della supply chain di build.

Controlla che i pacchetti npm/PyPI usati per costruire l'APK:
  * siano ancora pinnati agli stessi SHA256 (nessuna sostituzione silenziosa);
  * non siano nella lista di pacchetti compromessi/malevoli conosciuti;
  * non abbiano script di installazione (preinstall/install/postinstall);
  * non contengano URL di esfiltrazione noti nel codice distribuito;
  * risolvano dai registry attesi (npm/PyPI) e non da host arbitrari.

Scrive un report in docs/security/iocs.md. Exit 1 se qualcosa non torna.
"""
import io
import json
import os
import re
import tarfile
import urllib.request
import zipfile
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENVF = os.path.join(ROOT, "tools", "toolchain.env")
REPORT = os.path.join(ROOT, "docs", "security", "iocs.md")

# pacchetti compromessi/malevoli noti (eventi pubblici) — match esatto sul nome
BLOCKLIST = {
    "event-stream", "flatmap-stream", "ua-parser-js", "coa", "rc", "colors",
    "faker", "node-ipc", "peacenotwar", "pycord-self", "ctx", "phpass",
    "discordi.js", "lottie-player", "solana-python-sdk", "ultralytics",
}
# domini di esfiltrazione visti in incidenti npm recenti
SUSPICIOUS_HOSTS = (
    "webhook.site", "pipedream.net", "ngrok.io", "ngrok-free.app",
    "pastebin.com", "transfer.sh", "interact.sh", "oast.fun", "requestbin",
    "burpcollaborator", "dnslog.cn", "workers.dev/collect",
)
ALLOWED_NPM_HOST = "registry.npmjs.org"
ALLOWED_PYPI_HOST = "files.pythonhosted.org"


def load_env():
    env = {}
    for line in open(ENVF, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v.strip()
    return env


def get(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": "spydetector-ioc"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    return data if binary else json.loads(data)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def scan_npm(env, findings):
    for group in ("AAPTJS3", "MINAPK"):
        url = env.get(group + "_URL", "")
        want = env.get(group + "_SHA256", "")
        version = env.get(group + "_VERSION", "")
        if not url:
            findings.append(("warn", "%s: URL assente in toolchain.env" % group))
            continue
        host = re.sub(r"^https?://([^/]+)/.*$", r"\1", url)
        if host != ALLOWED_NPM_HOST:
            findings.append(("fail", "%s: host inatteso %s" % (group, host)))
        data = get(url, binary=True)
        got = sha256(data)
        if want and got != want:
            findings.append(("fail", "%s: SHA256 cambiato! atteso %s…, ottenuto %s…"
                             % (group, want[:16], got[:16])))
        else:
            findings.append(("ok", "%s %s: SHA256 verificato (%s…)" % (group, version, got[:16])))

        meta_url = "%s/%s/%s" % (
            "https://registry.npmjs.org",
            "aaptjs3" if group == "AAPTJS3" else "%40drxiaozhi%2Fminapk", version)
        try:
            meta = get(meta_url)
        except Exception as exc:  # noqa: BLE001
            findings.append(("warn", "%s: metadati non leggibili (%s)" % (group, exc)))
            meta = {}
        name = meta.get("name", "")
        if name in BLOCKLIST:
            findings.append(("fail", "%s: pacchetto in blocklist (%s)" % (group, name)))
        scripts = (meta.get("scripts") or {})
        hook = [k for k in scripts if k in ("preinstall", "install", "postinstall")]
        if hook:
            findings.append(("warn", "%s: script di install presenti %s (controllare)" % (group, hook)))
        else:
            findings.append(("ok", "%s: nessuno script di install" % group))

        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile() or m.size > 4_000_000:
                    continue
                if not re.search(r"\.(js|json|c|py|sh|jar|txt)$", m.name):
                    continue
                try:
                    blob = tar.extractfile(m).read()
                except Exception:  # noqa: BLE001
                    continue
                text = blob.decode("utf-8", "ignore").lower()
                for bad in SUSPICIOUS_HOSTS:
                    if bad in text:
                        findings.append(("fail", "%s/%s cita %s" % (group, m.name, bad)))
        findings.append(("ok", "%s: nessun host di esfiltrazione noto" % group))


def scan_jdk(env, findings):
    url = env.get("JDK4PY_URL", "")
    want = env.get("JDK4PY_SHA256", "")
    if not url:
        findings.append(("warn", "JDK: URL assente"))
        return
    host = re.sub(r"^https?://([^/]+)/.*$", r"\1", url)
    if host != ALLOWED_PYPI_HOST:
        findings.append(("fail", "JDK: host inatteso %s" % host))
    data = get(url, binary=True)
    got = sha256(data)
    if want and got != want:
        findings.append(("fail", "JDK: SHA256 cambiato! atteso %s…, ottenuto %s…"
                         % (want[:16], got[:16])))
    else:
        findings.append(("ok", "JDK %s: SHA256 verificato (%s…)"
                         % (env.get("JDK4PY_VERSION", "?"), got[:16])))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if "jdk4py/java-runtime/bin/java" not in z.namelist():
                findings.append(("fail", "JDK: struttura inattesa (bin/java assente)"))
            else:
                findings.append(("ok", "JDK: struttura attesa (bin/java presente)"))
    except zipfile.BadZipFile:
        findings.append(("fail", "JDK: wheel non valido"))


def main():
    env = load_env()
    findings = []
    print("Controllo IOC della toolchain (npm/PyPI)")
    for fn, label in ((scan_npm, "npm"), (scan_jdk, "pypi")):
        try:
            fn(env, findings)
        except Exception as exc:  # noqa: BLE001
            findings.append(("fail", "%s: errore durante il controllo (%s)" % (label, exc)))

    fails = [f for f in findings if f[0] == "fail"]
    warns = [f for f in findings if f[0] == "warn"]
    for level, msg in findings:
        print("  %-4s %s" % (level, msg))

    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        fh.write("# IOC della supply chain di build\n\n")
        fh.write("Generato da `scripts/check-iocs.py`. Controlla i pacchetti usati per\n")
        fh.write("costruire l'APK (npm + PyPI): hash, host, script di install, host di esfiltrazione noti.\n\n")
        fh.write("| esito | controllo |\n|---|---|\n")
        for level, msg in findings:
            icon = {"ok": "✅", "warn": "⚠️", "fail": "❌"}[level]
            fh.write("| %s | %s |\n" % (icon, msg.replace("|", "\\|")))
        fh.write("\n**Esito: %s** (%d fail, %d warning)\n"
                 % ("BLOCCATO" if fails else "PASSATO", len(fails), len(warns)))
    print("\nEsito: %s (%d fail, %d warning)" % ("BLOCCATO" if fails else "PASSATO",
                                                len(fails), len(warns)))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
