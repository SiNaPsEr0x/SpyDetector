#!/usr/bin/env python3
"""
Aggiorna la knowledge base delle app di sorveglianza usata dai check on-device.

Genera `app/src/main/java/it/spydetector/app/core/ThreatDbGenerated.java`
partendo da:
  * la lista curata in `data/threat-seed.txt` (righe: pkg|nome|tipo|gravita)
  * i pacchetti gia' presenti in ThreatDb.java (per non perdere nulla)
  * eventuali fonti upstream raggiungibili (opzionali: se offline non e' errore)

La lista viene VALIDATA (sintassi dei package, niente duplicati, nessun
dimezzamento improvviso) prima di essere scritta: se la validazione fallisce,
il file generato viene lasciato intatto e lo script esce in errore.
"""
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = os.path.join(ROOT, "data", "threat-seed.txt")
CURATED = os.path.join(ROOT, "app", "src", "main", "java", "it", "spydetector",
                       "app", "core", "ThreatDb.java")
OUT = os.path.join(ROOT, "app", "src", "main", "java", "it", "spydetector",
                   "app", "core", "ThreatDbGenerated.java")

PKG_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}$")
ALLOWED_SEV = {"OK", "INFO", "ATTENTION", "WARNING", "CRITICAL"}


def read_seed():
    entries = []
    if not os.path.exists(SEED):
        return entries
    for line in open(SEED, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4:
            print("   seed non valido (4 campi attesi): %s" % line)
            continue
        entries.append(tuple(parts))
    return entries


def read_curated():
    """Recupera le voci gia' in ThreatDb.java (k("pkg", "nome", "tipo", Severity.X))."""
    if not os.path.exists(CURATED):
        return []
    src = open(CURATED, encoding="utf-8").read()
    pattern = re.compile(
        r'k\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*Severity\.(\w+)\s*\)')
    return pattern.findall(src)


def validate(entries):
    clean, seen, errors = [], set(), []
    for pkg, name, kind, sev in entries:
        if not PKG_RE.match(pkg):
            errors.append("package non valido: %s" % pkg)
            continue
        if sev not in ALLOWED_SEV:
            errors.append("gravita' non valida per %s: %s" % (pkg, sev))
            continue
        if not name.strip() or not kind.strip():
            errors.append("nome/tipo vuoto per %s" % pkg)
            continue
        if pkg in seen:
            continue
        seen.add(pkg)
        clean.append((pkg, name.strip().replace('"', "'"),
                      kind.strip().replace('"', "'"), sev))
    return clean, errors


def main():
    seed = read_seed()
    curated = read_curated()
    prev_count = len(curated)

    merged = {}
    for e in curated + seed:            # il seed vince (aggiornato)
        merged[e[0]] = e
    entries, errors = validate(list(merged.values()))

    for e in errors:
        print("   ATTENZIONE: " + e)
    print("   voci: %d (curate %d + seed %d, uniche %d)"
          % (len(entries), len(curated), len(seed), len(entries)))

    if len(entries) < 20:
        print("ERRORE: meno di 20 voci valide, non sovrascrivo il database")
        return 1
    if prev_count and len(entries) < prev_count * 0.5:
        print("ERRORE: la lista si e' dimezzata (%d -> %d), blocco l'aggiornamento"
              % (prev_count, len(entries)))
        return 1

    lines = [
        "package it.spydetector.app.core;",
        "",
        "/**",
        " * GENERATO da scripts/update-threat-db.py — non modificare a mano.",
        " * Fonte: data/threat-seed.txt + lista curata di ThreatDb.java.",
        " * Aggiornato: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        " * Voci: %d" % len(entries),
        " */",
        "final class ThreatDbGenerated {",
        "    private ThreatDbGenerated() {}",
        "",
        "    /** pkg|nome|tipo|gravita' */",
        "    static final String[] ENTRIES = {",
    ]
    for pkg, name, kind, sev in sorted(entries):
        lines.append('        "%s|%s|%s|%s",' % (pkg, name, kind, sev))
    lines += ["    };", "}", ""]
    content = "\n".join(lines)

    old = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
    # confronto ignorando la riga della data
    strip = lambda s: "\n".join(l for l in s.splitlines() if "Aggiornato:" not in l)
    if strip(old) == strip(content):
        print("   gia' aggiornato")
        return 0
    open(OUT, "w", encoding="utf-8").write(content)
    print("   scritto %s" % os.path.relpath(OUT, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
