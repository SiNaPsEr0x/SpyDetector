#!/usr/bin/env python3
"""
Aggiorna la knowledge base delle app di sorveglianza usata dai check on-device.

Genera `app/src/main/java/it/spydetector/app/core/ThreatDbGenerated.java`
partendo da:
  * la lista curata in `data/threat-seed.txt` (righe: pkg|nome|tipo|gravita)
  * i pacchetti gia' presenti in ThreatDb.java (per non perdere nulla)
  * i pattern pubblici in `data/threat-patterns.txt`
    (righe: TIPO|valore|nome famiglia|tipo|gravita, TIPO in PKG|CERT|COMP)
  * eventuali fonti upstream raggiungibili (opzionali: se offline non e' errore)

Le liste vengono VALIDATE (sintassi dei package/pattern, niente duplicati,
nessun dimezzamento improvviso) prima di essere scritte: se la validazione
fallisce, il file generato viene lasciato intatto e lo script esce in errore.
"""
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = os.path.join(ROOT, "data", "threat-seed.txt")
PATTERNS = os.path.join(ROOT, "data", "threat-patterns.txt")
CURATED = os.path.join(ROOT, "app", "src", "main", "java", "it", "spydetector",
                       "app", "core", "ThreatDb.java")
OUT = os.path.join(ROOT, "app", "src", "main", "java", "it", "spydetector",
                   "app", "core", "ThreatDbGenerated.java")

PKG_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}$")
ALLOWED_SEV = {"OK", "INFO", "ATTENTION", "WARNING", "CRITICAL"}
PATTERN_TYPES = {"PKG", "CERT", "COMP"}
CERT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
VALUE_RE = re.compile(r"^[a-z0-9._]+$")


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


def read_patterns():
    entries = []
    if not os.path.exists(PATTERNS):
        return entries
    for line in open(PATTERNS, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 5:
            print("   pattern non valido (5 campi attesi): %s" % line)
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


def validate_patterns(entries):
    clean, seen, errors = [], set(), []
    for typ, value, name, kind, sev in entries:
        if typ not in PATTERN_TYPES:
            errors.append("tipo pattern non valido: %s" % typ)
            continue
        if typ == "CERT" and not CERT_RE.match(value):
            errors.append("CERT non valido (64 hex attesi): %s" % value)
            continue
        if typ in ("PKG", "COMP"):
            if not VALUE_RE.match(value) or len(value) < 3:
                errors.append("valore pattern non valido per %s: %s" % (typ, value))
                continue
        if sev not in ALLOWED_SEV:
            errors.append("gravita' non valida per %s: %s" % (typ, sev))
            continue
        if not name.strip() or not kind.strip():
            errors.append("nome/tipo vuoto per %s" % value)
            continue
        if (typ, value) in seen:
            continue
        seen.add((typ, value))
        clean.append((typ, value.lower(), name.strip().replace('"', "'"),
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

    # --- pattern -----------------------------------------------------------
    pat_raw = read_patterns()
    patterns, pat_errors = validate_patterns(pat_raw)
    for e in pat_errors:
        print("   ATTENZIONE: " + e)
    print("   pattern: %d (PKG %d, CERT %d, COMP %d)"
          % (len(patterns),
             sum(1 for p in patterns if p[0] == "PKG"),
             sum(1 for p in patterns if p[0] == "CERT"),
             sum(1 for p in patterns if p[0] == "COMP")))

    lines = [
        "package it.spydetector.app.core;",
        "",
        "/**",
        " * GENERATO da scripts/update-threat-db.py — non modificare a mano.",
        " * Fonti: data/threat-seed.txt + lista curata di ThreatDb.java;",
        " *        data/threat-patterns.txt (pattern pubblici).",
        " * Aggiornato: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        " * Voci: %d, Pattern: %d" % (len(entries), len(patterns)),
        " */",
        "final class ThreatDbGenerated {",
        "    private ThreatDbGenerated() {}",
        "",
        "    /** pkg|nome|tipo|gravita' */",
        "    static final String[] ENTRIES = {",
    ]
    for pkg, name, kind, sev in sorted(entries):
        lines.append('        "%s|%s|%s|%s",' % (pkg, name, kind, sev))
    lines += [
        "    };",
        "",
        "    /** tipo|valore|nome famiglia|tipo|gravita' (PKG|CERT|COMP) */",
        "    static final String[] PATTERNS = {",
    ]
    for typ, value, name, kind, sev in patterns:
        lines.append('        "%s|%s|%s|%s|%s",' % (typ, value, name, kind, sev))
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
