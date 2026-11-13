#!/usr/bin/env python3
"""
Correzioni deterministiche delle finding prodotte da scripts/gates.py.

  python3 scripts/autofix.py                       # gira i gate e ripara
  python3 scripts/autofix.py --report build/gates.json
  python3 scripts/autofix.py --dry-run             # mostra senza toccare nulla
  python3 scripts/autofix.py --list                # regole disponibili
  python3 scripts/autofix.py --only ws-trailing --skip wf-pin

Principi (valgono per ogni regola):

  * **deterministica**: nessuna riscrittura "creativa" del codice, solo
    trasformazioni il cui risultato e' prevedibile e verificabile;
  * **idempotente**: rilanciarla non produce ulteriori modifiche;
  * **reversibile**: lavora sull'albero di lavoro, il commit lo fa la CI (o tu);
  * **onesta**: se una finding non ha una regola qui, resta dov'e' e il ciclo
    di self-healing la segnala a una persona invece di inventare una patch.

Le correzioni che cambiano la struttura di un file di testo (permessi delle
workflow, blocchi mancanti) sono fatte a livello di righe: i commenti e i pin
SHA esistenti non vengono mai riscritti da un parser YAML.

Uscita: 0 = applicato (o nulla da fare), 2 = errore interno.
"""
import argparse
import os
import re
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gates  # noqa: E402  (stessa directory: scripts/gates.py)

ROOT = gates.ROOT


# --------------------------------------------------------------------------
# infrastruttura di patch
# --------------------------------------------------------------------------
class Patcher(object):
    """Accumula le modifiche ai file e le scrive una volta sola."""

    def __init__(self, ctx, dry_run=False):
        self.ctx = ctx
        self.dry = dry_run
        self.pending = {}
        self.changes = []
        self.skipped = []

    # -- lettura/scrittura -------------------------------------------------
    def text(self, path):
        if path in self.pending:
            return self.pending[path]
        return self.ctx.read(path)

    def save(self, path, new_text, why):
        old = self.text(path)
        if old == new_text:
            return False
        self.pending[path] = new_text
        self.changes.append({"path": self.ctx.rel(path), "why": why})
        if not self.dry:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new_text)
            self.ctx.invalidate(path)
        return True

    def chmod(self, path, mode, why):
        cur = stat.S_IMODE(os.stat(path).st_mode)
        if cur == mode:
            return False
        self.changes.append({"path": self.ctx.rel(path), "why": why})
        if not self.dry:
            os.chmod(path, mode)
        return True

    def remove(self, path, why):
        if not os.path.exists(path):
            return False
        self.changes.append({"path": self.ctx.rel(path), "why": why})
        if not self.dry:
            os.remove(path)
            self.ctx.invalidate(path)
        return True

    def delegate(self, script, args, why):
        """Affida la correzione a uno script del progetto (gia' validato)."""
        cmd = [sys.executable,
               os.path.join(self.ctx.root, "scripts", script)] + args
        if self.dry:
            self.skipped.append({"why": "%s (dry-run: %s non eseguito)"
                                 % (why, script)})
            return False
        try:
            r = subprocess.run(cmd, cwd=self.ctx.root, capture_output=True,
                               text=True, timeout=900)
        except Exception as exc:  # noqa: BLE001
            self.skipped.append({"why": "%s: %s fallito (%s)" % (why, script, exc)})
            return False
        if r.returncode != 0:
            detail = " ".join(((r.stdout or "") + (r.stderr or "")).split())[:200]
            self.skipped.append({"why": "%s: %s exit %d (%s)"
                                 % (why, script, r.returncode, detail or "n/d")})
            return False
        self.ctx.invalidate()
        self.changes.append({"path": "-", "why": why + " (via %s)" % script})
        return True

    # -- utilita' ----------------------------------------------------------
    def by_rule(self, findings, rule):
        return [f for f in findings if f.fix and f.fix.split(":")[0] == rule]

    def flush(self):
        self.pending.clear()


def _rewrite_lines(text, transform, why, patcher, path):
    lines = text.split("\n")
    new = transform(lines)
    return patcher.save(path, "\n".join(new), why)


# --------------------------------------------------------------------------
# regole di correzione
# --------------------------------------------------------------------------
def fix_ws_bom(patcher, findings):
    """Rimuove la BOM UTF-8 a inizio file."""
    n = 0
    for f in patcher.by_rule(findings, "ws-bom"):
        raw = patcher.ctx.read_bytes(f.path)
        if not raw.startswith(b"\xef\xbb\xbf"):
            continue
        text = raw.decode("utf-8", "replace")
        if patcher.save(f.path, text.lstrip("\ufeff"), "rimossa BOM UTF-8"):
            n += 1
    return n


def fix_ws_crlf(patcher, findings):
    """Converte i fine riga CRLF in LF."""
    n = 0
    for f in patcher.by_rule(findings, "ws-crlf"):
        text = patcher.text(f.path)
        if "\r\n" not in text and "\r" not in text:
            continue
        if patcher.save(f.path, text.replace("\r\n", "\n").replace("\r", "\n"),
                        "fine riga CRLF -> LF"):
            n += 1
    return n


def fix_expand_tabs(patcher, findings):
    """Sostituisce i tab di indentazione con spazi (2 per YAML, 4 per il resto)."""
    n = 0
    rules = {"expand-tabs": 4, "yaml-tabs": 2}
    targets = {}
    for f in findings:
        if not f.fix:
            continue
        rule = f.fix.split(":")[0]
        if rule in rules:
            targets.setdefault(f.path, rules[rule])
    for path, width in targets.items():
        def transform(lines, width=width):
            out = []
            for line in lines:
                lead = line[:len(line) - len(line.lstrip())]
                if "\t" in lead:
                    out.append(lead.replace("\t", " " * width) + line.lstrip())
                else:
                    out.append(line)
            return out
        if _rewrite_lines(patcher.text(path), transform,
                          "tab di indentazione -> %d spazi" % width, patcher, path):
            n += 1
    return n


def fix_ws_trailing(patcher, findings):
    """Rimuove spazi e tab a fine riga."""
    n = 0
    paths = {f.path for f in patcher.by_rule(findings, "ws-trailing")}
    for path in paths:
        def transform(lines):
            return [l.rstrip() for l in lines]
        if _rewrite_lines(patcher.text(path), transform,
                          "rimossi spazi/tab a fine riga", patcher, path):
            n += 1
    return n


def fix_ws_final_newline(patcher, findings):
    """Aggiunge il newline finale mancante."""
    n = 0
    for f in patcher.by_rule(findings, "ws-final-newline"):
        text = patcher.text(f.path)
        if not text or text.endswith("\n"):
            continue
        if patcher.save(f.path, text + "\n", "aggiunto newline finale"):
            n += 1
    return n


def fix_file_exec_bit(patcher, findings):
    """Rende eseguibili gli script (anche per git, che registra il modo 100755)."""
    n = 0
    paths = {f.path for f in patcher.by_rule(findings, "file-exec-bit")}
    for path in paths:
        if not os.path.isfile(path):
            continue
        mode = stat.S_IMODE(os.stat(path).st_mode) | 0o111
        if patcher.chmod(path, mode, "permesso di esecuzione"):
            n += 1
    return n


def fix_file_leftover(patcher, findings):
    """Elimina i residui di merge/editor committati per errore."""
    n = 0
    paths = {f.path for f in patcher.by_rule(findings, "file-leftover")}
    for path in paths:
        if patcher.remove(path, "eliminato file residuo"):
            n += 1
    return n


def fix_gitignore_add(patcher, findings):
    """Aggiunge a .gitignore i percorsi di build non coperti."""
    fs = patcher.by_rule(findings, "gitignore-add")
    if not fs:
        return 0
    path = os.path.join(patcher.ctx.root, ".gitignore")
    text = patcher.text(path) if os.path.isfile(path) else ""
    missing = []
    for f in fs:
        m = re.search(r"non copre (\S+)", f.message)
        if m and m.group(1) not in text:
            missing.append(m.group(1))
    if not missing:
        return 0
    add = ("\n" if text and not text.endswith("\n") else "") + \
        "\n".join(missing) + "\n"
    return 1 if patcher.save(path, text + add,
                             ".gitignore: aggiunti %s" % ", ".join(missing)) else 0


def fix_shebang(patcher, findings, rules, line):
    n = 0
    paths = set()
    for rule in rules:
        paths |= {f.path for f in patcher.by_rule(findings, rule)}
    for path in paths:
        text = patcher.text(path)
        if text.startswith("#!"):
            continue
        if patcher.save(path, line + "\n" + text, "aggiunto shebang %s" % line):
            n += 1
    return n


def fix_sh_shebang(patcher, findings):
    """Aggiunge lo shebang bash agli script shell."""
    return fix_shebang(patcher, findings, ("sh-shebang",), "#!/usr/bin/env bash")


def fix_py_shebang(patcher, findings):
    """Aggiunge lo shebang python3 agli script Python."""
    return fix_shebang(patcher, findings, ("py-shebang",), "#!/usr/bin/env python3")


def fix_sh_strict(patcher, findings):
    """Inserisce `set -euo pipefail` dopo shebang e intestazione di commenti."""
    n = 0
    for f in patcher.by_rule(findings, "sh-strict"):
        lines = patcher.text(f.path).split("\n")
        idx = 0
        if lines and lines[0].startswith("#!"):
            idx = 1
        while idx < len(lines) and (lines[idx].startswith("#") or not lines[idx].strip()):
            idx += 1
        lines.insert(idx, "set -euo pipefail")
        lines.insert(idx + 1, "")
        if patcher.save(f.path, "\n".join(lines),
                        "aggiunto `set -euo pipefail`"):
            n += 1
    return n


def _drop_import_lines(patcher, findings, rule, why):
    n = 0
    byfile = {}
    for f in patcher.by_rule(findings, rule):
        if f.line:
            byfile.setdefault(f.path, set()).add(f.line)
    for path, linenos in byfile.items():
        lines = patcher.text(path).split("\n")
        keep = []
        dropped = []
        for num, line in enumerate(lines, 1):
            if num in linenos and re.match(r"^\s*import\b", line):
                dropped.append(line.strip())
                continue
            keep.append(line)
        if dropped and patcher.save(path, "\n".join(keep),
                                    "%s: %s" % (why, ", ".join(dropped))):
            n += 1
    return n


def fix_py_unused_import(patcher, findings):
    """Rimuove gli import Python il cui nome non compare mai nel file."""
    return _drop_import_lines(patcher, findings, "py-unused-import",
                              "rimosso import inutilizzato")


def fix_java_unused_import(patcher, findings):
    """Rimuove gli import Java il cui nome non compare mai nel file."""
    return _drop_import_lines(patcher, findings, "java-unused-import",
                              "rimosso import inutilizzato")


def fix_java_package(patcher, findings):
    """Allinea la dichiarazione `package` al percorso del file."""
    n = 0
    src_root = os.path.join(patcher.ctx.root, "app", "src", "main", "java")
    for f in patcher.by_rule(findings, "java-package"):
        rel = os.path.relpath(os.path.dirname(f.path), src_root)
        if rel.startswith(".."):
            continue
        want = rel.replace(os.sep, ".")
        text = patcher.text(f.path)
        new = re.sub(r"^(\s*package\s+)[\w.]+(\s*;)", r"\g<1>%s\g<2>" % want,
                     text, count=1, flags=re.M)
        if new != text and patcher.save(f.path, new,
                                        "package allineato al percorso (%s)" % want):
            n += 1
    return n


def _insert_before_jobs(path, block, patcher, why):
    """Inserisce un blocco di primo livello prima di `jobs:` (o in coda)."""
    lines = patcher.text(path).split("\n")
    idx = None
    for num, line in enumerate(lines):
        if re.match(r"^jobs\s*:", line):
            idx = num
            break
    if idx is None:
        idx = len(lines)
    while idx > 0 and not lines[idx - 1].strip():
        idx -= 1
    head, tail = lines[:idx], lines[idx:]
    # una riga vuota separa i blocchi di primo livello, come nel resto del file
    lead = [""] if head and head[-1].strip() else []
    sep = [] if (tail and not tail[0].strip()) else [""]
    new = head + lead + block + sep + tail
    return patcher.save(path, "\n".join(new), why)


def fix_wf_permissions(patcher, findings):
    """Aggiunge `permissions: contents: read` (least privilege di default)."""
    n = 0
    paths = sorted({f.path for f in patcher.by_rule(findings, "wf-permissions")})
    for path in paths:
        if re.search(r"^permissions\s*:", patcher.text(path), re.M):
            continue
        if _insert_before_jobs(path, ["permissions:", "  contents: read"], patcher,
                               "aggiunte permissions minime (contents: read)"):
            n += 1
    return n


def fix_wf_concurrency(patcher, findings):
    """Aggiunge il blocco `concurrency` per non accumulare corse parallele."""
    n = 0
    paths = sorted({f.path for f in patcher.by_rule(findings, "wf-concurrency")})
    for path in paths:
        text = patcher.text(path)
        if re.search(r"^concurrency\s*:", text, re.M):
            continue
        group = os.path.splitext(os.path.basename(path))[0]
        # chi scrive sul repo (release, push automatici) non va mai interrotto
        cancel = "false" if re.search(r"^\s*contents\s*:\s*write", text, re.M) else "true"
        block = ["concurrency:",
                 "  group: %s-${{ github.ref }}" % group,
                 "  cancel-in-progress: %s" % cancel]
        if _insert_before_jobs(path, block, patcher,
                               "aggiunto blocco concurrency (cancel-in-progress: %s)"
                               % cancel):
            n += 1
    return n


def fix_manifest_exported(patcher, findings):
    """Aggiunge `android:exported` esplicito ai componenti con intent-filter."""
    n = 0
    byfile = {}
    for f in findings:
        if f.fix and f.fix.startswith("manifest-exported:"):
            byfile.setdefault(f.path, []).append((f.line, f.fix.split(":", 1)[1]))
    for path, items in byfile.items():
        lines = patcher.text(path).split("\n")
        for line_no, value in sorted(items, reverse=True):
            if line_no is None or line_no < 1 or line_no > len(lines):
                continue
            line = lines[line_no - 1]
            if "android:exported" in line:
                continue
            m = re.match(r"^(\s*)<(\w+)(\s+android:name=\"[^\"]+\")?(.*)$", line)
            if not m:
                continue
            indent, tag, name_attr, rest = m.groups()
            attr = 'android:exported="%s"' % value
            if name_attr:
                lines[line_no - 1] = "%s<%s%s\n%s    %s%s" % (
                    indent, tag, name_attr, indent, attr, rest)
            else:
                lines[line_no - 1] = "%s<%s %s%s" % (indent, tag, attr, rest)
        if patcher.save(path, "\n".join(lines),
                        "aggiunto android:exported esplicito"):
            n += 1
    return n


def fix_data_dedupe(patcher, findings):
    """Rimuove le voci duplicate dai file in data/ (tiene la prima)."""
    n = 0
    paths = sorted({f.path for f in patcher.by_rule(findings, "data-dedupe")})
    for path in paths:
        lines = patcher.text(path).split("\n")
        seen, keep, dropped = set(), [], 0
        for line in lines:
            s = line.strip()
            if s and not s.startswith("#"):
                key = re.sub(r"\s+", " ", s.lower())
                # per i pattern conta la coppia tipo|valore, per le firme il pacchetto
                head = "|".join(key.split("|")[:2]) if "|" in key else key.split("=")[0]
                if head in seen:
                    dropped += 1
                    continue
                seen.add(head)
            keep.append(line)
        if dropped and patcher.save(path, "\n".join(keep),
                                    "rimosse %d voci duplicate" % dropped):
            n += 1
    return n


def fix_res_unused(patcher, findings):
    """Rimuove le risorse (string/color/style) mai referenziate. Solo --improve."""
    n = 0
    res_dir = os.path.join(patcher.ctx.root, "app", "src", "main", "res", "values")
    wanted = {}
    for f in patcher.by_rule(findings, "res-unused"):
        m = re.match(r"(string|color|style) `([^`]+)`", f.message)
        if m:
            wanted.setdefault(m.group(1), set()).add(m.group(2))
    if not wanted:
        return 0
    for name in sorted(os.listdir(res_dir)):
        path = os.path.join(res_dir, name)
        if not name.endswith(".xml") or not os.path.isfile(path):
            continue
        lines = patcher.text(path).split("\n")
        keep, dropped = [], []
        for line in lines:
            m = re.match(r'\s*<(string|color|style)\s+[^>]*name="([^"]+)"', line)
            if m and m.group(2) in wanted.get(m.group(1), ()) and "</" in line:
                dropped.append("%s/%s" % (m.group(1), m.group(2)))
                continue
            keep.append(line)
        if dropped and patcher.save(path, "\n".join(keep),
                                    "rimosse risorse inutilizzate: %s"
                                    % ", ".join(dropped)):
            n += 1
    return n


def fix_docs_workflow_row(patcher, findings):
    """Aggiunge alla tabella di docs/SECURITY.md le workflow non documentate."""
    fs = patcher.by_rule(findings, "docs-workflow-row")
    if not fs:
        return 0
    doc = os.path.join(patcher.ctx.root, "docs", "SECURITY.md")
    if not os.path.isfile(doc):
        return 0
    lines = patcher.text(doc).split("\n")
    # ultima riga della prima tabella (| Livello | Cosa | Dove |)
    start = None
    for num, line in enumerate(lines):
        if line.startswith("| Livello |"):
            start = num
            break
    if start is None:
        return 0
    end = start + 2
    while end < len(lines) and lines[end].startswith("|"):
        end += 1
    rows = []
    for f in fs:
        wf_path = f.path or os.path.join(patcher.ctx.root, ".github",
                                         "workflows", "?")
        wfname = os.path.basename(os.path.relpath(wf_path, patcher.ctx.root))
        name, desc = _workflow_headline(wf_path)
        rows.append("| **%s** | %s | `%s` |" % (name or wfname, desc, wfname))
    new = lines[:end] + rows + lines[end:]
    return 1 if patcher.save(doc, "\n".join(new),
                             "docs/SECURITY.md: documentate %s"
                             % ", ".join(os.path.basename(r.split("`")[-2])
                                         for r in rows if r.count("`") >= 2)) else 0


def _workflow_headline(path):
    """(name, descrizione) di una workflow, presi dal file stesso."""
    if not os.path.isfile(path):
        return None, "workflow"
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    name = None
    for line in lines:
        m = re.match(r"^name:\s*(.+)$", line)
        if m:
            name = m.group(1).strip().strip("\"'")
            break
    # primo blocco di commenti significativo (anche dopo `name:`/`on:`)
    desc, started = [], False
    for line in lines:
        if line.lstrip().startswith("#") and not line.startswith("#!"):
            body = line.lstrip()[1:].strip()
            if body:
                desc.append(body)
                started = True
        elif started:
            break
        elif line.strip() and not re.match(r"^(name|on|permissions|concurrency)\s*:", line):
            break
    text_desc = " ".join(desc)
    if len(text_desc) > 180:
        text_desc = text_desc[:177] + "..."
    return name, (text_desc or "controlli automatici")


def fix_data_threatdb(patcher, findings):
    """Rigenera ThreatDbGenerated.java dai data/ (delega allo script del progetto)."""
    if not patcher.by_rule(findings, "data-threatdb"):
        return 0
    before = _threatdb_text(patcher.ctx.root)
    ok = patcher.delegate("update-threat-db.py", [],
                          "rigenerato ThreatDbGenerated.java dai data/")
    if ok and before == _threatdb_text(patcher.ctx.root):
        patcher.skipped.append({"why": "ThreatDbGenerated gia' allineato"})
        return 0
    return 1 if ok else 0


def _threatdb_text(root):
    p = os.path.join(root, "app", "src", "main", "java", "it", "spydetector",
                     "app", "core", "ThreatDbGenerated.java")
    if not os.path.isfile(p):
        return ""
    return "\n".join(l for l in open(p, encoding="utf-8").read().split("\n")
                     if "Aggiornato:" not in l)


def fix_wf_pin(patcher, findings):
    """Pinna le action al commit SHA (delega a update-pins.py, serve rete)."""
    if not patcher.by_rule(findings, "wf-pin"):
        return 0
    return 1 if patcher.delegate("update-pins.py", [],
                                 "action pinnate al commit SHA + tag in commento") else 0


# registro: id -> (funzione, richiede --improve?)
FIXERS = {
    "ws-bom": fix_ws_bom,
    "ws-crlf": fix_ws_crlf,
    "expand-tabs": fix_expand_tabs,
    "yaml-tabs": fix_expand_tabs,
    "ws-trailing": fix_ws_trailing,
    "ws-final-newline": fix_ws_final_newline,
    "file-exec-bit": fix_file_exec_bit,
    "file-leftover": fix_file_leftover,
    "gitignore-add": fix_gitignore_add,
    "sh-shebang": fix_sh_shebang,
    "py-shebang": fix_py_shebang,
    "sh-strict": fix_sh_strict,
    "py-unused-import": fix_py_unused_import,
    "java-unused-import": fix_java_unused_import,
    "java-package": fix_java_package,
    "wf-permissions": fix_wf_permissions,
    "wf-concurrency": fix_wf_concurrency,
    "manifest-exported": fix_manifest_exported,
    "data-dedupe": fix_data_dedupe,
    "docs-workflow-row": fix_docs_workflow_row,
    "data-threatdb": fix_data_threatdb,
    "wf-pin": fix_wf_pin,
    "res-unused": fix_res_unused,
}

# regole applicate solo con --improve (miglioramenti, non correzioni di errori)
IMPROVE_ONLY = {"res-unused"}

# ordine di esecuzione: prima il testo "grezzo", poi la struttura, poi le deleghe
ORDER = [
    "ws-bom", "ws-crlf", "yaml-tabs", "expand-tabs", "ws-trailing",
    "ws-final-newline", "file-exec-bit", "file-leftover", "gitignore-add",
    "sh-shebang", "py-shebang", "sh-strict",
    "py-unused-import", "java-unused-import", "java-package",
    "manifest-exported", "data-dedupe", "res-unused",
    "wf-permissions", "wf-concurrency", "docs-workflow-row",
    "data-threatdb", "wf-pin",
]


def collect_fixable(findings, severity=gates.WARN, improve=False,
                    only=None, skip=()):
    """Regole applicabili a questo insieme di finding."""
    limit = gates.SEV_RANK[severity]
    wanted = set()
    for f in findings:
        if not f.fix:
            continue
        if gates.SEV_RANK[f.severity] > limit:
            continue
        rule = f.fix.split(":")[0]
        if rule in IMPROVE_ONLY and not improve:
            continue
        if only and rule not in only:
            continue
        if rule in skip:
            continue
        wanted.add(rule)
    return [r for r in ORDER if r in wanted]


def apply_fixes(ctx, findings, dry_run=False, severity=gates.WARN, improve=False,
                only=None, skip=(), verbose=True):
    """Applica le correzioni e ritorna (patcher, regole_eseguite)."""
    patcher = Patcher(ctx, dry_run=dry_run)
    rules = collect_fixable(findings, severity, improve, only, skip)
    if verbose:
        if rules:
            print("regole di correzione: %s" % ", ".join(rules))
        else:
            print("nessuna correzione automatica applicabile")
    for rule in rules:
        func = FIXERS[rule]
        try:
            count = func(patcher, findings)
        except Exception as exc:  # noqa: BLE001
            patcher.skipped.append({"why": "%s fallita: %s: %s"
                                    % (rule, type(exc).__name__, exc)})
            count = 0
        if verbose and count:
            print("  %-20s %d file" % (rule, count))
    return patcher, rules


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", metavar="PATH",
                    help="leggi le finding da un report di gates.py (default: gira i gate)")
    ap.add_argument("--json", metavar="PATH", help="scrivi il riepilogo in PATH")
    ap.add_argument("--dry-run", action="store_true", help="non scrivere nulla")
    ap.add_argument("--severity", choices=gates.SEVERITIES, default=gates.WARN,
                    help="gravita' massima da correggere (default: warn)")
    ap.add_argument("--improve", action="store_true",
                    help="applica anche i miglioramenti non bloccanti")
    ap.add_argument("--only", metavar="ID", action="append",
                    help="applica solo questa regola (ripetibile)")
    ap.add_argument("--skip", metavar="ID", action="append", default=[],
                    help="salta questa regola (ripetibile)")
    ap.add_argument("--gate", action="append", choices=gates.GATE_NAMES,
                    help="quando gira i gate, esegui solo questi")
    ap.add_argument("--with-build", action="store_true",
                    help="quando gira i gate, includi build+verifica APK")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--list", action="store_true", help="elenca le regole")
    args = ap.parse_args(argv)

    if args.list:
        print("Regole di correzione disponibili:")
        for rule in ORDER:
            doc = (FIXERS[rule].__doc__ or "").strip().split("\n")[0]
            extra = " [solo --improve]" if rule in IMPROVE_ONLY else ""
            print("  %-20s %s%s" % (rule, doc, extra))
        return 0

    ctx = gates.Ctx()
    if args.report:
        findings, _summary, _notes = gates.load_report(args.report)
    else:
        findings = gates.run_gates(ctx, only=set(args.gate or []),
                                   with_build=args.with_build, quiet=args.quiet)

    patcher, rules = apply_fixes(
        ctx, findings, dry_run=args.dry_run, severity=args.severity,
        improve=args.improve, only=set(args.only or []) or None,
        skip=set(args.skip), verbose=not args.quiet)

    if patcher.changes:
        print("\n%s %d modifiche su %d file:" % (
            "Da applicare" if args.dry_run else "Applicate",
            len(patcher.changes), len({c["path"] for c in patcher.changes})))
        for c in patcher.changes:
            print("  %-52s %s" % (c["path"], c["why"]))
    else:
        print("\nNessuna modifica da applicare")
    for s in patcher.skipped:
        print("  saltata: %s" % s["why"])

    if args.json:
        import json
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"schema": 1, "dry_run": args.dry_run, "rules": rules,
                       "changes": patcher.changes, "skipped": patcher.skipped},
                      fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
