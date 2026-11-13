#!/usr/bin/env python3
"""
Prova il ciclo di self-healing su una copia del repository con difetti iniettati.

  python3 scripts/test-selfheal.py            # tutte le fasi
  python3 scripts/test-selfheal.py --keep     # non cancellare la copia di prova

Tre fasi:

  A. difetti **riparabili** -> il ciclo deve chiudere verde (`healed`),
     le correzioni devono essere idempotenti (un secondo giro = `clean`)
     e la build dell'APK deve continuare a funzionare;
  B. difetti **non riparabili** -> il ciclo deve fermarsi (`stuck`), non
     toccare nessun file e restituire esattamente le regole che servono a
     una persona: meglio un errore onesto di una patch inventata;
  C. una correzione che **peggiora** le cose -> il ciclo deve accorgersene
     (`regressed`) e ripristinare l'albero di lavoro.

Serve solo la stdlib. Non tocca il repository vero: lavora in una directory
temporanea con un clone dei file tracciati.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import autofix  # noqa: E402
import gates  # noqa: E402
import selfheal  # noqa: E402

ROOT = gates.ROOT
COPY_IGNORE = shutil.ignore_patterns(".git", ".toolchain", "build", "dist",
                                     "__pycache__", "*.pyc")

PASS, FAIL = "ok  ", "FAIL"
_results = []


def check(name, condition, detail=""):
    _results.append((name, bool(condition)))
    if condition:
        print("  %s %s" % (PASS, name))
    else:
        print("  %s %s — %s" % (FAIL, name, detail))
        # in CI diventa un'annotazione: visibile senza aprire i log
        # (niente newline: romperebbero il formato delle annotazioni)
        flat = " ".join("%s %s" % (name, detail) .split())
        print("::error file=scripts/test-selfheal.py::self-test fallito: %s" % flat)
    return bool(condition)


def sh(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)


# --------------------------------------------------------------------------
# preparazione della copia
# --------------------------------------------------------------------------
def make_copy(dest):
    """Crea la copia di prova e ritorna lo SHA della baseline pulita."""
    shutil.copytree(ROOT, dest, ignore=COPY_IGNORE, dirs_exist_ok=True)
    sh(["git", "init", "-q"], dest)
    sh(["git", "config", "user.email", "selfheal@test.local"], dest)
    sh(["git", "config", "user.name", "selfheal-test"], dest)
    sh(["git", "config", "commit.gpgsign", "false"], dest)
    sh(["git", "add", "-A"], dest)
    r = sh(["git", "commit", "-qm", "baseline"], dest)
    if r.returncode != 0:
        raise RuntimeError("impossibile creare la baseline: %s" % r.stderr)
    return sh(["git", "rev-parse", "HEAD"], dest).stdout.strip()


def reset_copy(dest, sha):
    """Torna alla baseline pulita (albero, index e storico dei commit di prova)."""
    sh(["git", "reset", "--hard", "-q", sha], dest)
    sh(["git", "clean", "-fdq"], dest)


def read(dest, rel):
    with open(os.path.join(dest, rel), encoding="utf-8") as fh:
        return fh.read()


def write(dest, rel, text):
    path = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def strip_top_block(dest, rel, key):
    """Rimuove un blocco YAML di primo livello (chiave + figli piu' indentati)."""
    lines = read(dest, rel).split("\n")
    out, skipping = [], False
    for line in lines:
        if re.match(r"^%s\s*:" % re.escape(key), line):
            skipping = True
            continue
        if skipping:
            if line.strip() and not line.startswith((" ", "\t")):
                skipping = False
            else:
                continue
        out.append(line)
    if len(out) == len(lines):
        raise AssertionError("blocco %s non trovato in %s" % (key, rel))
    write(dest, rel, "\n".join(out))


def stage(dest):
    """Rende visibili a `git ls-files` anche i file appena creati."""
    sh(["git", "add", "-A"], dest)


def sub(dest, rel, old, new, count=1):
    text = read(dest, rel)
    if old not in text:
        raise AssertionError("pattern assente in %s: %r" % (rel, old[:60]))
    write(dest, rel, text.replace(old, new, count))


# --------------------------------------------------------------------------
# difetti riparabili: (nome, regola attesa, funzione di iniezione)
# --------------------------------------------------------------------------
def inj_trailing_ws(d):
    rel = "app/src/main/java/it/spydetector/app/core/Finding.java"
    write(d, rel, read(d, rel).replace("\n", "   \n", 1))


def inj_no_final_newline(d):
    rel = "README.md"
    write(d, rel, read(d, rel).rstrip("\n"))


def inj_crlf(d):
    rel = "data/threat-seed.txt"
    write(d, rel, read(d, rel).replace("\n", "\r\n"))


def inj_bom(d):
    rel = "scripts/verify-apk.py"
    write(d, rel, "\ufeff" + read(d, rel))


def inj_yaml_tabs(d):
    rel = ".github/workflows/secrets.yml"
    write(d, rel, read(d, rel).replace("\n  contents: read", "\n\tcontents: read"))


def inj_java_tabs(d):
    rel = "app/src/main/java/it/spydetector/app/core/Severity.java"
    write(d, rel, read(d, rel).replace("\n    ", "\n\t", 1))


def inj_no_permissions(d):
    strip_top_block(d, ".github/workflows/dependency-review.yml", "permissions")


def inj_no_concurrency(d):
    strip_top_block(d, ".github/workflows/ci.yml", "concurrency")


def inj_unused_java_import(d):
    rel = "app/src/main/java/it/spydetector/app/core/Report.java"
    text = read(d, rel)
    m = re.search(r"^package [\w.]+;\n", text, re.M)
    if not m:
        raise AssertionError("nessuna dichiarazione package in %s" % rel)
    write(d, rel, text[:m.end()] + "\nimport java.math.BigDecimal;\n" + text[m.end():])


def inj_unused_py_import(d):
    rel = "scripts/check-iocs.py"
    text = read(d, rel)
    m = re.search(r"^import tarfile\n", text, re.M)
    if not m:
        raise AssertionError("import di riferimento non trovato in %s" % rel)
    write(d, rel, text[:m.end()] + "import pprint\n" + text[m.end():])


def inj_no_shebang(d):
    rel = "tools/fetch-toolchain.sh"
    write(d, rel, read(d, rel).split("\n", 1)[1])


def inj_no_strict(d):
    rel = "scripts/release.sh"
    write(d, rel, read(d, rel).replace("set -euo pipefail\n", "", 1))


def inj_exec_bit(d):
    rel = "tools/fetch-toolchain.sh"
    r = sh(["git", "update-index", "--chmod=-x", rel], d)
    if r.returncode != 0:
        raise AssertionError("update-index fallito: %s" % r.stderr)
    os.chmod(os.path.join(d, rel), 0o644)


def inj_seed_dup(d):
    rel = "data/threat-seed.txt"
    lines = read(d, rel).split("\n")
    entry = next(l for l in lines if l.count("|") == 3 and not l.startswith("#"))
    write(d, rel, "\n".join(lines[:-1] + [entry, ""]))


def inj_threatdb_drift(d):
    rel = "app/src/main/java/it/spydetector/app/core/ThreatDbGenerated.java"
    write(d, rel, read(d, rel).replace("AccuSpy", "AccuSpyVecchio", 1))


def inj_exported(d):
    sub(d, "app/src/main/AndroidManifest.xml",
        '            android:name="it.spydetector.app.MainActivity"\n'
        '            android:exported="true"\n',
        '            android:name="it.spydetector.app.MainActivity"\n')


def inj_leftover(d):
    write(d, "app/src/main/java/it/spydetector/app/core/Report.java.orig", "residuo\n")


def inj_gitignore(d):
    sub(d, ".gitignore", "dist/\n", "")


def inj_undocumented_workflow(d):
    write(d, ".github/workflows/nightly-extra.yml",
          "name: Nightly Extra\n\n"
          "# Controlli aggiuntivi notturni.\n\n"
          "on:\n  schedule:\n    - cron: '3 3 * * *'\n\n"
          "permissions:\n  contents: read\n\n"
          "jobs:\n  extra:\n    runs-on: ubuntu-latest\n"
          "    steps:\n      - name: nop\n        run: echo ok\n")


def inj_package_mismatch(d):
    rel = "app/src/main/java/it/spydetector/app/core/Severity.java"
    sub(d, rel, "package it.spydetector.app.core;", "package it.spydetector.app.wrong;")


# (nome, regola di correzione, regola del gate da verificare, iniezione)
FIXABLE = [
    ("spazi a fine riga", "ws-trailing", "ws-trailing", inj_trailing_ws),
    ("newline finale mancante", "ws-final-newline", "ws-final-newline", inj_no_final_newline),
    ("fine riga CRLF", "ws-crlf", "ws-crlf", inj_crlf),
    ("BOM UTF-8", "ws-bom", "ws-bom", inj_bom),
    ("tab in YAML", "yaml-tabs", "wf-tab-indent", inj_yaml_tabs),
    ("tab in Java", "expand-tabs", "java-tabs", inj_java_tabs),
    ("permissions mancanti", "wf-permissions", "wf-permissions-missing", inj_no_permissions),
    ("concurrency mancante", "wf-concurrency", "wf-concurrency-missing", inj_no_concurrency),
    ("import Java inutilizzato", "java-unused-import", "java-unused-import", inj_unused_java_import),
    ("import Python inutilizzato", "py-unused-import", "py-unused-import", inj_unused_py_import),
    ("shebang mancante", "sh-shebang", "sh-shebang", inj_no_shebang),
    ("strict mode mancante", "sh-strict", "sh-strict", inj_no_strict),
    ("permesso di esecuzione", "file-exec-bit", "file-exec-bit", inj_exec_bit),
    ("voce duplicata nei data", "data-dedupe", "data-seed-dup", inj_seed_dup),
    ("codice generato non allineato", "data-threatdb", "data-threatdb-sync", inj_threatdb_drift),
    ("android:exported mancante", "manifest-exported", "manifest-exported-missing", inj_exported),
    ("file residuo", "file-leftover", "file-leftover", inj_leftover),
    (".gitignore incompleto", "gitignore-add", "gitignore-outputs", inj_gitignore),
    ("workflow non documentata", "docs-workflow-row", "docs-workflow-undocumented", inj_undocumented_workflow),
    ("package Java sbagliato", "java-package", "java-package-path", inj_package_mismatch),
]

# --------------------------------------------------------------------------
# difetti NON riparabili: il ciclo deve segnalarli, non inventare una patch
# --------------------------------------------------------------------------
def inj_unpinned_action(d):
    sub(d, ".github/workflows/ci.yml",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "actions/checkout@v7")


def inj_claim(d):
    sub(d, "README.md", "## Privacy\n",
        "## Privacy\n\nL'app non ha il permesso Internet.\n")


def inj_broken_link(d):
    sub(d, "README.md", "](docs/SECURITY.md)", "](docs/INESISTENTE.md)")


def inj_shell_syntax(d):
    sub(d, "scripts/release.sh", "#!/usr/bin/env bash", "#!/usr/bin/env bash\nif [ 1 ; then")


def inj_unregistered_check(d):
    sub(d, "app/src/main/java/it/spydetector/app/core/Engine.java",
        "        l.add(new MessagingCheck());\n", "")


def inj_dangerous_permission(d):
    sub(d, "app/src/main/AndroidManifest.xml",
        '    <uses-permission android:name="android.permission.INTERNET" />',
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        '    <uses-permission android:name="android.permission.READ_SMS" />')


def inj_injection(d):
    sub(d, ".github/workflows/ci.yml", "jobs:\n",
        "jobs:\n  echo-title:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - name: titolo\n        env: {}\n"
        "        run: echo \"${{ github.event.pull_request.title }}\"\n\n")


def inj_invalid_yaml(d):
    write(d, ".github/workflows/secrets.yml",
          read(d, ".github/workflows/secrets.yml") + "\n  rotto: non: yaml\n")


def inj_unverified_download(d):
    sub(d, ".github/workflows/ci.yml", "  build:\n",
        "  scarica:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: tool\n        run: |\n"
        "          curl -sSL -o tool.tgz https://example.com/tool.tgz\n"
        "          tar xzf tool.tgz\n          ./tool --version\n\n  build:\n")


# (nome, regola, iniezione, correzione solo con la rete)
MANUAL = [
    ("affermazione di privacy falsa", "claim-no-internet", inj_claim, None),
    ("collegamento rotto", "docs-link-broken", inj_broken_link, None),
    ("sintassi shell rotta", "sh-syntax", inj_shell_syntax, None),
    ("check non registrato", "java-check-not-registered", inj_unregistered_check, None),
    ("permesso pericoloso", "manifest-permission-dangerous",
     inj_dangerous_permission, None),
    ("script injection", "wf-run-injection", inj_injection, None),
    ("binario non verificato", "wf-unverified-download", inj_unverified_download, None),
    # rilevato solo se pyyaml e' installato (dipendenza in scripts/requirements.txt)
    ("YAML non valido", "yaml-invalid", inj_invalid_yaml, None),
    # il pin si puo' rifare, ma serve l'API GitHub: offline resta in carico a noi
    ("action non pinnata a SHA", "wf-pin-drift", inj_unpinned_action, "wf-pin"),
]


# --------------------------------------------------------------------------
# fasi
# --------------------------------------------------------------------------
def phase_fixable(dest, sha):
    print("\n=== fase A: difetti riparabili (%d) ===" % len(FIXABLE))
    # la copia pulita non deve avere errori: eventuali avvisi dipendono
    # dall'ambiente (es. shellcheck installato o no) e non contano qui
    reset_copy(dest, sha)
    baseline = gates.run_gates(gates.Ctx(root=dest), skip=("build",), quiet=True)
    base_errors = [f for f in baseline if f.severity == gates.ERROR]
    check("A/baseline senza errori", not base_errors,
          "%s" % [str(f) for f in base_errors[:3]])
    print("  --   baseline: %d errori, %d avvisi (dipendono dall'ambiente)"
          % (len(base_errors), sum(1 for f in baseline if f.severity == gates.WARN)))

    applied_rules = set()
    for name, fix_id, gate_rule, inject in FIXABLE:
        reset_copy(dest, sha)
        inject(dest)
        stage(dest)
        ctx = gates.Ctx(root=dest)
        before = gates.run_gates(ctx, skip=("build",), quiet=True)
        detected = [f for f in before if f.rule == gate_rule]
        if not check("A/%s: rilevato (%s)" % (name, gate_rule), detected,
                     "nessuna finding %s; viste: %s"
                     % (gate_rule, sorted({f.rule for f in before})[:8])):
            continue
        # il pin delle action serve rete: lo escludiamo dal test
        patcher, rules = autofix.apply_fixes(ctx, before, severity=gates.WARN,
                                             skip={"wf-pin"}, verbose=False)
        applied_rules.update(rules)
        after = gates.run_gates(gates.Ctx(root=dest), skip=("build",), quiet=True)
        left = [f for f in after if f.rule == gate_rule]
        ok = check("A/%s: riparato da %s" % (name, fix_id),
                   bool(patcher.changes) and not left and fix_id in rules,
                   "cambiamenti=%d, residui=%s, regole=%s"
                   % (len(patcher.changes), [str(f) for f in left][:2], rules[:6]))
        if not ok:
            for f in left[:4]:
                print("        residuo: %s" % f)
    check("A/tutte le regole riparabili sono state usate",
          applied_rules >= {r for _n, r, _g, _f in FIXABLE},
          "mancano: %s" % sorted({r for _n, r, _g, _f in FIXABLE} - applied_rules))

    # idempotenza: tutto insieme, due giri di seguito
    print("\n=== fase A2: tutti i difetti insieme + idempotenza ===")
    reset_copy(dest, sha)
    for _name, _fix, _rule, inject in FIXABLE:
        if inject is not inj_exec_bit:       # tocca l'index: va fatto per ultimo
            inject(dest)
    inj_exec_bit(dest)
    stage(dest)
    result = selfheal.run_loop(max_rounds=4, root=dest, skip_gates=("build",),
                               autofix_skip={"wf-pin"}, verbose=False)
    left_rules = {f["rule"] for f in result["remaining"]}
    expected = {r for _n, _f, r, _i in FIXABLE}
    final_errors = result["final"].get("errors", 0)
    check("A2/nessuna delle regole iniettate resta aperta",
          not (left_rules & expected),
          "restano: %s" % sorted(left_rules & expected))
    check("A2/errori non peggiori della baseline", final_errors <= len(base_errors),
          "finali=%d baseline=%d" % (final_errors, len(base_errors)))
    check("A2/ciclo chiuso verde", result["status"] in (selfheal.HEALED,
                                                        selfheal.CLEAN),
          "stato=%s, errori=%d" % (result["status"], final_errors))
    for f in result["remaining"][:5]:
        print("        residuo: %(rule)s %(path)s %(message).80s" % f)
    again = selfheal.run_loop(max_rounds=2, root=dest, skip_gates=("build",),
                              autofix_skip={"wf-pin"}, verbose=False)
    check("A2/secondo giro = niente da fare (idempotente)",
          again["status"] == selfheal.CLEAN and not again["changed_files"],
          "stato=%s, file=%s" % (again["status"], again["changed_files"]))
    check("A2/report e riepilogo prodotti",
          bool(result["rounds"]) and "Self-healing" in selfheal.markdown(result))


def phase_manual(dest, sha):
    print("\n=== fase B: difetti non riparabili (%d) ===" % len(MANUAL))
    for name, rule, inject, net_fix in MANUAL:
        if rule == "yaml-invalid" and gates._yaml is None:
            print("  --   B/%s: saltato (pyyaml non installato)" % name)
            continue
        reset_copy(dest, sha)
        inject(dest)
        stage(dest)
        ctx = gates.Ctx(root=dest)
        found = gates.run_gates(ctx, skip=("build",), quiet=True)
        hit = [f for f in found if f.rule == rule]
        if not check("B/%s: rilevato (%s)" % (name, rule), hit,
                     "regole viste: %s" % sorted({f.rule for f in found})[:8]):
            continue
        check("B/%s: %s" % (name, "correzione possibile solo con la rete"
                            if net_fix else "nessuna correzione automatica promessa"),
              all((f.fix or "").split(":")[0] == net_fix if net_fix else not f.fix
                  for f in hit),
              "fix=%s" % [f.fix for f in hit])
        patcher, _rules = autofix.apply_fixes(ctx, found, skip={"wf-pin"},
                                              verbose=False)
        # il difetto deve restare dov'e': niente patch inventate
        still = gates.run_gates(gates.Ctx(root=dest), skip=("build",), quiet=True)
        check("B/%s: il difetto resta e non viene toccato" % name,
              any(f.rule == rule for f in still),
              "scomparso dopo le correzioni (file toccati: %s)"
              % sorted({c["path"] for c in patcher.changes})[:3])


def phase_regression(dest, sha):
    print("\n=== fase C: correzione che peggiora le cose ===")
    reset_copy(dest, sha)
    # una modifica reale nell'albero, da annullare se il ciclo regredisce
    write(dest, "REGRESSIONE.txt", "da annullare\n")
    stage(dest)

    calls = {"n": 0}
    real_gates = gates.run_gates
    real_fixes = autofix.apply_fixes

    def fake_gates(ctx, **kw):
        calls["n"] += 1
        f = [gates.Finding("finto", "finto-errore", gates.ERROR, None,
                           message="errore %d" % calls["n"], fix="ws-trailing")]
        return f * calls["n"]          # a ogni giro gli errori aumentano

    class FakePatcher(object):
        changes = [{"path": "REGRESSIONE.txt", "why": "finta correzione"}]
        skipped = []

    gates.run_gates = fake_gates
    autofix.apply_fixes = lambda *a, **k: (FakePatcher(), ["ws-trailing"])
    try:
        result = selfheal.run_loop(max_rounds=3, root=dest, verbose=False,
                                   revert_on_regression=True)
    finally:
        gates.run_gates = real_gates
        autofix.apply_fixes = real_fixes

    check("C/stato = regressed", result["status"] == selfheal.REGRESSED,
          "stato=%s" % result["status"])
    check("C/albero ripristinato (git reset + clean)",
          not os.path.exists(os.path.join(dest, "REGRESSIONE.txt")),
          "REGRESSIONE.txt ancora presente")
    check("C/nessun file modificato dichiarato", not result["changed_files"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true",
                    help="non cancellare la copia di prova")
    ap.add_argument("--dest", metavar="DIR", help="dove creare la copia di prova")
    ap.add_argument("--phase", choices=("A", "B", "C"), action="append",
                    help="esegui solo questa fase (ripetibile)")
    args = ap.parse_args(argv)

    folder = args.dest or tempfile.mkdtemp(prefix="spydetector-selfheal-")
    print("copia di prova: %s" % folder)
    sha = make_copy(folder)
    try:
        phases = set(args.phase or ("A", "B", "C"))
        if "A" in phases:
            phase_fixable(folder, sha)
        if "B" in phases:
            phase_manual(folder, sha)
        if "C" in phases:
            phase_regression(folder, sha)
    finally:
        if args.keep or args.dest:
            print("\ncopia conservata in %s" % folder)
        else:
            shutil.rmtree(folder, ignore_errors=True)

    failed = [n for n, ok in _results if not ok]
    print("\n%d controlli, %d falliti" % (len(_results), len(failed)))
    for name in failed:
        print("  FALLITO: %s" % name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
