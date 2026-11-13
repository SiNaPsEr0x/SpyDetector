#!/usr/bin/env python3
"""
Ciclo di self-healing: gate -> correzione -> di nuovo gate, finche' il repo
e' verde o finche' le correzioni automatiche non bastano piu'.

  python3 scripts/selfheal.py                          # fino a 3 round
  python3 scripts/selfheal.py --max-rounds 5 --with-build
  python3 scripts/selfheal.py --improve                # anche i miglioramenti
  python3 scripts/selfheal.py --dry-run                # guarda, non toccare
  python3 scripts/selfheal.py --revert-on-regression   # annulla se peggiora

Come gira un round:

  1. esegue i gate (scripts/gates.py) e conta le finding;
  2. se non ci sono errori -> FINE, stato `clean`/`healed`;
  3. applica le correzioni deterministiche (scripts/autofix.py);
  4. se non ha cambiato niente -> FINE, stato `stuck` (serve una persona);
  5. altrimenti ricomincia: le correzioni possono svelare problemi nuovi
     (un import rimosso puo' rompere la build, un pin aggiornato puo'
     cambiare il comportamento di una workflow).

Il ciclo non puo' girare all'infinito: si ferma a --max-rounds e anche quando
un round non riduce gli errori. Con --revert-on-regression, se gli errori
aumentano rispetto all'inizio l'albero di lavoro viene ripristinato con git:
una correzione automatica che peggiora le cose non deve sopravvivere.

Uscita: 0 = verde (pulito o riparato), 1 = errori residui, 2 = errore interno.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import autofix  # noqa: E402
import gates  # noqa: E402

ROOT = gates.ROOT

CLEAN, HEALED, STUCK, REGRESSED, ERROR = "clean", "healed", "stuck", "regressed", "error"


def _count(findings):
    return {s: sum(1 for f in findings if f.severity == s) for s in gates.SEVERITIES}


def run_loop(max_rounds=3, with_build=False, improve=False, dry_run=False,
             only_gates=(), skip_gates=(), severity=gates.WARN,
             revert_on_regression=False, verbose=True, autofix_only=None,
             autofix_skip=(), root=ROOT):
    """Esegue il ciclo e ritorna un dizionario con lo stato finale."""
    rounds = []
    executed = []
    changed_files = set()
    status = ERROR
    findings = []
    summary = {}
    baseline_errors = None

    for index in range(1, max_rounds + 1):
        if verbose:
            print("\n===== round %d/%d =====" % (index, max_rounds))
        # contesto nuovo a ogni round: le correzioni possono creare o cancellare
        # file, e l'elenco dei file tracciati deve essere quello attuale
        ctx = gates.Ctx(root=root)
        findings = gates.run_gates(ctx, only=set(only_gates), skip=set(skip_gates),
                                   with_build=with_build, quiet=not verbose,
                                   executed=executed)
        summary = gates.summarize(findings, executed=executed)
        counts = _count(findings)
        if baseline_errors is None:
            baseline_errors = counts[gates.ERROR]

        if counts[gates.ERROR] == 0 and index == 1:
            status = CLEAN
            rounds.append({"round": index, "counts": counts, "changes": 0,
                           "rules": [], "files": []})
            if verbose:
                print("nessun errore: niente da riparare")
            break
        if counts[gates.ERROR] == 0:
            status = HEALED
            rounds.append({"round": index, "counts": counts, "changes": 0,
                           "rules": [], "files": []})
            if verbose:
                print("repo verde dopo %d round di correzioni" % (index - 1))
            break

        patcher, rules = autofix.apply_fixes(
            ctx, findings, dry_run=dry_run, severity=severity, improve=improve,
            only=autofix_only, skip=autofix_skip, verbose=verbose)
        files = sorted({c["path"] for c in patcher.changes if c["path"] != "-"})
        changed_files.update(files)
        rounds.append({"round": index, "counts": counts,
                       "changes": len(patcher.changes), "rules": rules,
                       "files": files, "skipped": patcher.skipped,
                       "summary": summary})

        if not patcher.changes:
            status = STUCK
            if verbose:
                print("nessuna correzione automatica applicabile: %d errori restano "
                      "in carico a una persona" % counts[gates.ERROR])
            break

        # un round che non riduce gli errori non sta progredendo
        prev = rounds[-2]["counts"][gates.ERROR] if len(rounds) > 1 else None
        if prev is not None and counts[gates.ERROR] >= prev:
            if index < max_rounds:
                if verbose:
                    print("gli errori non scendono (%d -> %d): mi fermo qui"
                          % (prev, counts[gates.ERROR]))
                status = STUCK
                break
    else:
        status = STUCK

    # ricontrolla dopo l'ultimo giro di correzioni (il ciclo esce dal for quando
    # ha appena modificato dei file senza averli ancora riverificati)
    if status == STUCK and rounds and rounds[-1]["changes"]:
        if verbose:
            print("\n===== verifica finale =====")
        ctx = gates.Ctx(root=root)
        findings = gates.run_gates(ctx, only=set(only_gates), skip=set(skip_gates),
                                   with_build=with_build, quiet=not verbose,
                                   executed=executed)
        summary = gates.summarize(findings, executed=executed)
        counts = _count(findings)
        rounds.append({"round": len(rounds) + 1, "counts": counts, "changes": 0,
                       "rules": [], "files": []})
        if counts[gates.ERROR] == 0:
            status = HEALED
    # una correzione automatica che aumenta gli errori non e' una correzione
    if status == STUCK and baseline_errors is not None \
            and summary.get("errors", 0) > baseline_errors:
        status = REGRESSED

    if status == REGRESSED and revert_on_regression and not dry_run:
        if verbose:
            print("\nREGRESSIONE: %d errori contro i %d iniziali -> ripristino"
                  % (summary.get("errors", 0), baseline_errors or 0))
        # reset --hard: annulla anche cio' che era stato aggiunto all'index;
        # clean -fd (senza -x) toglie i file nuovi ma lascia gli artefatti
        # ignorati come build/ e dist/
        for cmd in (["git", "-C", root, "reset", "--hard", "-q"],
                    ["git", "-C", root, "clean", "-fdq"]):
            subprocess.run(cmd, capture_output=True, timeout=120)
        ctx = gates.Ctx(root=root)
        findings = gates.run_gates(ctx, only=set(only_gates), skip=set(skip_gates),
                                   with_build=with_build, quiet=True,
                                   executed=executed)
        summary = gates.summarize(findings, executed=executed)
        changed_files = set()

    result = {
        "schema": 1,
        "status": status,
        "rounds": rounds,
        "baseline_errors": baseline_errors or 0,
        "final": summary,
        "changed_files": sorted(changed_files),
        "healed": status in (CLEAN, HEALED),
        "improved": bool(changed_files),
        "remaining": [f.to_dict() for f in findings if f.severity == gates.ERROR],
        "manual": sorted({f.rule for f in findings
                          if f.severity == gates.ERROR and not f.fix}),
        "notes": ctx.notes,
        "dry_run": dry_run,
    }
    return result


def markdown(result, title="Self-healing"):
    """Riepilogo leggibile (job summary della CI e corpo della PR)."""
    status = result["status"]
    label = {CLEAN: "verde (niente da fare)", HEALED: "riparato",
             STUCK: "servono interventi manuali", REGRESSED: "regressione annullata",
             ERROR: "errore interno"}[status]
    lines = ["### %s — %s" % (title, label), ""]
    lines.append("| round | errori | avvisi | info | correzioni | file toccati |")
    lines.append("|---:|---:|---:|---:|---:|---:|")
    for r in result["rounds"]:
        c = r["counts"]
        lines.append("| %d | %d | %d | %d | %d | %d |" % (
            r["round"], c[gates.ERROR], c[gates.WARN], c[gates.INFO],
            r["changes"], len(r["files"])))
    if result["changed_files"]:
        lines += ["", "**File modificati** (%d):" % len(result["changed_files"]), ""]
        for f in result["changed_files"]:
            lines.append("- `%s`" % f)
    rules = sorted({r for rnd in result["rounds"] for r in rnd.get("rules", [])})
    if rules:
        lines += ["", "Regole applicate: " + ", ".join("`%s`" % r for r in rules)]
    if result["remaining"]:
        lines += ["", "**Errori residui** (%d):" % len(result["remaining"]), ""]
        for f in result["remaining"][:25]:
            where = f["path"] + ((":%s" % f["line"]) if f.get("line") else "")
            msg = " ".join(f["message"].split())
            if len(msg) > 180:
                msg = msg[:177] + "..."
            lines.append("- `%s` in `%s` — %s" % (f["rule"], where, msg))
        if len(result["remaining"]) > 25:
            lines.append("- ... altre %d" % (len(result["remaining"]) - 25))
    skipped = [s["why"] for rnd in result["rounds"] for s in rnd.get("skipped", [])]
    if skipped:
        lines += ["", "Correzioni saltate:"] + ["- %s" % s for s in dict.fromkeys(skipped)]
    for note in result.get("notes", []):
        lines += ["", "_nota: %s_" % note]
    lines.append("")
    return "\n".join(lines)


def write_outputs(result, json_path=None, md_path=None, step_summary=False):
    if json_path:
        os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    text = markdown(result)
    if md_path:
        os.makedirs(os.path.dirname(os.path.abspath(md_path)), exist_ok=True)
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    # nella CI: outputs del job e step summary
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        final = result["final"]
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("status=%s\n" % result["status"])
            fh.write("healed=%s\n" % str(result["healed"]).lower())
            fh.write("improved=%s\n" % str(result["improved"]).lower())
            fh.write("rounds=%d\n" % len(result["rounds"]))
            fh.write("errors=%d\n" % final.get("errors", 0))
            fh.write("warnings=%d\n" % final.get("warnings", 0))
            fh.write("changed-files=%d\n" % len(result["changed_files"]))
            fh.write("manual=%s\n" % ",".join(result["manual"]))
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY") if step_summary else None
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-rounds", type=int, default=3,
                    help="quanti cicli gate->correzione al massimo (default 3)")
    ap.add_argument("--with-build", action="store_true",
                    help="includi build.sh + verify-apk.py nei gate")
    ap.add_argument("--improve", action="store_true",
                    help="applica anche i miglioramenti non bloccanti")
    ap.add_argument("--dry-run", action="store_true", help="non scrivere nulla")
    ap.add_argument("--severity", choices=gates.SEVERITIES, default=gates.WARN,
                    help="gravita' massima da correggere (default: warn)")
    ap.add_argument("--gate", action="append", choices=gates.GATE_NAMES, default=[],
                    help="esegui solo questi gate (ripetibile)")
    ap.add_argument("--skip", action="append", choices=gates.GATE_NAMES, default=[],
                    help="salta questi gate (ripetibile)")
    ap.add_argument("--fix-only", metavar="ID", action="append",
                    help="applica solo questa regola di correzione")
    ap.add_argument("--fix-skip", metavar="ID", action="append", default=[],
                    help="salta questa regola di correzione")
    ap.add_argument("--revert-on-regression", action="store_true",
                    help="ripristina l'albero di lavoro se gli errori aumentano")
    ap.add_argument("--json", metavar="PATH", help="scrivi il report JSON")
    ap.add_argument("--markdown", metavar="PATH", help="scrivi il riepilogo Markdown")
    ap.add_argument("--root", metavar="DIR", default=ROOT,
                    help="radice del repo (default: la repo del progetto)")
    ap.add_argument("--step-summary", action="store_true",
                    help="aggiungi il riepilogo a $GITHUB_STEP_SUMMARY")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.max_rounds < 1:
        print("ERRORE: --max-rounds deve essere >= 1", file=sys.stderr)
        return 2
    try:
        result = run_loop(max_rounds=args.max_rounds, with_build=args.with_build,
                          improve=args.improve, dry_run=args.dry_run,
                          only_gates=args.gate, skip_gates=args.skip,
                          severity=args.severity,
                          revert_on_regression=args.revert_on_regression,
                          verbose=not args.quiet,
                          autofix_only=set(args.fix_only or []) or None,
                          autofix_skip=set(args.fix_skip),
                          root=os.path.abspath(args.root))
    except KeyboardInterrupt:
        print("interrotto", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print("ERRORE interno del ciclo: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return 2

    text = write_outputs(result, args.json, args.markdown,
                         step_summary=args.step_summary)
    if args.quiet:
        print(text)
    final = result["final"]
    print("STATO: %s — %d errori, %d avvisi, %d info, %d file modificati"
          % (result["status"], final.get("errors", 0), final.get("warnings", 0),
             final.get("infos", 0), len(result["changed_files"])))
    if result["status"] in (CLEAN, HEALED):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
