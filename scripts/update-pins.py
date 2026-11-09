#!/usr/bin/env python3
"""
Aggiorna le action GitHub pinnate nelle workflow SOLO se la major nuova e'
compatibile, e scrive il pin in forma "tag # SHA" (cosi' il pin e' verificabile
e aggiornabile in automatico).

  python3 scripts/update-pins.py [--dry-run]

Regole:
  * tag `vX` / `vX.Y.Z` -> si aggiorna alla stessa major (es. v4 -> v4.39.3);
  * major nuova (es. v4 -> v5) -> si aggiorna solo se la action e' in
    ALLOW_MAJOR, altrimenti resta sulla major nota funzionante e lo segnala;
  * il pin e' sempre al commit SHA della release, con il tag in commento.
"""
import json
import os
import re
import subprocess
import sys
from urllib.request import Request, urlopen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# major nuove accettate in automatico per i repo piu' stabili
ALLOW_MAJOR = {
    "actions/checkout", "actions/setup-java", "actions/setup-python",
    "actions/cache", "actions/upload-artifact", "actions/download-artifact",
}
# non toccare: la major deve essere verificata a mano (API che cambiano)
HOLD_MAJOR = {
    "github/codeql-action", "actions/attest-build-provenance", "actions/attest-sbom",
    "aquasecurity/trivy-action", "gitleaks/gitleaks-action", "peter-evans/create-pull-request",
    "actions/dependency-review-action", "anchore/sbom-action", "ossf/scorecard-action",
}

_warned = set()

USES_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?uses:\s*(?P<repo>[\w.-]+/[\w.-]+(?:/[\w.-]+)*)@(?P<ref>\S+)(?P<tail>.*)$")


def api(path):
    req = Request("https://api.github.com" + path,
                  headers={"Accept": "application/vnd.github+json",
                           "User-Agent": "spydetector-pins"})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urlopen(req, timeout=60) as r:
        return json.load(r)


def major_of(ref):
    m = re.match(r"v?(\d+)", ref)
    return int(m.group(1)) if m else None


def split_uses(target):
    """`owner/repo/sub/path@ref` -> ("owner/repo", "sub/path")."""
    if "@" in target and target.count("/") >= 2:
        pass
    base = target.split("@")[0]
    parts = base.split("/")
    if len(parts) > 2:
        return "/".join(parts[:2]), "/".join(parts[2:])
    return base, ""


def latest_for(repo, current_ref):
    """Restituisce (tag, sha) piu' recente compatibile con la major corrente."""
    cur_major = major_of(current_ref)
    try:
        tags = api("/repos/%s/tags?per_page=100" % repo)
    except Exception as exc:  # noqa: BLE001
        print("   %-38s errore API: %s" % (repo, exc))
        return None
    best = None
    for t in tags:
        name = t["name"]
        if not re.match(r"^v?\d", name):
            continue
        mj = major_of(name)
        if mj is None:
            continue
        same_major = (mj == cur_major)
        if same_major or repo in ALLOW_MAJOR:
            if best is None or _vkey(name) > _vkey(best["name"]):
                best = t
        elif repo in HOLD_MAJOR and mj > (cur_major or 0):
            msg = "   %-38s major %d disponibile ma tenuta (verifica manuale)" % (repo, mj)
            if msg not in _warned:
                _warned.add(msg)
                print(msg)
    if best is None:
        return None
    sha = best["commit"]["sha"]
    return best["name"], sha


def _vkey(v):
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) + (0,) * (4 - min(4, len(parts)))


def main():
    dry = "--dry-run" in sys.argv
    changed_files = 0
    changes = []
    for fn in sorted(os.listdir(WORKFLOWS)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(WORKFLOWS, fn)
        lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
        out, touched = [], False
        for line in lines:
            m = USES_RE.match(line.rstrip("\n"))
            if not m:
                out.append(line)
                continue
            raw_repo, ref = m.group("repo"), m.group("ref")
            repo, sub = split_uses(raw_repo)
            if repo.startswith("./") or ref.startswith("sha256:"):
                out.append(line)
                continue
            resolved = latest_for(repo, ref)
            if not resolved:
                out.append(line)
                continue
            tag, sha = resolved
            new_ref = "%s # %s" % (sha, tag)
            if ref.split("#")[0].strip() == sha:
                out.append(line)
                continue
            target = "%s/%s" % (repo, sub) if sub else repo
            newline = re.sub(r"uses:\s*\S+", "uses: %s@%s" % (target, new_ref),
                             line.rstrip("\n"), count=1) + "\n"
            out.append(newline)
            touched = True
            changes.append("%s: %s %s -> %s" % (fn, repo, ref, new_ref))
        if touched and not dry:
            open(path, "w", encoding="utf-8").write("".join(out))
            changed_files += 1

    for c in changes:
        print("   " + c)
    print("\n%d workflow aggiornate" % changed_files)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Pin action aggiornati\n")
            fh.write("```\n%s\n```\n" % ("\n".join(changes) or "nessuno"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
