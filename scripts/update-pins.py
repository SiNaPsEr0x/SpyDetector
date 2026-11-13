#!/usr/bin/env python3
"""
Aggiorna le action GitHub pinnate nelle workflow SOLO se la major nuova e'
compatibile, e scrive il pin in forma "SHA # tag" (cosi' il pin e' verificabile
e aggiornabile in automatico).

  python3 scripts/update-pins.py [--dry-run] [--check] [--selftest]

Regole:
  * la major di riferimento si legge dal TAG in commento, mai dal ref: un pin
    e' un commit SHA di 40 cifre esadecimali e le sue prime cifre non sono una
    versione. Leggere `3ffccacd...` come "major 3" faceva retrocedere
    create-pull-request da v8.1.3 a v3.14.0 e `1e69f48...` come "major 1"
    faceva retrocedere actions/attest da v4.2.2 a v1.4.1;
  * si aggiorna restando nella stessa major (es. v4.2.0 -> v4.2.2);
  * una major nuova si adotta solo se la action e' in ALLOW_MAJOR; altrimenti
    resta sulla major nota funzionante e lo segnala (HOLD_MAJOR);
  * nessuna retrocessione: se il tag trovato e' piu' vecchio di quello gia'
    pinato, la riga non si tocca;
  * se la major non e' determinabile (pin senza commento di versione) la riga
    non si tocca: meglio un pin vecchio che un pin sbagliato;
  * la riga riscritta contiene un solo commento di versione.
"""
import json
import os
import re
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
    "github/codeql-action", "actions/attest", "actions/attest-build-provenance",
    "aquasecurity/trivy-action", "gitleaks/gitleaks-action", "peter-evans/create-pull-request",
    "actions/dependency-review-action", "anchore/sbom-action", "ossf/scorecard-action",
}

_warned = set()

USES_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?uses:\s*(?P<repo>[\w.-]+/[\w.-]+(?:/[\w.-]+)*)@(?P<ref>\S+)(?P<tail>.*)$")
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
# il tag in commento dopo il pin: "# v8.1.3"
TAG_RE = re.compile(r"#\s*(v?\d[0-9A-Za-z.\-+]*)")


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
    """Major di un TAG (`v8`, `v4.2.2`) — None per cio' che non e' un tag."""
    if SHA_RE.match(ref or ""):
        # un commit SHA non e' una versione: le sue cifre iniziali non contano
        return None
    m = re.match(r"v?(\d+)", ref or "")
    return int(m.group(1)) if m else None


def tag_in_tail(tail):
    """Il tag di versione scritto in commento dopo il pin, se c'e'."""
    m = TAG_RE.search(tail or "")
    return m.group(1) if m else None


def current_major(ref, tail):
    """Major attualmente in uso: dal tag, perche' il ref di solito e' uno SHA."""
    if SHA_RE.match(ref or ""):
        return major_of(tag_in_tail(tail) or "")
    return major_of(ref)


def vkey(v):
    """Chiave ordinabile di un tag: v8.1.3 -> (8, 1, 3, 0)."""
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) + (0,) * (4 - min(4, len(parts)))


def rewrite_uses_line(line, sha, tag):
    """Sostituisce ref E coda della riga `uses:`: un solo commento di versione."""
    m = USES_RE.match(line.rstrip("\n"))
    if not m:
        return line
    return line[:m.start("ref")] + "%s # %s" % (sha, tag) + "\n"


def split_uses(target):
    """`owner/repo/sub/path@ref` -> ("owner/repo", "sub/path")."""
    base = target.split("@")[0]
    parts = base.split("/")
    if len(parts) > 2:
        return "/".join(parts[:2]), "/".join(parts[2:])
    return base, ""


def list_tags(repo, pages=3):
    """Tag del repo, fino a `pages` pagine (100 tag l'una)."""
    out = []
    for page in range(1, pages + 1):
        try:
            batch = api("/repos/%s/tags?per_page=100&page=%d" % (repo, page))
        except Exception as exc:  # noqa: BLE001
            print("   %-38s errore API: %s" % (repo, exc))
            return out if out else None
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
    return out


def latest_for(repo, cur_major, cur_tag):
    """(tag, sha) piu' recente nella stessa major, senza mai retrocedere."""
    tags = list_tags(repo)
    if tags is None:
        return None
    best = None
    for t in tags:
        name = t["name"]
        mj = major_of(name)
        if mj is None:
            continue
        if mj == cur_major or repo in ALLOW_MAJOR:
            if best is None or vkey(name) > vkey(best["name"]):
                best = t
        elif repo in HOLD_MAJOR and mj > (cur_major or 0):
            msg = "   %-38s major %d disponibile ma tenuta (verifica manuale)" % (repo, mj)
            if msg not in _warned:
                _warned.add(msg)
                print(msg)
    if best is None:
        return None
    if cur_tag and vkey(best["name"]) < vkey(cur_tag):
        msg = ("   %-38s trovato %s ma il pinato e' %s: nessuna retrocessione"
               % (repo, best["name"], cur_tag))
        if msg not in _warned:
            _warned.add(msg)
            print(msg)
        return None
    return best["name"], best["commit"]["sha"]


def iter_workflows():
    if not os.path.isdir(WORKFLOWS):
        return
    for fn in sorted(os.listdir(WORKFLOWS)):
        if fn.endswith((".yml", ".yaml")):
            yield fn, os.path.join(WORKFLOWS, fn)


def update(dry=False):
    """Riscrive i pin compatibili. Resituisce (file_toccati, modifiche)."""
    changed_files = 0
    changes = []
    for fn, path in iter_workflows():
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines(keepends=True)
        out, touched = [], False
        for line in lines:
            m = USES_RE.match(line.rstrip("\n"))
            if not m:
                out.append(line)
                continue
            raw_repo, ref, tail = m.group("repo"), m.group("ref"), m.group("tail")
            repo, _sub = split_uses(raw_repo)
            if repo.startswith("./") or ref.startswith("sha256:"):
                out.append(line)
                continue
            cur_major = current_major(ref, tail)
            if cur_major is None:
                msg = ("   %-38s major non determinabile (pin %s senza tag in "
                       "commento): non la tocco" % (repo, ref[:12]))
                if msg not in _warned:
                    _warned.add(msg)
                    print(msg)
                out.append(line)
                continue
            resolved = latest_for(repo, cur_major, tag_in_tail(tail))
            if not resolved:
                out.append(line)
                continue
            tag, sha = resolved
            if ref.split("#")[0].strip() == sha and tag_in_tail(tail) == tag:
                out.append(line)          # gia' a posto: nessuna riscrittura
                continue
            out.append(rewrite_uses_line(line, sha, tag))
            touched = True
            changes.append("%s: %s %s# %s -> %s # %s"
                           % (fn, repo, ref[:12], tag_in_tail(tail) or "?", sha[:12], tag))
        if touched:
            changed_files += 1        # contato anche in dry-run: e' cio' che
            if not dry:               # restituisce "N workflow da aggiornare"
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("".join(out))
    return changed_files, changes


def check_unpinned():
    """Nessuna action deve restare su un tag mobile."""
    unpinned = []
    for fn, path in iter_workflows():
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                m = USES_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                ref = m.group("ref").split("#")[0].strip()
                if not SHA_RE.match(ref):
                    unpinned.append("%s:%d %s@%s" % (fn, i, m.group("repo"), ref))
    return unpinned


def selftest():
    """Prove senza rete sulla logica che aveva causato le retrocessioni."""
    casi = []

    def caso(nome, ottenuto, atteso):
        casi.append((nome, ottenuto == atteso, ottenuto, atteso))

    SHA8 = "3ffccacd46053766916f087ce41d627c0b8cf2d1"   # create-pull-request v8.1.3
    SHA1 = "1e69f48acb82d1966a394da916b4c1698aa569d6"   # actions/attest v4.2.2

    caso("lo SHA non e' una major", major_of(SHA8), None)
    caso("lo SHA che inizia per 1 non e' major 1", major_of(SHA1), None)
    caso("major da un tag secco", major_of("v8"), 8)
    caso("major da un tag completo", major_of("v4.2.2"), 4)
    caso("major corrente letta dal commento", current_major(SHA8, " # v8.1.3"), 8)
    caso("major corrente da tag mobile", current_major("v4", ""), 4)
    caso("senza commento la major e' ignota", current_major(SHA1, ""), None)
    caso("tag estratto dalla coda", tag_in_tail(" # v8.1.3"), "v8.1.3")
    caso("una coda vuota non ha tag", tag_in_tail(""), None)
    caso("v8.1.3 resta piu' recente di v3.14.0",
         vkey("v3.14.0") < vkey("v8.1.3"), True)
    caso("v4.2.2 resta piu' recente di v1.4.1",
         vkey("v1.4.1") < vkey("v4.2.2"), True)
    caso("v4.2.10 batte v4.2.9 (confronto numerico)",
         vkey("v4.2.10") > vkey("v4.2.9"), True)

    riga = "        uses: peter-evans/create-pull-request@%s # v8.1.3\n" % SHA8
    nuova = rewrite_uses_line(riga, "18f7dc018cc2cd597073088f7c7591b9d1c02672", "v8.1.4")
    caso("la riga riscritta ha un solo commento",
         nuova.count("# v"), 1)
    caso("la riga riscritta finisce con il tag nuovo",
         nuova.rstrip("\n").endswith("# v8.1.4"), True)
    caso("la riga riscritta tiene lo SHA nuovo",
         "18f7dc018cc2cd597073088f7c7591b9d1c02672" in nuova, True)
    caso("l'indentazione e il trattino restano",
         nuova.startswith("        uses: "), True)
    sottopercorso = ("        uses: github/codeql-action/init@%s # v4.39.3\n"
                     % "33d7b85da1a04171e211befe2c739303b9a4c066")
    caso("il sottopercorso dell'action resta intatto",
         rewrite_uses_line(sottopercorso, "a" * 40, "v4.39.4").strip()
         .startswith("uses: github/codeql-action/init@" + "a" * 40), True)

    falliti = [c for c in casi if not c[1]]
    for nome, ok, ottenuto, atteso in casi:
        print("  %s %s" % ("ok  " if ok else "FAIL", nome))
        if not ok:
            print("        ottenuto=%r atteso=%r" % (ottenuto, atteso))
    print("\n%d controlli, %d falliti" % (len(casi), len(falliti)))
    return 1 if falliti else 0


USAGE = """uso: python3 scripts/update-pins.py [opzione]

  (nessuna)   aggiorna i pin compatibili e scrive i file
  --dry-run   mostra cosa cambierebbe senza scrivere
  --check     come --dry-run, ma esce 1 se c'e' qualcosa da aggiornare
  --selftest  prove senza rete sulla logica di risoluzione delle versioni
  --help      questo testo
"""


def main(argv):
    if "-h" in argv or "--help" in argv:
        print(USAGE, end="")
        return 0
    if "--selftest" in argv:
        return selftest()
    dry = "--dry-run" in argv or "--check" in argv
    changed_files, changes = update(dry=dry)

    unpinned = check_unpinned()
    for u in unpinned:
        print("   NON PINNATA: " + u)
    for c in changes:
        print("   " + c)
    print("\n%d workflow %s" % (changed_files, "da aggiornare" if dry else "aggiornate"))

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and (changes or unpinned):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Pin action aggiornati\n")
            fh.write("```\n%s\n```\n" % ("\n".join(changes) or "nessuno"))

    if unpinned:
        print("ERRORE: %d action non pinnate a SHA" % len(unpinned))
        if os.environ.get("GITHUB_ACTIONS"):
            return 1
    if "--check" in argv and changes:
        print("ERRORE: %d pin non aggiornati" % len(changes))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
