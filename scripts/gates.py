#!/usr/bin/env python3
"""
Gate di qualita' del repository: un solo punto di verita' per i controlli
automatici, usato dalla CI, dal ciclo di self-healing e in locale.

  python3 scripts/gates.py                     # tutti i gate offline
  python3 scripts/gates.py --with-build        # + build APK e verifica
  python3 scripts/gates.py --json build/gates.json
  python3 scripts/gates.py --gate java --gate shell
  python3 scripts/gates.py --list              # gate e regole disponibili

Ogni problema e' una "finding" strutturata:

  gate / regola / gravita' (error|warn|info) / file / riga / messaggio / fix

`fix` e' l'identificatore della regola di correzione in scripts/autofix.py:
se e' presente il problema e' riparabile in automatico, altrimenti resta in
carico a una persona (il ciclo di self-healing apre una issue con il report).

Solo le finding `error` fanno fallire il gate (--fail-on warn per essere
piu' severi). Le `warn` sono problemi veri ma non bloccanti, le `info` sono
miglioramenti proposti.

Uscita: 0 = nessun errore, 1 = errori presenti, 2 = errore interno.
"""
import argparse
import json
import os
import re
import subprocess
import sys

try:
    # dipendenza opzionale (gia' in scripts/requirements.txt): con pyyaml la
    # validazione delle workflow e' completa, senza ci si limita ai controlli
    # strutturali fatti dal lettore a righe qui sotto
    import yaml as _yaml
except ImportError:  # pragma: no cover
    _yaml = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ERROR, WARN, INFO = "error", "warn", "info"
SEVERITIES = (ERROR, WARN, INFO)
SEV_RANK = {ERROR: 0, WARN: 1, INFO: 2}

# estensioni trattate come testo; tutto il resto e' binario (non viene toccato)
TEXT_EXT = (".java", ".py", ".sh", ".yml", ".yaml", ".xml", ".txt", ".md",
            ".json", ".env", ".gitignore", ".properties", ".cfg", ".ini")
TEXT_NAMES = (".gitignore", "VERSION", "LICENSE", "Makefile")

SKIP_DIRS = {".git", ".toolchain", "build", "dist", "__pycache__", "node_modules"}

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")

# contesti delle espressioni GitHub che finiscono dentro uno script shell:
# questi sono controllabili da chi apre una PR/fork (script injection)
UNSAFE_EXPR = ("github.event.", "github.head_ref")
# controllabili solo da chi ha accesso in scrittura: rischio minore
SEMI_UNSAFE_EXPR = ("inputs.",)

# permessi pericolosi per un'app che deve solo analizzare il telefono
FORBIDDEN_PERMISSIONS = (
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_PHONE_STATE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
)

# affermazioni di privacy che devono restare coerenti con l'AndroidManifest
NO_NET_CLAIMS = (
    r"non ha (?:il|alcun) permesso\s+internet",
    r"nessun permesso (?:di rete|internet)",
    r"senza (?:il )?permesso\s+internet",
    r"non (?:ha|usa|richiede) (?:il )?permesso\s+internet",
    r"no internet permission",
    r"does not (?:have|require|use) the internet permission",
    r"zero internet permission",
)

LEFTOVER_EXT = (".orig", ".rej", ".bak", ".tmp", ".swp", ".swo", ".log",
                ".sarif", ".part", ".idsig", ".class", ".dex", ".apk")

SEV_DB = ("CRITICAL", "WARNING")
PATTERN_TYPES = ("PKG", "CERT", "COMP")
CERT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")


# --------------------------------------------------------------------------
# modello
# --------------------------------------------------------------------------
class Finding(object):
    """Un problema trovato da un gate."""

    __slots__ = ("gate", "rule", "severity", "path", "line", "message", "fix")

    def __init__(self, gate, rule, severity, path, line=None, message="", fix=None):
        self.gate = gate
        self.rule = rule
        self.severity = severity
        self.path = path
        self.line = line
        self.message = message
        self.fix = fix

    def rel(self):
        if self.path and self.path.startswith(ROOT + os.sep):
            return os.path.relpath(self.path, ROOT)
        return self.path or ""

    def key(self):
        return (self.rule, self.rel(), self.line or 0)

    def to_dict(self):
        return {"gate": self.gate, "rule": self.rule, "severity": self.severity,
                "path": self.rel(), "line": self.line, "message": self.message,
                "fix": self.fix}

    def __str__(self):
        where = self.rel() + ((":%d" % self.line) if self.line else "")
        tag = {"error": "ERRORE", "warn": "avviso", "info": "info"}[self.severity]
        return "%-7s %-28s %s  %s" % (tag, self.rule, where or "-", self.message)


class Ctx(object):
    """Contesto condiviso dai gate: file tracciati, cache dei testi, tool."""

    def __init__(self, root=ROOT, with_git=None):
        self.root = root
        self._cache = {}
        self._modes = None
        self._tools = {}
        self.git = with_git if with_git is not None else self._detect_git()
        self.notes = []
        self._noted = set()
        self.files = self._enumerate()

    def note(self, key, text):
        """Messaggio informativo mostrato una volta sola."""
        if key not in self._noted:
            self._noted.add(key)
            self.notes.append(text)

    # -- infrastruttura ----------------------------------------------------
    def _detect_git(self):
        try:
            r = subprocess.run(["git", "-C", self.root, "rev-parse", "--git-dir"],
                               capture_output=True, timeout=20)
            return r.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def _enumerate(self):
        """Elenco dei file del repo (quelli tracciati, se git e' disponibile)."""
        if self.git:
            try:
                out = subprocess.run(["git", "-C", self.root, "ls-files", "-z"],
                                     capture_output=True, timeout=60).stdout
                files = [os.path.join(self.root, p) for p in out.decode("utf-8", "replace").split("\0") if p]
                return [f for f in files if os.path.isfile(f)]
            except Exception:  # noqa: BLE001
                pass
        found = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                found.append(os.path.join(dirpath, name))
        return found

    def git_modes(self):
        """Permessi dei file nell'index git (100644 / 100755)."""
        if self._modes is not None:
            return self._modes
        modes = {}
        if self.git:
            try:
                out = subprocess.run(["git", "-C", self.root, "ls-files", "-s", "-z"],
                                     capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
                for entry in out.split("\0"):
                    if not entry.strip():
                        continue
                    parts = entry.split(None, 3)
                    if len(parts) == 4:
                        modes[parts[3]] = parts[0]
            except Exception:  # noqa: BLE001
                pass
        self._modes = modes
        return modes

    def tool(self, name):
        """Path di un eseguibile esterno, o None."""
        if name not in self._tools:
            from shutil import which
            self._tools[name] = which(name)
        return self._tools[name]

    def rel(self, path):
        return os.path.relpath(path, self.root)

    def by_ext(self, *exts):
        return [f for f in self.files if f.endswith(exts)]

    def is_text(self, path):
        base = os.path.basename(path)
        if base in TEXT_NAMES:
            return True
        if not path.endswith(TEXT_EXT):
            return False
        return True

    def text_files(self):
        return [f for f in self.files if self.is_text(f)]

    def read_bytes(self, path):
        if path not in self._cache:
            with open(path, "rb") as fh:
                self._cache[path] = fh.read()
        return self._cache[path]

    def read(self, path):
        return self.read_bytes(path).decode("utf-8", "replace")

    def lines(self, path):
        return self.read(path).split("\n")

    def invalidate(self, path=None):
        if path is None:
            self._cache.clear()
        else:
            self._cache.pop(path, None)

    def run(self, cmd, cwd=None, timeout=1800):
        return subprocess.run(cmd, cwd=cwd or self.root, capture_output=True,
                              text=True, timeout=timeout)


# --------------------------------------------------------------------------
# lettore strutturale delle workflow (senza dipendenze YAML)
# --------------------------------------------------------------------------
class Token(object):
    __slots__ = ("line", "indent", "key", "value", "dash", "raw", "comment", "block")

    def __init__(self, line, indent, key, value, dash, raw, comment, block):
        self.line = line
        self.indent = indent
        self.key = key
        self.value = value
        self.dash = dash
        self.raw = raw
        self.comment = comment
        self.block = block or []

    def __repr__(self):
        return "Token(l=%d i=%d k=%r v=%r dash=%s)" % (
            self.line, self.indent, self.key, self.value, self.dash)


BLOCK_SCALAR = re.compile(r"^[|>][-+]?[0-9]*$")
KEY_LINE = re.compile(r"^(?P<key>[A-Za-z_][\w.\- ]*\w|\w)\s*:(?P<rest>.*)$")


def split_comment(text):
    """Separa il commento in coda a una riga YAML (# fuori dalle virgolette)."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip(), text[i + 1:].strip()
    return text.rstrip(), ""


def scan_yaml(text):
    """Lettura strutturale a righe di una workflow/action GitHub.

    Non serve un parser YAML completo: per i controlli bastano le chiavi, la
    loro indentazione, i block scalar (`run: |`) e le righe `uses:`. I block
    scalar sono raccolti come testo grezzo, cosi' i commenti shell dentro un
    `run:` non vengono scambiati per YAML.

    Ritorna (token, problemi) dove problemi sono righe non analizzabili.
    """
    tokens, problems = [], []
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        i += 1
        stripped = raw.strip()
        if not stripped:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if "\t" in raw[:indent + 1] and raw[:indent + 1].strip() == "":
            problems.append((i, "indentazione con tab (YAML non li ammette)"))
            continue
        code, comment = split_comment(stripped)
        dash = code.startswith("- ") or code == "-"
        body = code[1:].strip() if dash else code
        if not body:
            # elemento di sequenza senza valore sulla stessa riga
            tokens.append(Token(i, indent, None, "", dash, raw, comment, []))
            continue
        m = KEY_LINE.match(body)
        if not m:
            # scalare di sequenza ("- main") o continuazione: lo teniamo come valore
            tokens.append(Token(i, indent, None, body, dash, raw, comment, []))
            continue
        key = m.group("key").strip()
        rest = m.group("rest").strip()
        block = []
        if BLOCK_SCALAR.match(rest):
            # block scalar: tutte le righe piu' indentate sono testo grezzo
            base = indent + (2 if dash else 0)
            while i < n:
                nxt = lines[i]
                if not nxt.strip():
                    block.append((i + 1, ""))
                    i += 1
                    continue
                ni = len(nxt) - len(nxt.lstrip(" "))
                if ni <= base:
                    break
                block.append((i + 1, nxt))
                i += 1
            rest = ""
        elif rest.startswith("|") or rest.startswith(">"):
            rest = ""
        tokens.append(Token(i, indent, key, rest, dash, raw, comment, block))
    return tokens, problems


class Workflow(object):
    """Struttura di alto livello ricavata dai token."""

    def __init__(self, path, text):
        self.path = path
        self.text = text
        self.tokens, self.problems = scan_yaml(text)
        self.name = None
        self.triggers = []
        self.permissions = None
        self.has_concurrency = False
        self.jobs = {}
        self.steps = []
        self.uses = []
        self.inputs = {}
        self._parse()

    # -- helpers -----------------------------------------------------------
    def _top(self, key):
        return [t for t in self.tokens if t.indent == 0 and t.key == key]

    def _children(self, token, indent=None):
        """Token figli (indentazione maggiore) fino al prossimo fratello."""
        out, started = [], False
        for t in self.tokens:
            if t is token:
                started = True
                continue
            if not started:
                continue
            if t.indent <= token.indent:
                break
            if indent is None or t.indent == indent:
                out.append(t)
        return out

    def _mapping(self, token):
        """Chiavi di una mappa YAML sotto `token` (primo livello di figli)."""
        kids = self._children(token)
        if not kids:
            return {}
        level = min(k.indent for k in kids)
        out = {}
        for k in kids:
            if k.indent == level and k.key:
                out[k.key] = k
        return out

    def _parse(self):
        top = {t.key: t for t in self.tokens if t.indent == 0 and t.key}
        if "name" in top:
            self.name = top["name"].value.strip("\"'")
        # `on:` in YAML e' il booleano True; qui lavoriamo sul testo, quindi "on"
        if "on" in top:
            on = top["on"]
            if on.value:
                self.triggers = [x.strip(" '\"") for x in
                                 re.split(r"[,\[\]]", on.value) if x.strip(" '\"")]
            else:
                kids = self._children(on)
                level = min([k.indent for k in kids], default=None)
                if level is not None:
                    for k in kids:
                        if k.indent == level:
                            if k.key:
                                self.triggers.append(k.key)
                            elif k.dash and k.value:
                                self.triggers.append(k.value.strip("\"'"))
        if "permissions" in top:
            self.permissions = self._read_perms(top["permissions"])
        self.has_concurrency = "concurrency" in top

        jobs_tok = top.get("jobs")
        if jobs_tok:
            kids = self._children(jobs_tok)
            level = min((k.indent for k in kids), default=None)
            for jt in kids:
                if level is None:
                    break
                if jt.indent != level or not jt.key:
                    continue
                job = {"id": jt.key, "line": jt.line, "token": jt,
                       "runs_on": None, "permissions": None, "steps": [],
                       "keys": self._mapping(jt)}
                if "runs-on" in job["keys"]:
                    job["runs_on"] = job["keys"]["runs-on"].value.strip("\"'")
                if "permissions" in job["keys"]:
                    job["permissions"] = self._read_perms(job["keys"]["permissions"])
                self.jobs[jt.key] = job

        # step: ogni `steps:` (workflow o action composite) e i suoi elementi
        for st in [t for t in self.tokens if t.key == "steps"]:
            kids = self._children(st)
            if not kids:
                continue
            level = min(k.indent for k in kids)
            current = None
            for k in kids:
                if k.indent == level and k.dash:
                    current = {"line": k.line, "job": self._job_of(k), "keys": {},
                               "indent": level}
                    self.steps.append(current)
                    if k.key:
                        current["keys"][k.key] = k
                elif current is not None and k.indent > level and k.key:
                    current["keys"].setdefault(k.key, k)
        # collega gli step al job che li contiene
        for step in self.steps:
            job = self.jobs.get(step["job"])
            if job is not None:
                job["steps"].append(step)
        for step in self.steps:
            for key, tok in step["keys"].items():
                if key == "uses":
                    self.uses.append({"line": tok.line, "ref": tok.value.strip(),
                                      "raw": tok.raw, "comment": tok.comment,
                                      "token": tok, "step": step})

        runs = top.get("runs")
        if runs:
            self.using = self._mapping(runs).get("using")
        for it in [t for t in self.tokens if t.key == "inputs" and t.indent == 0]:
            self.inputs = self._mapping(it)

    def _job_of(self, token):
        best = None
        for job in self.jobs.values():
            if job["line"] < token.line and (best is None or job["line"] > best["line"]):
                best = job
        return best["id"] if best else None

    def _read_perms(self, token):
        if token.value:
            return {"__all__": token.value.strip("\"'")}
        return {k: v.value.strip("\"'") for k, v in self._mapping(token).items()}

    def is_action(self):
        return os.path.basename(os.path.dirname(self.path)) == "actions" or \
            bool(self._top("runs"))


# --------------------------------------------------------------------------
# gate: igiene dei file
# --------------------------------------------------------------------------
def gate_hygiene(ctx):
    out = []
    for path in ctx.files:
        if not os.path.isfile(path):
            continue          # cancellato da una correzione precedente
        rel = ctx.rel(path)
        base = os.path.basename(path)
        if base.endswith(LEFTOVER_EXT) or base in ("npm-debug.log",):
            out.append(Finding("hygiene", "file-leftover", ERROR, path,
                               message="file residuo committato nel repo",
                               fix="file-leftover"))
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > 2 * 1024 * 1024:
            out.append(Finding("hygiene", "file-large", WARN, path,
                               message="file da %.1f MiB nel repo" % (size / 1048576.0)))
        if not ctx.is_text(path):
            continue
        raw = ctx.read_bytes(path)
        if raw.startswith(b"\xef\xbb\xbf"):
            out.append(Finding("hygiene", "ws-bom", WARN, path,
                               message="BOM UTF-8 a inizio file", fix="ws-bom"))
        text = raw.decode("utf-8", "replace")
        if b"\r\n" in raw:
            out.append(Finding("hygiene", "ws-crlf", ERROR, path,
                               message="fine riga CRLF (atteso LF)", fix="ws-crlf"))
        lines = text.split("\n")
        for num, line in enumerate(lines, 1):
            if line != line.rstrip():
                out.append(Finding("hygiene", "ws-trailing", WARN, path, num,
                                   "spazi/tab a fine riga", fix="ws-trailing"))
                break
        if text and not text.endswith("\n"):
            out.append(Finding("hygiene", "ws-final-newline", WARN, path,
                               message="manca il newline finale", fix="ws-final-newline"))

    # VERSION: deve essere un semver perche' build.sh e release.yml lo usano
    vf = os.path.join(ctx.root, "VERSION")
    if os.path.isfile(vf):
        v = open(vf, encoding="utf-8").read().strip()
        if not re.match(r"^\d+\.\d+\.\d+$", v):
            out.append(Finding("hygiene", "version-format", ERROR, vf,
                               message="VERSION non e' un semver: %r" % v))

    # .gitignore deve coprire gli artefatti di build
    gi = os.path.join(ctx.root, ".gitignore")
    if os.path.isfile(gi):
        content = open(gi, encoding="utf-8").read()
        for wanted in (".toolchain", "build/", "dist/", "__pycache__"):
            if wanted not in content:
                out.append(Finding("hygiene", "gitignore-outputs", WARN, gi,
                                   message=".gitignore non copre %s" % wanted,
                                   fix="gitignore-add"))

    # permessi di esecuzione: gli script devono essere eseguibili anche da git
    modes = ctx.git_modes()
    for path in ctx.files:
        rel = ctx.rel(path)
        if not (path.endswith(".sh") or (path.endswith(".py") and
                                          os.sep + "scripts" + os.sep in path + os.sep)):
            continue
        mode = modes.get(rel)
        # vale l'index git (cio' che finisce in un clone) oppure l'albero di
        # lavoro: un chmod +x non ancora committato e' gia' una correzione
        if mode != "100755" and not os.access(path, os.X_OK):
            out.append(Finding("hygiene", "file-exec-bit", WARN, path,
                               message="script non eseguibile (modo %s)" % (mode or "n/d"),
                               fix="file-exec-bit"))
    return out


# --------------------------------------------------------------------------
# gate: shell
# --------------------------------------------------------------------------
def gate_shell(ctx):
    out = []
    bash = ctx.tool("bash") or "/bin/bash"
    shellcheck = ctx.tool("shellcheck")
    for path in ctx.by_ext(".sh"):
        text = ctx.read(path)
        lines = text.split("\n")
        first = lines[0] if lines else ""
        if not first.startswith("#!"):
            out.append(Finding("shell", "sh-shebang", WARN, path, 1,
                               "manca lo shebang", fix="sh-shebang"))
        head = "\n".join(lines[:25])
        if not re.search(r"set\s+(-[a-zA-Z]*e[a-zA-Z]*o\s+pipefail|-euo\s+pipefail"
                         r"|-o\s+errexit)", head):
            out.append(Finding("shell", "sh-strict", WARN, path, 1,
                               "manca `set -euo pipefail` (gli errori passano inosservati)",
                               fix="sh-strict"))
        if bash:
            r = ctx.run([bash, "-n", path])
            if r.returncode != 0:
                line = _first_line_no(r.stderr)
                out.append(Finding("shell", "sh-syntax", ERROR, path, line,
                                   "sintassi bash non valida: %s" % _one_line(r.stderr)))
        if shellcheck:
            # shellcheck e' opzionale e la sua versione cambia da un ambiente
            # all'altro: i suoi esiti non sono mai bloccanti (la sintassi, che
            # invece lo e', la verifica `bash -n` con la regola sh-syntax)
            r = ctx.run([shellcheck, "--format=gcc", path])
            for ln, sev, msg in _parse_gcc(r.stdout):
                level = INFO if sev in ("note", "style") else WARN
                out.append(Finding("shell", "sh-shellcheck", level, path, ln,
                                   "shellcheck (%s): %s" % (sev, msg)))
        else:
            ctx.note("shellcheck",
                     "shellcheck non installato: controllo approfondito saltato")
    return out


def _first_line_no(text):
    m = re.search(r"line (\d+)", text or "")
    return int(m.group(1)) if m else None


def _one_line(text):
    return " ".join((text or "").split())[:200]


def _parse_gcc(text):
    """Formato gcc: `file:line:col: level: message`."""
    out = []
    for line in (text or "").split("\n"):
        m = re.match(r"^[^:]+:(\d+):(\d+):\s*(\w+):\s*(.*)$", line)
        if m:
            out.append((int(m.group(1)), m.group(3), m.group(4).strip()))
    return out


# --------------------------------------------------------------------------
# gate: python
# --------------------------------------------------------------------------
PY_IMPORT = re.compile(r"^\s*(?:from\s+[\w.]+\s+)?import\s+(.+?)\s*$")


def py_imported_names(path):
    """(riga, nome_legato, testo) per ogni import di un file Python."""
    out = []
    for num, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        code = line.split("#", 1)[0].rstrip()
        if not code.strip().startswith(("import ", "from ")):
            continue
        m = PY_IMPORT.match(code)
        if not m:
            continue
        clause = m.group(1)
        if clause.endswith("\\"):
            continue
        for part in clause.split(","):
            part = part.strip()
            if not part:
                continue
            if part.startswith("("):
                part = part.lstrip("(").strip()
            if " as " in part:
                out.append((num, part.split(" as ")[1].strip(), line))
            elif part.startswith("from") or " " in part:
                continue
            else:
                out.append((num, part.split(".")[0].strip(), line))
    return out


def unused_imports(path, language):
    """Import il cui nome non compare mai altrove nel file (rimozione sicura)."""
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    if language == "java":
        binds = java_imported_names(path)
    else:
        binds = py_imported_names(path)
    if not binds:
        return []
    body = []
    for num, line in enumerate(lines, 1):
        if num in {b[0] for b in binds}:
            continue
        body.append(line)
    corpus = "\n".join(body)
    out = []
    for num, name, raw in binds:
        if not name or name == "*":
            continue
        if "noqa" in raw or "pragma" in raw or "pylint" in raw:
            continue
        if not re.search(r"\b%s\b" % re.escape(name), corpus):
            out.append((num, name, raw))
    return out


def gate_python(ctx):
    out = []
    for path in ctx.by_ext(".py"):
        text = ctx.read(path)
        try:
            compile(text, path, "exec")
        except SyntaxError as exc:
            out.append(Finding("python", "py-syntax", ERROR, path, exc.lineno,
                               "sintassi Python non valida: %s" % exc.msg))
            continue
        lines = text.split("\n")
        if not lines[0].startswith("#!"):
            out.append(Finding("python", "py-shebang", WARN, path, 1,
                               "manca lo shebang", fix="py-shebang"))
        stripped = "\n".join(l for l in lines[:5] if not l.startswith("#!"))
        if not (text.lstrip().startswith('"""') or text.lstrip().startswith("'''")
                or '"""' in stripped[:400] or "'''" in stripped[:400]):
            out.append(Finding("python", "py-docstring", INFO, path, 1,
                               "nessuna docstring di modulo"))
        for num, name, raw in unused_imports(path, "python"):
            out.append(Finding("python", "py-unused-import", WARN, path, num,
                               "import inutilizzato: %s" % name, fix="py-unused-import"))
        for num, line in enumerate(lines, 1):
            if re.match(r"^\s*except\s*:", line):
                out.append(Finding("python", "py-bare-except", WARN, path, num,
                                   "`except:` cattura anche KeyboardInterrupt/SystemExit"))
            if "\t" in line[:len(line) - len(line.lstrip())]:
                out.append(Finding("python", "py-tabs", WARN, path, num,
                                   "indentazione con tab", fix="expand-tabs"))
                break
    return out


# --------------------------------------------------------------------------
# gate: java
# --------------------------------------------------------------------------
JAVA_IMPORT = re.compile(r"^\s*import\s+(static\s+)?([\w.]+(?:\.\*)?)\s*;")
JAVA_TYPE = re.compile(
    r"^\s*(?:public\s+|final\s+|abstract\s+|strictfp\s+)*"
    r"(?:class|interface|enum|@interface)\s+(\w+)")


def java_imported_names(path):
    out = []
    for num, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        code = line.split("//", 1)[0].rstrip()
        m = JAVA_IMPORT.match(code)
        if not m:
            continue
        if m.group(1):  # import static: il nome legato non e' l'ultima parte
            continue
        fqcn = m.group(2)
        out.append((num, fqcn.split(".")[-1], line))
    return out


def java_wildcard_imports(path):
    out = []
    for num, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        m = JAVA_IMPORT.match(line.split("//", 1)[0])
        if m and m.group(2).endswith(".*"):
            out.append((num, m.group(2)))
    return out


def gate_java(ctx):
    out = []
    src_root = os.path.join(ctx.root, "app", "src", "main", "java")
    checks_dir = os.path.join(src_root, "it", "spydetector", "app", "checks")
    engine = os.path.join(src_root, "it", "spydetector", "app", "core", "Engine.java")

    for path in ctx.by_ext(".java"):
        text = ctx.read(path)
        lines = text.split("\n")
        base = os.path.basename(path)[:-5]

        m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.M)
        if not m:
            out.append(Finding("java", "java-package-missing", ERROR, path, 1,
                               "dichiarazione `package` assente"))
        else:
            want = m.group(1).replace(".", os.sep)
            real = os.path.dirname(path)
            if not real.endswith(want):
                out.append(Finding("java", "java-package-path", ERROR, path,
                                   lines.index(m.group(0)) + 1,
                                   "package %s non corrisponde al percorso (%s)"
                                   % (m.group(1), ctx.rel(real)), fix="java-package"))

        public_types = []
        for num, line in enumerate(lines, 1):
            tm = JAVA_TYPE.match(line.split("//", 1)[0])
            if tm and re.match(r"^\s*public\b", line):
                public_types.append((num, tm.group(1)))
        if len(public_types) == 1 and public_types[0][1] != base:
            out.append(Finding("java", "java-filename", ERROR, path, public_types[0][0],
                               "il tipo pubblico %s deve stare in %s.java"
                               % (public_types[0][1], public_types[0][1])))

        for num, name, raw in unused_imports(path, "java"):
            out.append(Finding("java", "java-unused-import", WARN, path, num,
                               "import inutilizzato: %s" % name, fix="java-unused-import"))
        for num, fqcn in java_wildcard_imports(path):
            out.append(Finding("java", "java-wildcard-import", WARN, path, num,
                               "import con wildcard %s (rende la build non riproducibile)"
                               % fqcn))
        for num, line in enumerate(lines, 1):
            if "\t" in line[:len(line) - len(line.lstrip())]:
                out.append(Finding("java", "java-tabs", WARN, path, num,
                                   "indentazione con tab", fix="expand-tabs"))
                break
        for num, line in enumerate(lines, 1):
            if re.search(r"\bSystem\.(out|err)\.print", line):
                out.append(Finding("java", "java-sysout", WARN, path, num,
                                   "System.out in codice Android (usa android.util.Log)"))
            if "printStackTrace()" in line:
                out.append(Finding("java", "java-printstacktrace", WARN, path, num,
                                   "printStackTrace() scrive su stderr: usa Log"))

        for num, line in enumerate(lines, 1):
            cm = re.search(r"catch\s*\(\s*[\w.<>|\s]+\s+(\w+)\s*\)\s*\{(.*)$", line)
            if not cm:
                continue
            var, rest = cm.group(1), cm.group(2).strip()
            body = rest[:-1].strip() if rest.endswith("}") else None
            if body is None:
                nxt = lines[num].strip() if num < len(lines) else ""
                body = "" if nxt.startswith("}") else nxt
            if body and body.startswith("//"):
                body = ""
            if body == "" and var.lower() not in ("ignored", "ignore", "unused"):
                out.append(Finding("java", "java-empty-catch", WARN, path, num,
                                   "catch vuoto: l'eccezione di `%s` sparisce "
                                   "(rinominala in `ignored` o gestiscila)" % var))

    # ogni check deve essere registrato nell'Engine, altrimenti la scansione
    # salta un'area intera senza che nessuno se ne accorga
    if os.path.isdir(checks_dir) and os.path.isfile(engine):
        eng = open(engine, encoding="utf-8").read()
        declared = {}
        for name in sorted(os.listdir(checks_dir)):
            if not name.endswith("Check.java"):
                continue
            cls = name[:-5]
            src = open(os.path.join(checks_dir, name), encoding="utf-8").read()
            if not re.search(r"\bimplements\b[^{]*\bCheck\b", src):
                continue
            declared[cls] = os.path.join(checks_dir, name)
            if "new %s(" % cls not in eng:
                out.append(Finding("java", "java-check-not-registered", ERROR,
                                   declared[cls],
                                   message="%s implementa Check ma non e' registrato "
                                           "in Engine.defaultChecks(): l'area non viene "
                                           "mai analizzata" % cls))
        for m in re.finditer(r"new\s+(\w*Check)\s*\(", eng):
            if m.group(1) not in declared and m.group(1) != "Check":
                out.append(Finding("java", "java-check-missing-class", ERROR, engine,
                                   message="Engine istanzia %s ma la classe non esiste "
                                           "in checks/" % m.group(1)))
    return out


# --------------------------------------------------------------------------
# gate: workflow e action GitHub
# --------------------------------------------------------------------------
def gate_actions(ctx):
    out = []
    wf_dir = os.path.join(ctx.root, ".github", "workflows")
    ac_dir = os.path.join(ctx.root, ".github", "actions")
    paths = sorted(ctx.by_ext(".yml", ".yaml"))
    paths = [p for p in paths if p.startswith(wf_dir) or p.startswith(ac_dir)]

    for path in paths:
        text = ctx.read(path)
        if _yaml is not None:
            try:
                _yaml.safe_load(text)
            except Exception as exc:  # noqa: BLE001
                line = getattr(exc, "problem_mark", None)
                out.append(Finding("actions", "yaml-invalid", ERROR, path,
                                   (line.line + 1) if line else None,
                                   "YAML non valido, GitHub non lo carica: %s"
                                   % _one_line(str(exc))))
                # niente `continue`: i controlli strutturali girano comunque,
                # cosi' un tab di indentazione (che rende lo YAML invalido)
                # viene sia segnalato sia corretto
        else:
            ctx.note("pyyaml", "pyyaml non installato (pip install -r "
                               "scripts/requirements.txt): validazione YAML "
                               "completa saltata")
        wf = Workflow(path, text)
        rel = ctx.rel(path)
        is_action = wf.is_action()

        for line, why in wf.problems:
            out.append(Finding("actions", "wf-tab-indent", ERROR, path, line, why,
                               fix="yaml-tabs"))

        # --- pin delle action di terze parti ------------------------------
        for use in wf.uses:
            ref = use["ref"]
            if not ref or ref.startswith("$"):
                continue
            if ref.startswith("./") or ref.startswith(".github/"):
                #attenzione: lstrip("./") mangerebbe anche il punto di .github
                rel = ref[2:] if ref.startswith("./") else ref
                target = os.path.normpath(os.path.join(ctx.root, rel))
                if not os.path.isdir(target) and not os.path.isfile(target):
                    out.append(Finding("actions", "wf-local-action-missing", ERROR,
                                       path, use["line"],
                                       "action locale inesistente: %s" % ref))
                continue
            if ref.startswith("docker://"):
                image = ref[len("docker://"):]
                if image.endswith(":latest") or ":" not in image:
                    out.append(Finding("actions", "wf-docker-latest", WARN, path,
                                       use["line"],
                                       "immagine %s non pinnata a una versione" % image))
                continue
            if "@" not in ref:
                out.append(Finding("actions", "wf-pin-drift", ERROR, path, use["line"],
                                   "action senza ref: %s" % ref, fix="wf-pin"))
                continue
            repo, _, sha = ref.partition("@")
            if not SHA_RE.match(sha):
                out.append(Finding("actions", "wf-pin-drift", ERROR, path, use["line"],
                                   "%s pinnata a `%s` e non a un commit SHA "
                                   "(la action puo' cambiare sotto di noi)" % (repo, sha),
                                   fix="wf-pin"))
            elif not use["comment"] and "# v" not in use["raw"]:
                out.append(Finding("actions", "wf-pin-no-comment", WARN, path,
                                   use["line"],
                                   "pin SHA senza il tag in commento (leggibilita' "
                                   "e aggiornamento automatico)", fix="wf-pin"))

        if is_action:
            if not wf.name:
                out.append(Finding("actions", "action-no-name", WARN, path, 1,
                                   "action senza `name:`"))
            if not wf._top("description"):
                out.append(Finding("actions", "action-no-description", WARN, path, 1,
                                   "action senza `description:`"))
            runs = wf._top("runs")
            using = wf._mapping(runs[0]).get("using") if runs else None
            if using and using.value.strip("\"'") == "composite":
                for step in wf.steps:
                    if "run" in step["keys"] and "shell" not in step["keys"]:
                        out.append(Finding("actions", "action-composite-shell", ERROR,
                                           path, step["keys"]["run"].line,
                                           "step composite con `run:` senza `shell:` "
                                           "(obbligatorio nelle action composite)"))
            _check_injection(out, ctx, wf, path)
            continue

        # --- workflow ------------------------------------------------------
        if not wf.name:
            out.append(Finding("actions", "wf-no-name", WARN, path, 1,
                               "workflow senza `name:`"))
        if not wf.triggers:
            out.append(Finding("actions", "wf-no-trigger", ERROR, path, 1,
                               "workflow senza trigger (`on:`): non parte mai"))
        if wf.permissions is None:
            out.append(Finding("actions", "wf-permissions-missing", ERROR, path, 1,
                               "manca `permissions:` a livello workflow (default troppo "
                               "largo: least privilege)", fix="wf-permissions"))
        elif wf.permissions.get("__all__") == "write-all":
            out.append(Finding("actions", "wf-permissions-write-all", ERROR, path, 1,
                               "`permissions: write-all` e' il contrario del "
                               "least privilege"))

        triggers = set(t.lower() for t in wf.triggers)
        if "pull_request_target" in triggers:
            perms = wf.permissions or {}
            writable = {k: v for k, v in perms.items()
                        if k != "__all__" and str(v).startswith("write")}
            if writable or perms.get("__all__") == "write-all":
                out.append(Finding("actions", "wf-pr-target-write", ERROR, path, 1,
                                   "`pull_request_target` con permessi di scrittura "
                                   "(%s): rischio 'pwn request', il codice della PR "
                                   "gira con i secrets del repo" % ", ".join(writable)))
            else:
                out.append(Finding("actions", "wf-pr-target", WARN, path, 1,
                                   "`pull_request_target`: verifica che non esegua "
                                   "codice della PR"))
        if triggers & {"push", "pull_request", "schedule", "workflow_dispatch"} \
                and not wf.has_concurrency:
            out.append(Finding("actions", "wf-concurrency-missing", WARN, path, 1,
                               "senza `concurrency:` le corse si accumulano e girano "
                               "in parallelo sullo stesso branch", fix="wf-concurrency"))

        for job in wf.jobs.values():
            if not job["runs_on"] and "uses" not in job["keys"]:
                out.append(Finding("actions", "wf-job-no-runs-on", ERROR, path,
                                   job["line"], "job `%s` senza `runs-on:`" % job["id"]))
            if not job["steps"] and "uses" not in job["keys"]:
                out.append(Finding("actions", "wf-job-no-steps", ERROR, path,
                                   job["line"], "job `%s` senza `steps:`" % job["id"]))

        _check_injection(out, ctx, wf, path)
        _check_downloads(out, ctx, wf, path)
        _check_merge_redispatch(out, ctx, wf, path)
        _check_pr_token(out, ctx, wf, path)
    return out


def _check_injection(out, ctx, wf, path):
    """Espressioni `${{ }}` dentro uno script: classic GitHub script injection."""
    for step in wf.steps:
        run = step["keys"].get("run")
        if run is None:
            continue
        chunks = [(ln, txt) for ln, txt in run.block]
        if run.value:
            chunks.insert(0, (run.line, run.value))
        for lineno, chunk in chunks:
            for m in EXPR_RE.finditer(chunk):
                expr = m.group(1).strip()
                low = expr.lower()
                if any(low.startswith(p) for p in UNSAFE_EXPR):
                    out.append(Finding("actions", "wf-run-injection", ERROR, path,
                                       lineno,
                                       "`${{ %s }}` interpolato in uno script: e' "
                                       "controllabile dall'esterno (script injection). "
                                       "Passa dal blocco `env:` dello step" % expr))
                elif any(low.startswith(p) for p in SEMI_UNSAFE_EXPR):
                    out.append(Finding("actions", "wf-run-inputs", WARN, path, lineno,
                                       "`${{ %s }}` interpolato in uno script: passa "
                                       "dal blocco `env:` dello step" % expr))


DOWNLOAD_RE = re.compile(r"\b(curl|wget)\b")
EXEC_RE = re.compile(r"(tar\s+(-\w*[xz]\w*)|unzip\b|chmod\s+\+x|\./[A-Za-z0-9_.\-]+"
                     r"|\bbash\s+[A-Za-z0-9_.\-/]+\.sh|\bsh\s+[A-Za-z0-9_.\-/]+\.sh)")
VERIFY_RE = re.compile(r"(sha256sum|sha256|SHA256|checksum|--verify|gpg\b|cosign)")


def _check_downloads(out, ctx, wf, path):
    """Binario scaricato ed eseguito senza verifica dell'hash: supply chain."""
    for step in wf.steps:
        run = step["keys"].get("run")
        if run is None or not run.block:
            continue
        text = "\n".join(t for _, t in run.block)
        if not (DOWNLOAD_RE.search(text) and EXEC_RE.search(text)):
            continue
        if VERIFY_RE.search(text):
            continue
        out.append(Finding("actions", "wf-unverified-download", ERROR, path,
                           run.line,
                           "scarica ed esegui/estrai un binario senza verificarne "
                           "l'SHA256: usa una action pinnata o aggiungi il checksum"))


MERGE_CALL_RE = re.compile(r"(gh\s+pr\s+merge\b|/pulls/[^\s\"']*?/merge\b|merge_method\s*=)")
REDISPATCH_RE = re.compile(r"(gh\s+workflow\s+run\b|/actions/workflows/[^\s\"']*?/dispatches"
                           r"|repository_dispatch)")


def _check_merge_redispatch(out, ctx, wf, path):
    """Merge col GITHUB_TOKEN senza riavvio esplicito delle workflow su main.

    GitHub non innesca nuove corse per gli eventi generati dal GITHUB_TOKEN
    (eccezioni: workflow_dispatch e repository_dispatch). Chi fonde una PR con
    il token di default quindi lascia ferme tutte le pipeline in ascolto sui
    push verso il branch predefinito: Release non pubblica l'APK corretto e le
    scansioni periodiche restano l'unico controllo sul codice appena unito.
    """
    merge_step = None
    code = []
    for step in wf.steps:
        run = step["keys"].get("run")
        if run is None or not run.block:
            continue
        # solo il codice dei blocchi run: i commenti citano spesso i nomi degli
        # eventi e falserebbero la verifica
        text = "\n".join(t for _, t in run.block)
        code.append(text)
        if merge_step is None and MERGE_CALL_RE.search(text):
            merge_step = run
    if merge_step is None:
        return
    if REDISPATCH_RE.search("\n".join(code)):
        return
    out.append(Finding("actions", "wf-merge-no-redispatch", WARN, path, merge_step.line,
                       "il merge usa il GITHUB_TOKEN: i push che genera non innescano "
                       "altre workflow, quindi Release e le scansioni su push verso il "
                       "branch predefinito restano ferme — riavvia quelle necessarie "
                       "con `gh workflow run <file> --ref <branch>`"))


CREATE_PR_RE = re.compile(r"uses:\s*peter-evans/create-pull-request\b")
WITH_TOKEN_RE = re.compile(r"^\s+token:\s*\S", re.M)


def _check_pr_token(out, ctx, wf, path):
    """PR aperta col GITHUB_TOKEN di default: non innesca nessun workflow.

    Vale la stessa regola anti-ricorsione del merge: una pull_request creata con
    il token della corsa non genera eventi, quindi sulla PR non partono ne' la CI
    ne' l'automerge. Il resto del ciclo resta bloccato su una PR che nessuno
    controlla e nessuno fonde.
    """
    lines = wf.text.split("\n")
    for i, line in enumerate(lines):
        if not CREATE_PR_RE.search(line):
            continue
        indent = len(line) - len(line.lstrip(" "))
        end = len(lines)
        for j in range(i + 1, len(lines)):
            nxt = lines[j]
            if not nxt.strip():
                continue
            ind = len(nxt) - len(nxt.lstrip(" "))
            if ind < indent or (ind <= indent and nxt.lstrip().startswith("- ")):
                end = j
                break
        if not WITH_TOKEN_RE.search("\n".join(lines[i:end])):
            out.append(Finding("actions", "wf-pr-token-default", WARN, path, i + 1,
                               "PR creata col GITHUB_TOKEN: le PR aperte cosi' non "
                               "innescano workflow, quindi la CI e l'automerge non "
                               "partono — usa un PAT (`token: ${{ secrets.X || "
                               "github.token }}`) o riavvia i check a mano"))


# --------------------------------------------------------------------------
# gate: Android (manifest, risorse, coerenza delle affermazioni)
# --------------------------------------------------------------------------
COMPONENT_RE = re.compile(r"<(activity|activity-alias|service|receiver|provider)\b")


def gate_android(ctx):
    out = []
    import xml.etree.ElementTree as ET

    manifest_path = os.path.join(ctx.root, "app", "src", "main", "AndroidManifest.xml")
    declared_perms = []
    if os.path.isfile(manifest_path):
        text = ctx.read(manifest_path)
        try:
            ET.fromstring(text)
        except ET.ParseError as exc:
            out.append(Finding("android", "xml-parse", ERROR, manifest_path,
                               getattr(exc, "lineno", None),
                               "manifest non valido: %s" % exc))
        declared_perms = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', text)
        for perm in declared_perms:
            if perm in FORBIDDEN_PERMISSIONS:
                out.append(Finding("android", "manifest-permission-dangerous", ERROR,
                                   manifest_path, _line_of(text, perm),
                                   "permesso %s: un analizzatore di sorveglianza non "
                                   "deve poter leggere SMS/microfono/fotocamera" % perm))
        if re.search(r'android:debuggable\s*=\s*"true"', text):
            out.append(Finding("android", "manifest-debuggable", ERROR, manifest_path,
                               _line_of(text, "debuggable"),
                               "android:debuggable=\"true\" in un APK di release"))

        # componenti esposti: su Android 12+ `exported` deve essere esplicito
        for m in COMPONENT_RE.finditer(text):
            start = m.start()
            end = text.find(">", start)
            tag = text[start:end + 1] if end != -1 else text[start:start + 400]
            has_filter = "<intent-filter" in text[start:start + 3000].split(
                "</%s>" % m.group(1))[0]
            if "android:exported" not in tag and has_filter:
                launcher = "android.intent.category.LAUNCHER" in text[start:start + 3000]
                out.append(Finding("android", "manifest-exported-missing", ERROR,
                                   manifest_path, text[:start].count("\n") + 1,
                                   "<%s> con intent-filter senza android:exported "
                                   "esplicito (install fallisce su Android 12+)"
                                   % m.group(1),
                                   fix="manifest-exported:%s" % ("true" if launcher
                                                                 else "false")))

    # risorse: nomi dichiarati vs nomi usati
    res_dir = os.path.join(ctx.root, "app", "src", "main", "res")
    defined = {"string": set(), "color": set(), "style": set(),
               "drawable": set(), "mipmap": set(), "array": set(),
               "string-array": set(), "integer-array": set()}
    if os.path.isdir(res_dir):
        for dirpath, dirnames, filenames in os.walk(res_dir):
            for name in filenames:
                if not name.endswith(".xml"):
                    continue
                p = os.path.join(dirpath, name)
                txt = ctx.read(p)
                try:
                    ET.fromstring(txt)
                except ET.ParseError as exc:
                    out.append(Finding("android", "xml-parse", ERROR, p,
                                       getattr(exc, "lineno", None),
                                       "XML risorse non valido: %s" % exc))
                folder = os.path.basename(dirpath).split("-")[0]
                for kind in ("string", "color", "style", "drawable", "array"):
                    for rm in re.finditer(r"<%s\s+[^>]*name=\"([^\"]+)\"" % kind, txt):
                        defined.setdefault(kind, set()).add(rm.group(1))
                if folder in ("drawable", "mipmap"):
                    defined.setdefault(folder, set()).add(os.path.splitext(name)[0])

    alias = {"string": "string", "color": "color", "style": "style",
             "drawable": "drawable", "mipmap": "mipmap", "array": "array"}
    used = {}
    scan_files = [p for p in ctx.files if p.endswith((".xml", ".java"))
                  and os.sep + "app" + os.sep in p]
    for p in scan_files:
        txt = ctx.read(p)
        for m in re.finditer(r"@(string|color|style|drawable|mipmap|array)/([\w.]+)", txt):
            used.setdefault(alias.get(m.group(1), m.group(1)), set()).add(m.group(2))
        for m in re.finditer(r"R\.(string|color|drawable|style|id|array|mipmap)\.(\w+)", txt):
            key = "drawable" if m.group(1) == "id" else m.group(1)
            if key in used or key in defined:
                used.setdefault(alias.get(key, key), set()).add(m.group(2))
    for kind, names in used.items():
        if kind == "id" or kind not in defined:
            continue
        for name in sorted(names):
            if name.startswith("android:"):
                continue
            if name not in defined.get(kind, set()):
                out.append(Finding("android", "res-missing", ERROR, None,
                                   message="riferimento a @%s/%s ma la risorsa non "
                                           "e' definita" % (kind, name)))
    for kind in ("string", "color", "style"):
        for name in sorted(defined.get(kind, ()) - used.get(kind, ())):
            out.append(Finding("android", "res-unused", INFO, res_dir,
                               message="%s `%s` definita ma mai usata" % (kind, name),
                               fix="res-unused"))

    # coerenza fra manifest e cio' che diciamo all'utente (README, UI, docs)
    if "android.permission.INTERNET" in declared_perms:
        claim = re.compile("|".join(NO_NET_CLAIMS), re.I)
        for p in ctx.files:
            if not p.endswith((".java", ".md", ".txt", ".xml")):
                continue
            if os.sep + "data" + os.sep in p:
                continue
            txt = ctx.read(p)
            for m in claim.finditer(txt):
                out.append(Finding("android", "claim-no-internet", ERROR, p,
                                   txt[:m.start()].count("\n") + 1,
                                   "il manifest dichiara INTERNET ma qui scriviamo "
                                   "%r: affermazione falsa per chi si fida dell'app"
                                   % m.group(0)))
    return out


def _line_of(text, needle):
    i = text.find(needle)
    return text[:i].count("\n") + 1 if i >= 0 else None


# --------------------------------------------------------------------------
# gate: dati (knowledge base stalkerware)
# --------------------------------------------------------------------------
def _read_data(ctx, name):
    path = os.path.join(ctx.root, "data", name)
    if not os.path.isfile(path):
        return path, []
    rows = []
    for num, line in enumerate(ctx.read(path).split("\n"), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        rows.append((num, s))
    return path, rows


def gate_data(ctx):
    out = []
    path, rows = _read_data(ctx, "threat-seed.txt")
    seen = {}
    valid = 0
    for num, row in rows:
        parts = row.split("|")
        if len(parts) != 4:
            out.append(Finding("data", "data-seed-format", ERROR, path, num,
                               "attese 4 colonne `pkg|nome|tipo|gravita`, trovate %d"
                               % len(parts)))
            continue
        pkg, name, kind, sev = [p.strip() for p in parts]
        if not PKG_RE.match(pkg):
            out.append(Finding("data", "data-seed-package", ERROR, path, num,
                               "nome pacchetto non valido: %s" % pkg))
        if sev not in SEV_DB:
            out.append(Finding("data", "data-seed-severity", ERROR, path, num,
                               "gravita' %r non ammessa (usa %s)"
                               % (sev, "/".join(SEV_DB))))
        if not name or not kind:
            out.append(Finding("data", "data-seed-empty", ERROR, path, num,
                               "nome o tipo vuoto per %s" % pkg))
        if pkg in seen:
            out.append(Finding("data", "data-seed-dup", WARN, path, num,
                               "%s duplicato (gia' alla riga %d)" % (pkg, seen[pkg]),
                               fix="data-dedupe"))
        else:
            seen[pkg] = num
            valid += 1
    if rows and valid < 20:
        out.append(Finding("data", "data-seed-count", ERROR, path,
                           message="solo %d voci valide: la knowledge base non puo' "
                                   "scendere sotto 20 (regressione)" % valid))

    path, rows = _read_data(ctx, "threat-patterns.txt")
    seen = set()
    for num, row in rows:
        parts = row.split("|")
        if len(parts) != 5:
            out.append(Finding("data", "data-pattern-format", ERROR, path, num,
                               "attese 5 colonne `TIPO|valore|nome|tipo|gravita`"))
            continue
        typ, value, name, kind, sev = [p.strip() for p in parts]
        if typ not in PATTERN_TYPES:
            out.append(Finding("data", "data-pattern-type", ERROR, path, num,
                               "tipo %r non ammesso (PKG/CERT/COMP)" % typ))
        if typ == "CERT" and not CERT_RE.match(value):
            out.append(Finding("data", "data-pattern-cert", ERROR, path, num,
                               "CERT deve essere un SHA-256 di 64 hex: %s" % value))
        if typ in ("PKG", "COMP") and len(value) < 3:
            out.append(Finding("data", "data-pattern-value", ERROR, path, num,
                               "valore troppo corto (%s): troppi falsi positivi" % value))
        if sev not in SEV_DB:
            out.append(Finding("data", "data-pattern-severity", ERROR, path, num,
                               "gravita' %r non ammessa" % sev))
        if (typ, value.lower()) in seen:
            out.append(Finding("data", "data-pattern-dup", WARN, path, num,
                               "pattern %s|%s duplicato" % (typ, value),
                               fix="data-dedupe"))
        seen.add((typ, value.lower()))

    path, rows = _read_data(ctx, "official-signatures.txt")
    seen = {}
    for num, row in rows:
        if "=" not in row:
            out.append(Finding("data", "data-signature-format", ERROR, path, num,
                               "atteso `pacchetto=SHA256`"))
            continue
        pkg, _, digest = row.partition("=")
        pkg, digest = pkg.strip(), digest.strip()
        if not PKG_RE.match(pkg):
            out.append(Finding("data", "data-signature-package", ERROR, path, num,
                               "pacchetto non valido: %s" % pkg))
        if not CERT_RE.match(digest):
            out.append(Finding("data", "data-signature-hash", ERROR, path, num,
                               "hash non valido (64 hex attesi): %s" % digest))
        if pkg in seen:
            out.append(Finding("data", "data-signature-dup", WARN, path, num,
                               "%s duplicato (riga %d)" % (pkg, seen[pkg]),
                               fix="data-dedupe"))
        seen[pkg] = num

    # ThreatDbGenerated.java deve corrispondere al generatore
    gen = os.path.join(ctx.root, "scripts", "update-threat-db.py")
    if os.path.isfile(gen):
        r = ctx.run([sys.executable, gen, "--check"], timeout=180)
        if r.returncode not in (0,):
            target = os.path.join(ctx.root, "app", "src", "main", "java",
                                  "it", "spydetector", "app", "core",
                                  "ThreatDbGenerated.java")
            detail = _one_line((r.stdout or "") + (r.stderr or "")) or \
                "exit %d" % r.returncode
            out.append(Finding("data", "data-threatdb-sync", ERROR, target,
                               message="ThreatDbGenerated.java non allineato ai data/"
                                       " (%s)" % detail, fix="data-threatdb"))
    return out


# --------------------------------------------------------------------------
# gate: documentazione
# --------------------------------------------------------------------------
MD_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def gate_docs(ctx):
    out = []
    md_files = [p for p in ctx.files if p.endswith(".md")]
    for p in md_files:
        txt = ctx.read(p)
        for num, line in enumerate(txt.split("\n"), 1):
            for m in MD_LINK.finditer(line):
                target = m.group(1).strip()
                if target.startswith(("http://", "https://", "mailto:", "#", "<")):
                    continue
                target = target.split("#", 1)[0]
                if not target:
                    continue
                resolved = os.path.normpath(os.path.join(os.path.dirname(p), target))
                if not resolved.startswith(ctx.root + os.sep):
                    # link relativo a GitHub (es. ../../releases): non verificabile
                    continue
                if not os.path.exists(resolved):
                    out.append(Finding("docs", "docs-link-broken", ERROR, p, num,
                                       "collegamento a %s inesistente" % target))

    # ogni workflow deve essere documentato in docs/SECURITY.md
    sec = os.path.join(ctx.root, "docs", "SECURITY.md")
    wf_dir = os.path.join(ctx.root, ".github", "workflows")
    if os.path.isfile(sec) and os.path.isdir(wf_dir):
        doc = ctx.read(sec)
        for name in sorted(os.listdir(wf_dir)):
            if not name.endswith((".yml", ".yaml")):
                continue
            if name not in doc:
                out.append(Finding("docs", "docs-workflow-undocumented", WARN,
                                   os.path.join(wf_dir, name),
                                   message="%s non e' documentato in docs/SECURITY.md"
                                           % name, fix="docs-workflow-row"))

    # ogni script dovrebbe essere citato in README o in docs/
    corpus = ""
    for p in md_files:
        corpus += ctx.read(p)
    for p in sorted(ctx.by_ext(".py", ".sh")):
        rel = ctx.rel(p)
        if not rel.startswith("scripts/") and not rel.startswith("tools/"):
            continue
        if rel not in corpus and os.path.basename(p) not in corpus:
            out.append(Finding("docs", "docs-script-undocumented", INFO, p,
                               message="%s non e' citato in nessuna documentazione"
                                       % rel))
    return out


# --------------------------------------------------------------------------
# gate: build + verifica APK (opzionale, serve la toolchain)
# --------------------------------------------------------------------------
ECJ_ERR = re.compile(r"^(?:ERROR|WARNING) in (?P<path>[^\s]+\.java)\s*\(at line (?P<line>\d+)\)",
                     re.M)


def gate_build(ctx):
    out = []
    aapt2 = os.path.join(ctx.root, ".toolchain", "bin", "aapt2")
    build_sh = os.path.join(ctx.root, "build.sh")
    if not os.path.isfile(build_sh):
        return [Finding("build", "build-script-missing", ERROR, build_sh,
                        message="build.sh assente")]
    if not os.path.exists(aapt2):
        return [Finding("build", "build-toolchain-missing", WARN, aapt2,
                        message="toolchain non scaricata: esegui "
                                "./tools/fetch-toolchain.sh (gate build saltato)")]

    r = ctx.run(["./build.sh"], timeout=1800)
    log = os.path.join(ctx.root, "build", "ecj.log")
    if r.returncode != 0:
        ecj = ctx.read(log) if os.path.isfile(log) else ""
        found = False
        for m in ECJ_ERR.finditer(ecj):
            p = m.group("path")
            if not os.path.isabs(p):
                p = os.path.join(ctx.root, p)
            out.append(Finding("build", "java-compile", ERROR, p, int(m.group("line")),
                               "errore di compilazione ECJ (vedi build/ecj.log)"))
            found = True
        if not found:
            tail = "\n".join(((r.stdout or "") + (r.stderr or "")).split("\n")[-25:])
            out.append(Finding("build", "build-failed", ERROR, build_sh,
                               message="build.sh fallito (exit %d):\n%s"
                                       % (r.returncode, tail)))
        return out

    import glob
    apks = sorted(glob.glob(os.path.join(ctx.root, "dist", "*.apk")))
    if not apks:
        out.append(Finding("build", "apk-missing", ERROR, build_sh,
                           message="build.sh ok ma nessun APK in dist/"))
        return out
    verify = os.path.join(ctx.root, "scripts", "verify-apk.py")
    r = ctx.run([sys.executable, verify, apks[0]], timeout=300)
    if r.returncode != 0:
        bad = [l for l in (r.stdout or "").split("\n") if "FAIL" in l]
        out.append(Finding("build", "apk-verify", ERROR, apks[0],
                           message="verifica APK fallita: %s"
                                   % ("; ".join(x.strip() for x in bad) or "vedi log")))
    return out


# --------------------------------------------------------------------------
# registro dei gate
# --------------------------------------------------------------------------
GATES = [
    ("hygiene", gate_hygiene, "whitespace, newline, BOM, residui, permessi, VERSION"),
    ("shell", gate_shell, "sintassi bash, shebang, strict mode, shellcheck"),
    ("python", gate_python, "sintassi, import inutilizzati, shebang, docstring"),
    ("java", gate_java, "package, tipi, import, catch vuoti, check registrati"),
    ("actions", gate_actions, "workflow/action: pin SHA, permessi, injection, supply chain"),
    ("android", gate_android, "manifest, permessi, risorse, coerenza delle affermazioni"),
    ("data", gate_data, "knowledge base stalkerware e codice generato"),
    ("docs", gate_docs, "collegamenti e copertura della documentazione"),
    ("build", gate_build, "build APK + verifica (solo con --with-build)"),
]
GATE_NAMES = [g[0] for g in GATES]


def run_gates(ctx, only=None, skip=(), with_build=False, quiet=False, executed=None):
    """Esegue i gate selezionati e ritorna la lista di finding.

    `executed`, se passato (una lista), riceve i nomi dei gate eseguiti.
    """
    findings = []
    if executed is not None:
        del executed[:]
    for name, func, _desc in GATES:
        if name == "build" and not with_build:
            continue
        if only and name not in only:
            continue
        if name in skip:
            continue
        if executed is not None:
            executed.append(name)
        if not quiet:
            print("==> gate %s" % name)
        try:
            got = func(ctx) or []
        except Exception as exc:  # noqa: BLE001
            got = [Finding(name, "gate-crash", ERROR, None,
                           message="il gate e' fallito: %s: %s"
                                   % (type(exc).__name__, exc))]
        findings.extend(got)
        if not quiet:
            errs = sum(1 for f in got if f.severity == ERROR)
            warns = sum(1 for f in got if f.severity == WARN)
            infos = sum(1 for f in got if f.severity == INFO)
            print("    %d errori, %d avvisi, %d info" % (errs, warns, infos))
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.gate, f.rel(), f.line or 0))
    return findings


def summarize(findings, fail_on=ERROR, executed=None):
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    failed = sum(counts[s] for s in SEVERITIES
                 if SEV_RANK[s] <= SEV_RANK[fail_on])
    fixable = sorted({f.fix.split(":")[0] for f in findings
                      if f.fix and SEV_RANK[f.severity] <= SEV_RANK[fail_on]})
    manual = sorted({f.rule for f in findings
                     if not f.fix and SEV_RANK[f.severity] <= SEV_RANK[fail_on]})
    return {"errors": counts[ERROR], "warnings": counts[WARN], "infos": counts[INFO],
            "total": len(findings), "failed": failed, "ok": failed == 0,
            "fixable": fixable, "manual": manual, "fail_on": fail_on,
            "gates": list(executed or [])}


def markdown(findings, summary=None, title="Gate di qualita'"):
    summary = summary or summarize(findings)
    lines = ["### %s" % title, ""]
    if summary["ok"]:
        lines.append("Tutti i gate verdi: **%d avvisi**, **%d info**, nessun errore."
                     % (summary["warnings"], summary["infos"]))
    else:
        lines.append("**%d errori**, %d avvisi, %d info."
                     % (summary["errors"], summary["warnings"], summary["infos"]))
    lines.append("")
    by_gate = {}
    for f in findings:
        by_gate.setdefault(f.gate, []).append(f)
    lines += ["| gate | errori | avvisi | info |", "|---|---:|---:|---:|"]
    # mostra anche i gate passati senza finding: si deve vedere cosa e' girato
    executed = summary.get("gates") or [n for n in GATE_NAMES if n in by_gate]
    for name in GATE_NAMES:
        if name not in executed:
            continue
        got = by_gate.get(name, [])
        lines.append("| `%s` | %d | %d | %d |" % (
            name,
            sum(1 for f in got if f.severity == ERROR),
            sum(1 for f in got if f.severity == WARN),
            sum(1 for f in got if f.severity == INFO)))
    if summary["fixable"]:
        lines += ["", "Riparabili in automatico: " +
                  ", ".join("`%s`" % f for f in summary["fixable"])]
    if summary["manual"]:
        lines += ["", "Serve una persona: " +
                  ", ".join("`%s`" % f for f in summary["manual"])]
    show = [f for f in findings if f.severity != INFO][:40]
    if show:
        lines += ["", "| gravita' | regola | dove | cosa |", "|---|---|---|---|"]
        for f in show:
            where = f.rel() + ((":%d" % f.line) if f.line else "")
            msg = f.message.replace("\n", " ").replace("|", "\\|")
            if len(msg) > 160:
                msg = msg[:157] + "..."
            lines.append("| %s | `%s` | `%s` | %s |" % (f.severity, f.rule, where, msg))
        if len(findings) > len(show):
            lines.append("")
            lines.append("_altre %d finding (info) nel report JSON_"
                         % (len(findings) - len(show)))
    lines.append("")
    return "\n".join(lines)


def write_report(path, ctx, findings, summary):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    payload = {"schema": 1, "root": ctx.root, "summary": summary,
               "notes": ctx.notes, "findings": [f.to_dict() for f in findings]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return payload


def load_report(path):
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    findings = []
    for d in payload.get("findings", []):
        p = d.get("path") or None
        if p and not os.path.isabs(p):
            p = os.path.join(ROOT, p)
        findings.append(Finding(d["gate"], d["rule"], d["severity"], p,
                                d.get("line"), d.get("message", ""), d.get("fix")))
    return findings, payload.get("summary", {}), payload.get("notes", [])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gate", action="append", choices=GATE_NAMES,
                    help="esegui solo questo gate (ripetibile)")
    ap.add_argument("--skip", action="append", choices=GATE_NAMES, default=[],
                    help="salta questo gate (ripetibile)")
    ap.add_argument("--with-build", action="store_true",
                    help="esegui anche build.sh + verify-apk.py")
    ap.add_argument("--json", metavar="PATH", help="scrivi il report JSON in PATH")
    ap.add_argument("--fail-on", choices=SEVERITIES, default=ERROR,
                    help="gravita' minima che fa fallire (default: error)")
    ap.add_argument("--max-print", type=int, default=60,
                    help="quante finding stampare (default 60, 0 = tutte)")
    ap.add_argument("--step-summary", action="store_true",
                    help="aggiungi il riepilogo a $GITHUB_STEP_SUMMARY")
    ap.add_argument("--quiet", action="store_true", help="niente avanzamento")
    ap.add_argument("--list", action="store_true", help="elenca gate e regole")
    args = ap.parse_args(argv)

    if args.list:
        print("Gate disponibili:")
        for name, _func, desc in GATES:
            print("  %-10s %s" % (name, desc))
        print("\nRegole con correzione automatica (scripts/autofix.py):")
        try:
            import autofix
            for fix_id in sorted(autofix.FIXERS):
                print("  %-22s %s" % (fix_id, autofix.FIXERS[fix_id].__doc__.
                                      strip().split("\n")[0]))
        except Exception as exc:  # noqa: BLE001
            print("  (autofix non importabile: %s)" % exc)
        return 0

    ctx = Ctx()
    if not ctx.files:
        print("ERRORE: nessun file trovato in %s" % ctx.root, file=sys.stderr)
        return 2
    executed = []
    findings = run_gates(ctx, only=set(args.gate or []), skip=set(args.skip),
                         with_build=args.with_build, quiet=args.quiet,
                         executed=executed)
    summary = summarize(findings, args.fail_on, executed)

    limit = args.max_print or len(findings)
    shown = [f for f in findings if f.severity != INFO][:limit]
    if shown:
        print("")
        for f in shown:
            print("  " + str(f))
        if len(findings) > len(shown):
            print("  ... altre %d finding nel report" % (len(findings) - len(shown)))
    for note in ctx.notes:
        print("  nota: %s" % note)

    print("\nESITO: %d errori, %d avvisi, %d info -> %s"
          % (summary["errors"], summary["warnings"], summary["infos"],
             "OK" if summary["ok"] else "FALLITO"))
    if summary["fixable"]:
        print("Riparabili in automatico: %s" % ", ".join(summary["fixable"]))
    if summary["manual"]:
        print("Serve una persona per: %s" % ", ".join(summary["manual"]))

    if args.json:
        write_report(args.json, ctx, findings, summary)
        print("report: %s" % args.json)
    if args.step_summary:
        target = os.environ.get("GITHUB_STEP_SUMMARY")
        if target:
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(markdown(findings, summary) + "\n")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
