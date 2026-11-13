# Sicurezza del progetto

## Come funziona la catena di build

Ogni APK pubblicato è costruito **da GitHub Actions**, non da una macchina
locale. Le stesse verifiche girano in CI e in locale (`./build.sh`).

| Livello | Cosa viene verificato | Dove |
|---|---|---|
| **Toolchain** | JDK, `aapt2`, `d8`, `ecj`, `apksigner`, `android.jar` pinnati a versione + **SHA256** (`tools/toolchain.env`), host solo `registry.npmjs.org` / `files.pythonhosted.org` | `tools/fetch-toolchain.sh`, `scripts/check-iocs.py` |
| **Update del toolchain** | ogni versione candidata viene **scaricata e provata** (aapt2 deve rispondere, i jar devono contenere le classi attese, il JDK deve avere `bin/java`+`keytool`) prima di essere pinnata | `scripts/update-toolchain.py` |
| **Action GitHub** | tutte pinnate a **commit SHA** con tag in commento; aggiornamento automatico solo restando nella stessa major, che viene letta dal tag e mai dallo SHA, e senza mai retrocedere (`--selftest`, 17 prove senza rete, gira a ogni CI) | `scripts/update-pins.py` |
| **APK** | struttura zip, manifest binario, package, activity, firma v2/v3, classi e check nel DEX, permessi **non** concessi (niente INTERNET/SMS/microfono/fotocamera) | `scripts/verify-apk.py` |
| **Firma** | `apksigner verify` con schema v2+v3 | `build.sh` |
| **Provenienza** | attestazione di build + SBOM con `actions/attest` (verificabile con `gh attestation verify`) | `release.yml` |
| **SBOM** | SPDX dell'APK allegato alla release | `release.yml` |
| **Tracciabilita'** | la descrizione della release elenca i fix applicati: commit `[self-heal]` con le regole usate, piu' le altre modifiche dalla release precedente | `release.yml` |
| **Malware** | ClamAV sull'APK, ogni push e ogni notte | `malware-scan.yml` |
| **Segreti** | gitleaks su tutto lo storico | `secrets.yml` |
| **SAST** | CodeQL (Actions) + Semgrep (Java/Android, Python, Bash) | `codeql.yml`, `sast.yml` |
| **Dipendenze** | Dependency Review sulle PR, Dependabot giornaliero | `dependency-review.yml`, `dependabot.yml` |
| **Vulnerabilità** | OSV Scanner + Trivy (vuln, secret, misconfig) con report in code scanning | `vulnerability-scan.yml` |
| **CI** | actionlint sulle workflow, gate di qualita' + self-test del ciclo, build e verifica dell'APK su ogni PR e branch di lavoro | `ci.yml`, `.github/actions/` |
| **Gate di qualita'** | regole su codice Java/Python/shell, workflow (pin SHA, permessi, script injection, binari non verificati), manifest, dati e docs | `scripts/gates.py` |
| **Correzioni deterministiche** | ogni regola riparabile ha una trasformazione idempotente e verificabile: niente patch inventate | `scripts/autofix.py` |
| **Self-healing** | ciclo gate → correzione → gate (fino a N round), PR solo se chiude verde, regressione annullata con git | `self-heal.yml`, `scripts/selfheal.py` |
| **Innesco automatico** | se una pipeline fallisce, il ciclo riparte sul branch che ha fallito e avvisa nella PR | `auto-fix-on-failure.yml` |
| **Self-test del ciclo** | 91 controlli su una copia del repo con difetti iniettati, **anche quando il repo non e' pulito** (le assert confrontano i delta con la baseline: un soccorritore che pretende un repo sano non soccorre nessuno): difetti iniettati in una copia del repo, il ciclo deve ripararli tutti e non toccare cio' che non sa riparare | `scripts/test-selfheal.py` |
| **Automerge sicuro** | le PR vengono unite solo se **tutti** i check sono verdi (le major di Dependabot restano manuali); dopo il merge riavvia Release e Malware/IOC, perche' un merge fatto col `GITHUB_TOKEN` non genera eventi push | `automerge.yml` |
| **Postura repo** | OpenSSF Scorecard settimanale | `repo-scorecard.yml` |
| **Aggiornamenti** | job giornaliero che aggiorna toolchain/action/threat DB, **ricompila e verifica**, e apre PR solo se tutto passa | `security-updates.yml` |

## Ciclo di self-healing

Il repository si corregge da solo con un ciclo chiuso. Ogni passaggio e'
verificato dal successivo: niente finisce su `main` senza che tutta la CI lo
abbia ricontrollato.

```
  CI · SAST · CodeQL · Secret · Malware · Vulnerability · Scorecard · Release
                                     │ fallisce
                                     ▼
                          Auto-Fix (innesco)  ── leggia la diagnosi, controlla
                                     │          i tetti, avvisa nella PR
                                     ▼
                               Self-Heal
                    gate → correzioni deterministiche → gate
                              (fino a N round)
                                     │
                    ┌────────────────┴────────────────┐
              chiude verde                    errori residui
                    │                                 │
                    ▼                                 ▼
          PR con le correzioni              issue `self-heal` con il report
                    │                       (nessuna patch inventata)
                    ▼
     tutta la CI ricontrolla la PR
                    │
       ┌────────────┴────────────┐
    tutto verde              qualcosa fallisce
       │                         │
       ▼                         ▼
  automerge → Release      Auto-Fix riavvia il ciclo
  (APK nuovo)              (tetto: 3 tentativi sul branch)
```

### Cosa corregge da solo

Solo trasformazioni **deterministiche** e **idempotenti** (rilanciarle non
cambia piu' nulla). Elenco completo: `python3 scripts/autofix.py --list`.

| Regola | Cosa fa |
|---|---|
| `ws-trailing`, `ws-final-newline`, `ws-crlf`, `ws-bom` | whitespace, newline finale, CRLF → LF, BOM |
| `expand-tabs`, `yaml-tabs` | tab → spazi (4 per Java/Python, 2 per YAML) |
| `py-unused-import`, `java-unused-import` | rimuove gli import il cui nome non compare mai nel file |
| `sh-shebang`, `py-shebang`, `sh-strict` | shebang e `set -euo pipefail` mancanti |
| `file-exec-bit`, `file-leftover`, `gitignore-add` | permessi di esecuzione, residui di merge, `.gitignore` |
| `java-package` | allinea la dichiarazione `package` al percorso del file |
| `wf-permissions`, `wf-concurrency` | aggiunge `permissions: contents: read` e il blocco `concurrency` |
| `wf-pin` | pinna le action al commit SHA (via `scripts/update-pins.py`, serve rete); aggiorna solo nella stessa major e rifiuta le retrocessioni |
| `manifest-exported` | aggiunge `android:exported` esplicito ai componenti con intent-filter |
| `data-dedupe`, `data-threatdb` | voci duplicate nei `data/`, `ThreatDbGenerated.java` rigenerato |
| `docs-workflow-row` | aggiunge alla tabella qui sopra le workflow non documentate |
| `res-unused` | rimuove le risorse mai referenziate (**solo** con `--improve`) |

### Cosa NON corregge mai

Tutto cio' che richiederebbe una decisione al posto tuo. Il ciclo lo segnala in
una issue con il report, invece di inventare una patch:

| Regola | Perche' serve una persona |
|---|---|
| `java-compile`, `build-failed`, `apk-verify` | un errore di compilazione va capito, non mascherato |
| `claim-no-internet` | un'affermazione di privacy falsa va riscritta, non cancellata |
| `manifest-permission-dangerous` | aggiungere `READ_SMS` a un'app anti-spyware e' una scelta di prodotto |
| `java-check-not-registered` | attivare un'area di scansione cambia cosa vede l'utente |
| `wf-run-injection`, `wf-pr-target-write` | riscrivere il flusso di una workflow puo' rompere la CI |
| `wf-unverified-download` | scegliere la fonte e l'hash di un binario e' una decisione di supply chain |
| `wf-merge-no-redispatch` | decidere quali pipeline riavviare dopo un merge automatico e' progettazione della CI |
| `wf-pr-token-default` | fornire un PAT al ciclo e' una scelta di chi configura la repo: il token non si puo' inventare |
| `sh-syntax`, `py-syntax`, `yaml-invalid` | sintassi rotta: la causa non e' deducibile in modo sicuro |
| `sh-backtick` | un backtick fuori dagli apici singoli e' un comando: se era testo va escapato, se era sostituzione legacy va riscritto `$(...)` |
| `wf-gh-no-repo` | dove debba guardare `gh` (repo, branch, permessi) dipende dall'intento del passo |
| `data-seed-*`, `docs-link-broken` | contenuti curati a mano |

### Le sicurezze del ciclo

| Rischio | Come viene fermato |
|---|---|
| correzione che peggiora le cose | se gli errori **aumentano**, `--revert-on-regression` fa `git reset --hard` + `clean` e non apre nessuna PR |
| loop infinito fra CI e auto-fix | tentativi contati sul branch (marker `[self-heal]` nei commit, tetto 3) + tetto di 8 corse/24h nell'innesco + `concurrency` su entrambi |
| merge di una correzione sbagliata | la PR viene riesaminata da **tutta** la CI e `automerge.yml` la unisce solo se ogni check e' verde |
| correzione unita ma non pubblicata | GitHub non innesca workflow per gli eventi generati dal `GITHUB_TOKEN`: dopo il merge `automerge.yml` riavvia esplicitamente Release (nuovo APK) e Malware/IOC con `gh workflow run`, e il gate `wf-merge-no-redispatch` impedisce che il riavvio venga tolto |
| modifiche fuori controllo | il ciclo lavora solo sui file tracciati da git; i report finiscono in `build/` (ignorato) |
| esecuzione di codice arbitrario | le correzioni sono regole fisse in `scripts/autofix.py`: nessun LLM, nessun download, nessuna action nuova; la rete serve solo a `update-pins.py` (API GitHub) |
| il correttore si rompe | `scripts/test-selfheal.py` gira in CI prima del ciclo: difetti iniettati in una copia del repo, deve ripararli tutti |

### Token, PR del bot e il segreto `SPD_PR_TOKEN`

Il ciclo apre e fonde PR con l'identita' di GitHub Actions, e qui GitHub mette
tre ostacoli diversi. Sono stati verificati tutti e tre in CI, non dedotti.

| ostacolo | cosa succede | come viene chiuso |
|---|---|---|
| gli eventi generati dal `GITHUB_TOKEN` non innescano workflow (eccezioni: `workflow_dispatch` e `repository_dispatch`) | un merge automatico non fa partire ne' Release ne' le scansioni su main | `automerge.yml` riavvia esplicitamente `release.yml` e `malware-scan.yml`, e solo se la PR era verso il branch predefinito. Verificato: v0.0.7 e v0.0.8 pubblicate dopo i merge di #17 e #19 |
| senza checkout `gh` non determina la repo (`GITHUB_REPOSITORY` non gli basta) | il riavvio falliva e il passo risultava comunque verde | `GH_REPO` esplicito nei passi con `gh` + gate `wf-gh-no-repo` |
| **Settings → Actions → General → “Allow GitHub Actions to create and approve pull requests”** disattivato | `GitHub Actions is not permitted to create or approve pull requests`: la PR non nasce proprio | il ciclo non perde nulla (`continue-on-error`, issue `self-heal` col branch curato, `::error::`). Con la spunta attiva la PR nasce: verificato su #20, autore `app/github-actions` |

La spunta **non** toglie un ultimo cancello: le corse innescate da
`pull_request` su una PR aperta col token di corsa restano in `action_required`,
cioe' aspettano che qualcuno con accesso in scrittura prema **Approve workflows
to run**. Su #20 erano CI, Secret Scanning e Automerge; approvate con

    gh api -X POST repos/<owner>/<repo>/actions/runs/<run-id>/approve

la CI e' passata e automerge ha fuso. Il ciclo nel frattempo non resta cieco:
dispatcha `ci.yml` sul branch curato, e `workflow_dispatch` quel cancello non lo
passa, quindi le correzioni vengono verificate comunque — ad aspettare e' solo
il merge.

Per togliere anche quel clic serve il segreto **`SPD_PR_TOKEN`** (PAT
fine-grained: solo questa repo, `Contents` e `Pull requests` in scrittura,
scadenza breve). Le workflow lo usano come
`${{ secrets.SPD_PR_TOKEN || github.token }}`: con il PAT la PR nasce da
un'identita' utente, i check partono da soli e il ciclo chiude senza mani.
Senza, si ripiega sul token della corsa: la PR viene aperta, la CI riavviata a
mano, il corpo della PR spiega cosa manca. Nessun passo fallisce per questo.

I gate `wf-pr-token-default` (create-pull-request senza `token:` esplicito) e
`wf-merge-no-redispatch` (merge senza riavvio) impediscono che le scorciatoie
tornino indietro in silenzio.

### Provarlo in locale

```bash
python3 scripts/gates.py                    # tutti i controlli (0 errori = verde)
python3 scripts/gates.py --with-build       # + build dell'APK e verifica
python3 scripts/autofix.py --dry-run        # cosa verrebbe corretto, senza scrivere
python3 scripts/selfheal.py --with-build    # il ciclo completo
python3 scripts/test-selfheal.py            # self-test del meccanismo
```

## Aggiornamenti automatici giornalieri

Ogni giorno alle **04:17 UTC** (06:17 a Milano) `security-updates.yml`:

1. allinea le action pinnate alle ultime release compatibili;
2. valida e pinna la toolchain npm/PyPI più recente;
3. rigenera la knowledge base delle app di sorveglianza (`data/threat-seed.txt`
   → `ThreatDbGenerated.java`) con controllo anti-regressione (≥20 voci, la
   lista non può dimezzarsi);
4. **compila l'APK e lo verifica** con le versioni nuove;
5. scansiona con Trivy/OSV;
6. apre (o aggiorna) la PR `chore/security-updates`.

Se build o verifica falliscono, la PR **non viene aperta**: un aggiornamento
rotto non arriva mai al branch principale.

## Verificare un APK scaricato

```bash
sha256sum SpyDetector-v1.0.0-release.apk          # confronta con il .sha256
gh attestation verify SpyDetector-v1.0.0-release.apk --repo SiNaPsEr0x/SpyDetector
```

## Segnalare una vulnerabilità

Apri una **security advisory privata** (Security → Advisories → *Report a
vulnerability*) invece di una issue pubblica. Risposta attesa entro 7 giorni.

## Cose da sapere (limiti onesti)

- **La chiave di firma è nel repo** (`signing/spydetector-release.jks`,
  password `spydetector`): chiunque può firmare un APK con la stessa identità.
  Va bene per un progetto personale; per una distribuzione reale va sostituita
  con una chiave custodita fuori dal repository. La CI può usare i secrets
  `SPD_KS_B64` / `SPD_KS_PASS` se li configuri.
- Code scanning / Dependabot alerts / secret scanning richiedono che le
  funzioni di sicurezza siano abilitate nelle impostazioni del repository
  (Settings → Code security). Le workflow caricano i risultati appena attive.
- In CI `actionlint` applica shellcheck ai blocchi `run:` e **boccia anche gli
  avvisi di stile** (es. SC2006 sui backtick). In locale i gate coprono la
  sintassi (`bash -n`), i backtick (`sh-backtick`) e — se shellcheck e'
  installato — i suoi esiti, che pero' restano non bloccanti perche' la
  versione cambia da un ambiente all'altro. Un giro in CI resta quindi
  l'ultima parola sulle workflow.
- Senza il segreto `SPD_PR_TOKEN` il ciclo **non si chiude da solo**: apre la PR
  e la fa verificare, ma i check innescati dalla PR restano in `action_required`
  e il merge aspetta un'approvazione umana (vedi sopra).
