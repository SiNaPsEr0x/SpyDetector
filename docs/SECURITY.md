# Sicurezza del progetto

## Come funziona la catena di build

Ogni APK pubblicato è costruito **da GitHub Actions**, non da una macchina
locale. Le stesse verifiche girano in CI e in locale (`./build.sh`).

| Livello | Cosa viene verificato | Dove |
|---|---|---|
| **Toolchain** | JDK, `aapt2`, `d8`, `ecj`, `apksigner`, `android.jar` pinnati a versione + **SHA256** (`tools/toolchain.env`), host solo `registry.npmjs.org` / `files.pythonhosted.org` | `tools/fetch-toolchain.sh`, `scripts/check-iocs.py` |
| **Update del toolchain** | ogni versione candidata viene **scaricata e provata** (aapt2 deve rispondere, i jar devono contenere le classi attese, il JDK deve avere `bin/java`+`keytool`) prima di essere pinnata | `scripts/update-toolchain.py` |
| **Action GitHub** | tutte pinnate a **commit SHA** con tag in commento; aggiornamento automatico solo se la major è compatibile | `scripts/update-pins.py` |
| **APK** | struttura zip, manifest binario, package, activity, firma v2/v3, classi e check nel DEX, permessi **non** concessi (niente INTERNET/SMS/microfono/fotocamera) | `scripts/verify-apk.py` |
| **Firma** | `apksigner verify` con schema v2+v3 | `build.sh` |
| **Provenienza** | attestazione di build + `attest-sbom` (verificabile con `gh attestation verify`) | `release.yml` |
| **SBOM** | SPDX dell'APK allegato alla release | `release.yml` |
| **Malware** | ClamAV sull'APK, ogni push e ogni notte | `malware-scan.yml` |
| **Segreti** | gitleaks su tutto lo storico | `secrets.yml` |
| **SAST** | CodeQL (Java/Kotlin + Actions) | `codeql.yml` |
| **Dipendenze** | Dependency Review sulle PR, Dependabot giornaliero | `dependency-review.yml`, `dependabot.yml` |
| **Vulnerabilità** | OSV Scanner + Trivy (vuln, secret, misconfig) con report in code scanning | `vulnerability-scan.yml` |
| **SAST Java** | Semgrep (regole java/security-audit/shell/secrets) | `sast.yml` |
| **Automerge sicuro** | le PR di aggiornamento vengono unite solo se **tutti** i check sono verdi (le major restano manuali) | `automerge.yml` |
| **Postura repo** | OpenSSF Scorecard settimanale | `scorecard.yml` |
| **Aggiornamenti** | job giornaliero che aggiorna toolchain/action/threat DB, **ricompila e verifica**, e apre PR solo se tutto passa | `security-updates.yml` |

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
