# SpyDetector

**Controlla se il tuo Android è spiato.** Un'analisi completa del telefono in
pochi secondi: punteggio di rischio da 0 a 100 e, per ogni problema, il motivo e
cosa fare.

Tutto avviene **sul telefono**: l'app non ha il permesso Internet e non manda
fuori nessun dato.

<p align="center">
  <img src="docs/preview.png" alt="SpyDetector: punteggio di rischio, contatori per gravità e aree analizzate" width="900">
</p>

---

## Come si usa

1. **Scarica l'APK** dalla pagina [Releases](../../releases) di questo repository.
2. **Aprilo sul telefono** e consenti *Installa da questa origine*.
3. Apri SpyDetector: la scansione parte da sola. Puoi ripeterla quando vuoi con
   **AVVIA SCANSIONE COMPLETA**.
4. Leggi il risultato: tocca un'area per vedere i dettagli, poi **CONDIVIDI** per
   salvare o inviare il report.

Serve **Android 8.0 o successivo**.

## Cosa trova

| Area | Esempi di cosa controlla |
|---|---|
| **Sistema** | root, bootloader sbloccato, sistema modificato, protezioni kernel disattivate |
| **Configurazione** | blocco schermo, cifratura, aggiornamenti di sicurezza vecchi, debug USB |
| **Accessibilità** | app che possono *leggere lo schermo*: è così che si rubano chat, password e codici |
| **Notifiche e controllo** | chi legge le tue notifiche, chi può impedire la disinstallazione, tastiere e app SMS strane |
| **Spyware noto** | confronto con un elenco di app di sorveglianza conosciute (mSpy, FlexiSPY, Hoverwatch…) |
| **WhatsApp e Telegram** | versioni modificate (GB WhatsApp, Plus, YoWA…), firma dell'app, come controllare i dispositivi collegati |
| **App installate** | app arrivate fuori dal Play Store, nomi sospetti, permessi pericolosi (SMS + microfono + posizione + fotocamera) |
| **Rete** | VPN e tunnel attivi, proxy impostati |

### Come leggere il punteggio

| Punteggio | Significato |
|---|---|
| **0** | nessun rischio rilevato |
| **1–9** | basso: ci sono dettagli da sistemare |
| **10–24** | medio: qualche impostazione va corretta |
| **25–49** | alto: ci sono app o permessi da verificare subito |
| **50–100** | critico: possibile sorveglianza attiva |

Ogni voce ha una gravità (OK, attenzione, rischio, critico): apri il dettaglio
per vedere **la prova** e **la cosa da fare**.

## Se il risultato non ti convince

- **Non è un antivirus.** Rileva indizi tecnici, non tutto lo spyware esistente.
- Se vedi un'app che non riconosci con accessibilità o lettura notifiche,
  revoca quei permessi e disinstallala.
- In caso di dubbio serio: reset ai dati di fabbrica e cambio password da un
  **altro** dispositivo.
- Su Android 9+ l'elenco dei servizi di accessibilità può essere nascosto alle
  app: SpyDetector lo dice e ti indica dove controllare a mano.

## Privacy

Nessun permesso di rete, nessun account, nessuna pubblicità, nessuna statistica.
L'elenco delle app installate viene letto solo in locale per l'analisi.

## Per chi sviluppa

L'APK si compila senza Android Studio:

```bash
./tools/fetch-toolchain.sh    # scarica gli strumenti di build
./build.sh                    # crea dist/SpyDetector-v<versione>-release.apk
```

Dettagli su build, automazione e controlli di sicurezza:
[docs/SECURITY.md](docs/SECURITY.md).

## Licenza

Uso personale e didattico. Analizza solo dispositivi tuoi o per cui hai
un'autorizzazione esplicita.
