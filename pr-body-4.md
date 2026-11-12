## Fix UI: font dinamici auto-regolabili + altre correzioni

### Problema
Tutti i testi della UI usavano dimensioni SP fisse (es. `14f`, `10f`, `30f`).
Su schermi piccoli (es. Galaxy S21 con 375dp) i font apparivano eccessivi,
su schermi grandi (es. tablet 600dp+) i font erano troppo piccoli.

### Soluzione
Implementato un sistema di scaling dinamico dei font basato sulla larghezza
dello schermo:

1. **`Ui.fontScale(Context)`** — calcola un fattore di scaling partendo
   dalla larghezza in dp dello schermo (riferimento: 360dp).
   Scala: 0.85× su schermi piccoli → 1.4× su schermi grandi.
   Clampata tra 0.85 e 1.4 per evitare estremi.

2. **`Ui.sp(Context, base)`** — converte un valore SP base in SP scalato.

3. **`Ui.textS()`, `labelS()`, `chipS()`, `buttonS()`** — sostituiscono
   `text()`, `label()`, `chip()`, `button()` con testo scalato dinamicamente.
   Tous i metodi originali mantenuti per backward compat.

### Altre correzioni
- Credit text: `9f` → `9.5f` base (leggibilità migliorata)
- Build verificato: 64 classi compilate, APK signature OK

### Risultato
- Schermo 360dp: fattore 1.0× (nessun cambiamento)
- Schermo 300dp: fattore 0.85× (font più piccoli)
- Schermo 420dp: fattore 1.17× (font leggermente più grandi)
- Schermo 500dp+: fattore 1.4× (font più grandi)
