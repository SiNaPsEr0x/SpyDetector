# IOC della supply chain di build

Generato da `scripts/check-iocs.py`. Controlla i pacchetti usati per
costruire l'APK (npm + PyPI): hash, host, script di install, host di esfiltrazione noti.

| esito | controllo |
|---|---|
| ✅ | AAPTJS3 2.0.2: SHA256 verificato (26031bd1acb577ed…) |
| ✅ | AAPTJS3: nessuno script di install |
| ✅ | AAPTJS3: nessun host di esfiltrazione noto |
| ✅ | MINAPK 0.5.1: SHA256 verificato (5e411bfdf4a0eae8…) |
| ✅ | MINAPK: nessuno script di install |
| ✅ | MINAPK: nessun host di esfiltrazione noto |
| ✅ | JDK 21.0.8.2: SHA256 verificato (85addfcb57c7051d…) |
| ✅ | JDK: struttura attesa (bin/java presente) |

**Esito: PASSATO** (0 fail, 0 warning)

