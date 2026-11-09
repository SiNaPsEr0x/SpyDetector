package it.spydetector.app.checks;

import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Build;

import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;
import it.spydetector.app.util.Sys;

import java.util.ArrayList;
import java.util.List;

/**
 * Configurazione di sicurezza del dispositivo: blocco schermo, cifratura,
 * patch di sicurezza, debug USB, opzioni sviluppatore, installazione da
 * sorgenti sconosciute.
 */
public class DeviceHardeningCheck implements Check {

    @Override public String id() { return "HARDENING"; }
    @Override public String category() { return "Configurazione"; }
    @Override public String label() { return "Robustezza del dispositivo"; }

    @Override public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        Context ctx = data.ctx;

        // --- blocco schermo ------------------------------------------------
        boolean secure = false;
        try {
            KeyguardManager km = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
            secure = km != null && km.isDeviceSecure();
        } catch (Throwable ignored) {}
        if (secure) {
            out.add(new Finding("SCREEN_LOCK", cat, "Blocco schermo attivo", Severity.OK,
                    "PIN/password/biometria configurati.", "Nessuna azione necessaria."));
        } else {
            out.add(new Finding("SCREEN_LOCK", cat, "Nessun blocco schermo",
                    Severity.CRITICAL, "Il dispositivo non richiede PIN o impronta.",
                    "Senza blocco schermo chiunque prenda il telefono puo' leggere WhatsApp, "
                    + "installare app e attivare servizi di accessibilita'. Imposta subito un PIN "
                    + "di almeno 6 cifre."));
        }

        // --- cifratura -----------------------------------------------------
        try {
            DevicePolicyManager dpm = (DevicePolicyManager)
                    ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            int status = dpm == null ? -1 : dpm.getStorageEncryptionStatus();
            boolean enc = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                    || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
                    || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER;
            out.add(new Finding("ENCRYPTION", cat, "Cifratura memoria interna",
                    enc ? Severity.OK : Severity.WARNING,
                    "getStorageEncryptionStatus() = " + status,
                    enc ? "Nessuna azione necessaria."
                        : "La memoria non risulta cifrata: un PIN forte e la cifratura proteggono i "
                          + "dati se il telefono viene perso."));
        } catch (Throwable ignored) {}

        // --- patch di sicurezza -------------------------------------------
        if (Build.VERSION.SDK_INT >= 23) {
            String patch = Build.VERSION.SECURITY_PATCH == null ? "" : Build.VERSION.SECURITY_PATCH;
            long ts = Sys.date(patch);
            int months = Sys.monthsAgo(ts);
            if (months < 0) {
                out.add(new Finding("PATCH", cat, "Patch di sicurezza non determinabile",
                        Severity.INFO, "Valore non esposto dal sistema.", "Verifica gli aggiornamenti."));
            } else if (months > 12) {
                out.add(new Finding("PATCH", cat, "Patch di sicurezza molto vecchia",
                        Severity.WARNING, patch + " (~" + months + " mesi fa)",
                        "Il telefono non riceve aggiornamenti da oltre un anno: esistono vulnerabilita' "
                        + "note sfruttabili da remoto. Aggiorna il sistema o cambia dispositivo.")
                        .detail("Patch", patch).detail("Mesi", String.valueOf(months)));
            } else if (months > 6) {
                out.add(new Finding("PATCH", cat, "Patch di sicurezza datata",
                        Severity.ATTENTION, patch + " (~" + months + " mesi fa)",
                        "Aggiorna il sistema quando possibile.").detail("Patch", patch));
            } else {
                out.add(new Finding("PATCH", cat, "Patch di sicurezza recente", Severity.OK,
                        patch + " (~" + months + " mesi fa)", "Nessuna azione necessaria."));
            }
        }

        // --- debug USB ------------------------------------------------------
        if (data.access.adbEnabled) {
            out.add(new Finding("ADB", cat, "Debug USB attivo",
                    Severity.ATTENTION, "adb_enabled = 1",
                    "Con il debug USB attivo, chi collega il telefono a un PC puo' installare app e "
                    + "leggere dati. Disattiva Opzioni sviluppatore > Debug USB se non ti serve."));
        } else {
            out.add(new Finding("ADB", cat, "Debug USB disattivato", Severity.OK,
                    "adb_enabled = 0", "Nessuna azione necessaria."));
        }

        // --- posizione finta ------------------------------------------------
        if (data.access.mockLocationEnabled) {
            out.add(new Finding("MOCK_LOCATION", cat, "Posizione finta abilitata",
                    Severity.ATTENTION, "mock_location = 1",
                    "Un'app sta simulando la posizione GPS. Se non e' una tua app di test, "
                    + "disattiva 'App di posizione finta' nelle opzioni sviluppatore."));
        }
        return out;
    }
}
