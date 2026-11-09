package it.spydetector.app.checks;

import it.spydetector.app.core.AccessState;
import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.InstalledApps;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;
import it.spydetector.app.core.ThreatDb;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Il vettore d'attacco numero uno su Android: i servizi di accessibilita'.
 * Un'app con accessibilita' attiva puo' leggere TUTTO quello che appare sullo
 * schermo (incluse le chat di WhatsApp) e simulare i tocchi al posto tuo.
 *
 * Regola applicata: per ogni app con accessibilita' attiva si controlla se e'
 * nel database locale dei kit di sorveglianza, se e' un'app che normalmente non
 * ne ha bisogno (downloader, torce, giochi...) o se non ha nemmeno un'icona
 * lanciabile (tipico dei payload nascosti).
 */
public class AccessibilityCheck implements Check {

    /** Categorie di app per cui l'accessibilita' ha senso. */
    private static final String[] LEGIT = {
            "talkback", "samsung.accessibility", "switchaccess", "voiceaccess",
            "accessibilitysuite", "com.google.android.marvin", "com.android.", "com.samsung.android.",
            "com.google.android.inputmethod", "com.microsoft.appmanager", "com.teamviewer",
            "com.anydesk", "com.paresh.droidbots", "com.google.android.apps.accessibility"
    };

    @Override public String id() { return "ACCESSIBILITY"; }
    @Override public String category() { return "Sorveglianza"; }
    @Override public String label() { return "Servizi di accessibilita' attivi"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        Set<String> accPkgs = data.access.accessibilityPackages();

        if (!data.access.servicesReadable && accPkgs.isEmpty()) {
            out.add(new Finding("ACC_READ", cat, "Stato accessibilita' non leggibile",
                    Severity.INFO,
                    "Il sistema (Android 9+) non espone l'elenco dei servizi attivi a questa app.",
                    "Controlla manualmente: Impostazioni > Accessibilita' > Servizi scaricati. "
                    + "Deve esserci SOLO quello che hai attivato tu."));
        }

        if (accPkgs.isEmpty()) {
            out.add(new Finding("ACC_NONE", cat, "Nessun servizio di accessibilita' attivo",
                    Severity.OK, "Nessuna app puo' leggere lo schermo tramite accessibilita'.",
                    "Nessuna azione necessaria."));
        } else {
            Map<String, String> comps = AccessState.byPackage(data.access.accessibilityComponents);
            for (String pkg : accPkgs) {
                InstalledApps.App app = data.apps.get(pkg);
                if (pkg.equals(data.ctx.getPackageName())) continue;
                ThreatDb.Known known = ThreatDb.find(pkg);
                String label = app != null ? app.label : pkg;
                String detail = app != null
                        ? "App: " + label + " (" + pkg + ")\nComponente: " + comps.get(pkg)
                        : "Componente: " + comps.get(pkg);

                if (known != null) {
                    out.add(new Finding("ACC_KNOWN", cat,
                            "ACCESSIBILITA' ATTIVA SU STALKERWARE: " + known.name,
                            Severity.CRITICAL,
                            "Il kit di sorveglianza '" + known.name + "' (" + known.kind + ") ha il "
                            + "servizio di accessibilita' attivo: puo' leggere ogni schermo e simulare tocchi.",
                            "Disattiva subito: Impostazioni > Accessibilita' > " + known.name + " > Off. "
                            + "Poi disinstalla l'app e cambia le password degli account principali.")
                            .detail("Pacchetto", pkg)
                            .detail("Componente", String.valueOf(comps.get(pkg))));
                } else if (isLegit(pkg) || (app != null && isKnownSystemAcc(pkg))) {
                    out.add(new Finding("ACC_LEGIT", cat, "Accessibilita' su app con funzione dichiarata",
                            Severity.INFO, detail,
                            "Sembra un'app di accessibilita' o un tool remoto che hai installato tu. "
                            + "Verifica solo che sia davvero quella che intendevi."));
                } else if (ThreatDb.isAccessibilityAbuser(pkg) || isUnexpected(pkg)) {
                    out.add(new Finding("ACC_SUSPECT", cat,
                            "Accessibilita' attiva su app che non dovrebbe averla",
                            Severity.CRITICAL, detail,
                            "App come questa non ha alcun motivo di leggere lo schermo: e' una delle "
                            + "tecniche piu' usate per rubare chat (WhatsApp inclusa), OTP e password. "
                            + "Disattiva l'accessibilita' e disinstalla l'app.")
                            .detail("Pacchetto", pkg));
                } else {
                    out.add(new Finding("ACC_PRESENT", cat, "Accessibilita' attiva: " + label,
                            Severity.WARNING, detail,
                            "Un'app con accessibilita' puo' leggere tutto quello che compare sullo "
                            + "schermo. Se non riconosci " + label + " o non ricordi di averla attivata, "
                            + "disattivala e disinstallala.")
                            .detail("Pacchetto", pkg));
                }

                // Combinazione letale: accessibilita' + lettura notifiche
                if (data.access.notificationPackages().contains(pkg)) {
                    out.add(new Finding("ACC_NOTIF_COMBO", cat,
                            "Combinazione pericolosa: accessibilita' + lettura notifiche",
                            Severity.CRITICAL, label + " ha ENTRAMBI i permessi piu' potenti di Android.",
                            "Questa combinazione permette di leggere notifiche (anteprime di WhatsApp, "
                            + "SMS con OTP) E controllare lo schermo. Rimuovi immediatamente l'app.")
                            .detail("Pacchetto", pkg));
                }
            }
        }

        // --- contatori: quante app possono leggere lo schermo -------------
        int n = accPkgs.size();
        if (n > 3) {
            out.add(new Finding("ACC_MANY", cat, "Molti servizi di accessibilita' contemporanei",
                    Severity.ATTENTION, n + " servizi attivi.",
                    "Oltre 3 servizi attivi e' anomalo su un telefono domestico: rivedi l'elenco."));
        }
        return out;
    }

    private static boolean isLegit(String pkg) {
        for (String s : LEGIT) if (pkg.toLowerCase().contains(s)) return true;
        return false;
    }

    private static boolean isKnownSystemAcc(String pkg) {
        return pkg.startsWith("com.android.") || pkg.startsWith("com.google.android.")
                || pkg.startsWith("com.samsung.android.") || pkg.startsWith("com.miui.")
                || pkg.startsWith("com.oneplus.") || pkg.startsWith("com.oppo.")
                || pkg.startsWith("com.vivo.") || pkg.startsWith("com.transsion.");
    }

    /** App con nomi/categorie tipiche di camuffamento. */
    private static final Set<String> CAMOUFLAGE = new HashSet<>(Arrays.asList(
            "torch", "flashlight", "calculator", "calcolatrice", "torcia", "battery", "cleaner",
            "compass", "bussola", "radio", "weather", "meteo", "notes", "wallpaper"));

    private static boolean isUnexpected(String pkg) {
        String p = pkg.toLowerCase();
        for (String s : CAMOUFLAGE) if (p.contains(s)) return true;
        // nomi con suffisso "service/system" tipici dei payload
        return p.endsWith(".service") || p.endsWith(".system") || p.contains("sysapp")
                || p.contains("update.service") || p.contains("com.sys.");
    }
}
