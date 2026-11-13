package it.spydetector.app.checks;


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
import java.util.Set;

/**
 * App installate fuori dal Play Store o senza certificato riconoscibile:
 * e' cosi' che si installa lo stalkerware quando si ha accesso fisico al
 * telefono. Evidenzia quelle con nome "camuffato" o senza icona.
 */
public class UnknownSideloadCheck implements Check {

    private static final Set<String> STORE_INSTALLERS = new HashSet<>(Arrays.asList(
            "com.android.vending", "com.google.android.packageinstaller",
            "com.android.packageinstaller", "com.samsung.android.galaxyapps",
            "com.huawei.appmarket", "com.xiaomi.mipicks", "com.amazon.venezia",
            "com.oppo.market", "com.heytap.market", "com.vivo.appstore"
    ));

    private static final String[] SUSPICIOUS_WORDS = {
            "spy", "track", "monitor", "keylog", "watch", "remote", "hidden", "stealth",
            "invisible", "secret", "silent", "sorge", "system", "service", "helper", "update"
    };

    @Override public String id() { return "SIDELOAD"; }
    @Override public String category() { return "Applicazioni"; }
    @Override public String label() { return "App installate fuori dallo store"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        List<String> sideloaded = new ArrayList<>();

        for (InstalledApps.App app : data.apps.user()) {
            boolean fromStore = STORE_INSTALLERS.contains(app.installer);
            if (fromStore) continue;
            if (app.pkg.equals(data.ctx.getPackageName())) continue;

            // App con firma ufficiale verificata: e' genuina anche se sideloaded
            if (ThreatDb.isOfficialSignature(data.ctx, app.pkg)) continue;

            String p = app.pkg.toLowerCase();
            String l = app.label.toLowerCase();
            boolean shady = false;
            for (String w : SUSPICIOUS_WORDS) {
                if (p.contains(w) || l.contains(w)) { shady = true; break; }
            }
            sideloaded.add(app.label);

            if (shady) {
                out.add(new Finding("SIDELOAD_SUSPECT", cat,
                        "App installata a mano con nome sospetto: " + app.label,
                        Severity.WARNING,
                        app.pkg + " non proviene da uno store e il nome contiene termini tipici "
                        + "di tool di monitoraggio.",
                        "Se non ricordi di aver installato questa app, disinstallala adesso. "
                        + "Le app di sorveglianza vengono installate a mano in pochi minuti.")
                        .detail("Pacchetto", app.pkg)
                        .detail("Installer", app.installer.isEmpty() ? "sconosciuto" : app.installer)
                        .detail("Pericolosi", perms(app)));
            }
        }

        if (sideloaded.isEmpty()) {
            out.add(new Finding("SIDELOAD_NONE", cat, "Nessuna app fuori dallo store",
                    Severity.OK, "Tutte le app utente risultano installate da uno store ufficiale.",
                    "Nessuna azione necessaria."));
        } else {
            out.add(new Finding("SIDELOAD_SUMMARY", cat,
                    sideloaded.size() + " app installate al di fuori degli store",
                    sideloaded.size() > 3 ? Severity.ATTENTION : Severity.INFO,
                    join(sideloaded),
                    "Le app installate da APK possono essere legittime (beta, app aziendali). "
                    + "Controlla solo di riconoscerle tutte."));
        }
        return out;
    }

    private static String perms(InstalledApps.App app) {
        List<String> found = new ArrayList<>();
        for (String p : app.requested) {
            String desc = it.spydetector.app.core.ThreatDb.riskyPermissions().get(p);
            if (desc != null) found.add(desc);
        }
        return found.isEmpty() ? "nessuno" : join(found);
    }

    private static String join(List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) sb.append(" • ");
            sb.append(l.get(i));
        }
        return sb.toString();
    }
}
