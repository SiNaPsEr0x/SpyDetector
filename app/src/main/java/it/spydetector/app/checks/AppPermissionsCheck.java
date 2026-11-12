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
import java.util.Map;
import java.util.Set;

/**
 * Analizza i permessi realmente dichiarati dalle app installate e segnala le
 * combinazioni che, insieme, valgono un tool di sorveglianza:
 * SMS + microfono + posizione (o + fotocamera).
 */
public class AppPermissionsCheck implements Check {

    /** App legittime che chiedono microfono + posizione ecc. (non segnalate). */
    private static final Set<String> COMMS = new HashSet<>(Arrays.asList(
            "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "com.facebook.orca",
            "com.instagram.android", "com.snapchat.android", "com.google.android.apps.messaging",
            "com.discord", "com.skype.raider", "com.viber.voip", "com.microsoft.teams",
            "us.zoom.videomeetings", "com.google.android.talk", "jp.naver.line.android"
    ));

    @Override public String id() { return "APP_PERMS"; }
    @Override public String category() { return "Applicazioni"; }
    @Override public String label() { return "Permessi pericolosi delle app"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        Map<String, String> risky = ThreatDb.riskyPermissions();
        int flagged = 0;

        for (InstalledApps.App app : data.apps.user()) {
            if (app.pkg.equals(data.ctx.getPackageName())) continue;

            // App con firma ufficiale verificata: i permessi sono quelli
            // normali dell'app ufficiale, non e' un warning.
            if (ThreatDb.isOfficialSignature(data.ctx, app.pkg)) continue;

            Set<String> has = new HashSet<>(Arrays.asList(app.requested));

            boolean sms = has.contains("android.permission.READ_SMS")
                    || has.contains("android.permission.RECEIVE_SMS");
            boolean mic = has.contains("android.permission.RECORD_AUDIO");
            boolean loc = has.contains("android.permission.ACCESS_FINE_LOCATION");
            boolean cam = has.contains("android.permission.CAMERA");
            boolean callLog = has.contains("android.permission.READ_CALL_LOG");
            boolean accessibility = has.contains("android.permission.BIND_ACCESSIBILITY_SERVICE");
            boolean notif = has.contains("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE");

            boolean comboSpy = sms && mic && (loc || cam);
            boolean comboDeep = (sms || callLog) && mic && loc && cam;
            boolean hasAccessService = accessibility || notif;

            if (hasAccessService && !COMMS.contains(app.pkg)) {
                flagged++;
                out.add(new Finding("PERM_ACCESS_SVC", cat,
                        "Dichiara un servizio di controllo del sistema: " + app.label,
                        Severity.CRITICAL,
                        app.pkg + " contiene un " + (accessibility ? "servizio di accessibilita'"
                                : "listener di notifiche") + ", cioe' la capacita' di leggere/guidare "
                                + "l'intera interfaccia del telefono.",
                        "Se non e' un'app di accessibilita' o un tool remoto che usi consapevolmente, "
                        + "disinstallala.").detail("Pacchetto", app.pkg));
            }

            if (comboDeep) {
                flagged++;
                out.add(new Finding("PERM_COMBO", cat,
                        "Combinazione da spyware: " + app.label,
                        Severity.CRITICAL,
                        app.pkg + " chiede SMS + registro chiamate + microfono + posizione + fotocamera.",
                        "Nessuna app normale ha bisogno di tutto questo insieme. Disinstalla e "
                        + "controlla accessibilita' e notifiche.").detail("Pacchetto", app.pkg));
            } else if (comboSpy && !COMMS.contains(app.pkg)) {
                flagged++;
                out.add(new Finding("PERM_COMBO2", cat,
                        "Permessi da sorveglianza: " + app.label,
                        Severity.WARNING,
                        app.pkg + " puo' leggere SMS, ascoltare il microfono e "
                        + (loc ? "seguire la posizione" : "usare la fotocamera") + ".",
                        "Verifica che sia davvero necessaria: in caso contrario limita i permessi da "
                        + "Impostazioni > App > Permessi.").detail("Pacchetto", app.pkg));
            } else if (sms && !COMMS.contains(app.pkg) && ThreatDb.find(app.pkg) == null) {
                out.add(new Finding("PERM_SMS", cat,
                        "App non di messaggistica con accesso agli SMS: " + app.label,
                        Severity.ATTENTION,
                        app.pkg + " puo' leggere gli SMS (incluse notifiche bancarie e codici OTP).",
                        "Revoca il permesso SMS da Impostazioni > App > Permessi > SMS, "
                        + "a meno che non sia la tua app di messaggi.").detail("Pacchetto", app.pkg));
            }

            // app che hanno UN solo permesso molto invasivo: informazione
            List<String> single = new ArrayList<>();
            for (String p : app.requested) {
                String d = risky.get(p);
                if (d != null && (p.endsWith("RECORD_AUDIO") || p.endsWith("SYSTEM_ALERT_WINDOW"))) {
                    single.add(d);
                }
            }
            int target;
            try { target = Integer.parseInt(app.targetSdk); } catch (Throwable t) { target = 28; }
            if (single.size() == 1 && !comboSpy && target < 29) {
                out.add(new Finding("PERM_OLD_TARGET", cat,
                        "App non aggiornata (target SDK vecchio): " + app.label,
                        Severity.INFO,
                        app.pkg + " ha targetSdk " + app.targetSdk + ": Android applica meno "
                        + "restrizioni ai suoi permessi.",
                        "Aggiorna o sostituisci l'app.").detail("Pacchetto", app.pkg));
            }
        }

        if (flagged == 0) {
            out.add(new Finding("PERM_NONE", cat, "Nessuna app con combinazioni da spyware",
                    Severity.OK, "Nessuna app utente combina permessi tipici dei tool di sorveglianza.",
                    "Nessuna azione necessaria."));
        }
        return out;
    }
}
