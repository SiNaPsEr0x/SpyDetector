package it.spydetector.app.checks;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.InstalledApps;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Messaggistica: rileva i <b>client modificati</b> di WhatsApp/Telegram (GB
 * WhatsApp, WhatsApp Plus, YoWA, Telegram X non ufficiali) e verifica la firma
 * del pacchetto ufficiale.
 *
 * Un client clonato ha accesso in chiaro a tutte le chat e le inoltra a server
 * di terzi: e' il modo piu' comune con cui "qualcuno vede i tuoi messaggi".
 * Le sessioni "dispositivi collegati" (WhatsApp Web/Desktop) sono lato server e
 * non sono leggibili da un'app: il report spiega come verificarle a mano.
 */
public class MessagingCheck implements Check {

    private static final Map<String, String> CLONED = new HashMap<>();
    static {
        CLONED.put("com.gbwhatsapp", "GB WhatsApp");
        CLONED.put("com.gbwhatsapp3", "GB WhatsApp");
        CLONED.put("com.whatsapp.gb", "GB WhatsApp");
        CLONED.put("com.yowhatsapp", "YoWhatsApp");
        CLONED.put("com.fmwhatsapp", "FM WhatsApp");
        CLONED.put("com.whatsapp.plus", "WhatsApp Plus");
        CLONED.put("com.ogwhatsapp", "OGWhatsApp");
        CLONED.put("com.whatsapp.w4b.mod", "WhatsApp Business mod");
        CLONED.put("org.telegram.plus", "Telegram Plus");
        CLONED.put("org.telegram.messenger.web", "Telegram non ufficiale");
        CLONED.put("com.whatsapp.unofficial", "WhatsApp non ufficiale");
        CLONED.put("com.hide.chat.whatsapp", "WhatsApp nascosto");
    }

    @Override public String id() { return "MESSAGING"; }
    @Override public String category() { return "Messaggistica"; }
    @Override public String label() { return "WhatsApp/Telegram: client e sessioni"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        boolean foundClone = false;

        // --- 1. client clonati / modificati -------------------------------
        for (InstalledApps.App app : data.apps.all()) {
            String name = CLONED.get(app.pkg);
            if (name == null) {
                String l = app.pkg.toLowerCase();
                if (l.contains("whatsapp") && !app.pkg.equals("com.whatsapp")
                        && !app.pkg.equals("com.whatsapp.w4b")) {
                    name = "Client WhatsApp non ufficiale";
                } else if (l.contains("telegram") && !app.pkg.equals("org.telegram.messenger")
                        && !app.pkg.equals("org.telegram.messenger.web")
                        && !app.pkg.equals("org.thunderdog.challegram")) {
                    name = "Client Telegram non ufficiale";
                }
            }
            if (name == null) continue;
            foundClone = true;
            out.add(new Finding("MSG_CLONE", cat, "Client di messaggistica modificato: " + name,
                    Severity.CRITICAL,
                    app.pkg + " non e' il client ufficiale. I cloni (GB WhatsApp, Plus, YoWA, FM) "
                    + "hanno accesso in chiaro alle chat e possono inoltrarle a server di terzi, "
                    + "oltre a farti perdere la cifratura end-to-end.",
                    "Disinstalla, reinstalla WhatsApp dal Play Store e ripristina un backup locale. "
                    + "I cloni violano i termini di servizio e possono portare al ban dell'account.")
                    .detail("Pacchetto", app.pkg)
                    .detail("Firma", signature(data, app.pkg)));
        }
        if (!foundClone) {
            out.add(new Finding("MSG_CLONE_NONE", cat, "Nessun client WhatsApp/Telegram modificato",
                    Severity.OK, "Presenti solo pacchetti ufficiali.", "Nessuna azione necessaria."));
        }

        // --- 2. verifica firma del pacchetto ufficiale --------------------
        InstalledApps.App wa = data.apps.get("com.whatsapp");
        if (wa != null) {
            String sig = signature(data, "com.whatsapp");
            String knownOfficial = signatureSha(data, "com.whatsapp");
            out.add(new Finding("MSG_WA_SIG", cat, "WhatsApp ufficiale installato",
                    Severity.INFO,
                    "Pacchetto com.whatsapp, versione " + (wa.versionName.isEmpty() ? "n/d" : wa.versionName)
                    + ", firma " + (knownOfficial.isEmpty() ? "non leggibile" : knownOfficial),
                    "Verifica tu che la firma SHA-256 corrisponda a quella pubblicata da WhatsApp "
                    + "sul Play Store. Una firma diversa indica un APK rifirmato da terzi."));
        }

        // --- 3. istruzioni verifica sessioni remote -----------------------
        out.add(new Finding("MSG_LINKED", cat, "Dispositivi collegati: verifica manuale (30 secondi)",
                Severity.INFO,
                "Le sessioni WhatsApp Web/Desktop e gli accessi remoti sono registrati lato server: "
                + "nessuna app puo' leggerli dal telefono. Puoi pero' vederli e revocarli tu.",
                "WhatsApp: Impostazioni > Dispositivi collegati. Se vedi un computer che non "
                + "riconosci, toccalo e scegli 'Disconnetti' (e attiva la verifica in due passaggi).\n"
                + "Telegram: Impostazioni > Dispositivi > Termina tutte le altre sessioni.\n"
                + "Google: myaccount.google.com > Sicurezza > Dispositivi.\n"
                + "Se temi un accesso remoto al telefono (non a un account), guarda i servizi di "
                + "accessibilita' e i permessi in questo report."));
        return out;
    }

    private static String signature(ScanData data, String pkg) {
        try {
            PackageManager pm = data.ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
            Signature[] s = pi.signatures;
            if (s == null || s.length == 0) return "";
            byte[] raw = s[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(raw);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02X:", d[i]));
            return sb.substring(0, sb.length() - 1) + "…";
        } catch (Throwable t) {
            return "";
        }
    }

    private static String signatureSha(ScanData data, String pkg) {
        try {
            PackageManager pm = data.ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
            Signature[] s = pi.signatures;
            if (s == null || s.length == 0) return "";
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return "SHA-256 " + sb;
        } catch (Throwable t) {
            return "";
        }
    }
}
