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
 * Come un'app resta nascosta e "viva" sul telefono:
 * - lettura delle notifiche (vede le anteprime di WhatsApp/SMS),
 * - amministratore del dispositivo (impedisce la disinstallazione),
 * - VPN sempre attiva (instrada il traffico),
 * - tastiera di terze parti (legge tutto cio' che digiti),
 * - app SMS predefinita (legge/scrive i tuoi SMS).
 */
public class PersistenceCheck implements Check {

    private static final Set<String> KNOWN_KEYBOARDS = new HashSet<>(Arrays.asList(
            "com.google.android.inputmethod.latin", "com.touchtype.swiftkey",
            "com.swype.android.inputmethod", "com.samsung.android.honeyboard",
            "com.baidu.input", "com.sohu.inputmethod.sogou", "com.microsoft.swiftkey",
            "org.futo.inputmethod.latin", "com.anysoftkeyboard.languagepack.italian",
            "com.anysoftkeyboard"
    ));

    private static final Set<String> KNOWN_SMS = new HashSet<>(Arrays.asList(
            "com.google.android.apps.messaging", "com.android.messaging",
            "com.samsung.android.messaging", "com.textra", "com.smsapp.dual",
            "com.miui.smsextra", "org.thoughtcrime.securesms"
    ));

    @Override public String id() { return "PERSISTENCE"; }
    @Override public String category() { return "Sorveglianza"; }
    @Override public String label() { return "Persistenza e canali di controllo"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();

        // --- lettura notifiche ---------------------------------------------
        Set<String> npkgs = data.access.notificationPackages();
        if (npkgs.isEmpty()) {
            out.add(new Finding("NOTIF_NONE", cat, "Nessuna app legge le tue notifiche",
                    Severity.OK, "Nessun Notification Listener attivo.",
                    "Nessuna azione necessaria."));
        }
        for (String pkg : npkgs) {
            if (pkg.equals(data.ctx.getPackageName())) continue;
            InstalledApps.App app = data.apps.get(pkg);
            String label = app != null ? app.label : pkg;
            ThreatDb.Known known = ThreatDb.find(pkg);
            boolean expected = pkg.startsWith("com.android.") || pkg.startsWith("com.google.android.")
                    || pkg.contains("smartwatch") || pkg.contains("wearable") || pkg.contains("miwear");
            if (known != null) {
                out.add(new Finding("NOTIF_KNOWN", cat,
                        "LETTURA NOTIFICHE SU STALKERWARE: " + known.name,
                        Severity.CRITICAL,
                        known.name + " legge ogni notifica, incluse le anteprime di WhatsApp e gli SMS con OTP.",
                        "Revoca subito l'accesso: Impostazioni > App > Accesso a notifiche > "
                        + known.name + " > Off, poi disinstalla l'app.")
                        .detail("Pacchetto", pkg));
            } else if (!expected) {
                out.add(new Finding("NOTIF_APP", cat,
                        "App con accesso alle notifiche: " + label,
                        Severity.WARNING,
                        pkg + " puo' leggere il contenuto delle notifiche di WhatsApp, email e SMS.",
                        "Se non serve (es. non e' il tuo smartwatch o un'app di gestione notifiche), "
                        + "revoca l'accesso da Impostazioni > App > Accesso a notifiche.")
                        .detail("Pacchetto", pkg));
            }
        }

        // --- amministratori del dispositivo ---------------------------------
        Set<String> admins = data.access.adminPackages();
        for (String pkg : admins) {
            InstalledApps.App app = data.apps.get(pkg);
            String label = app != null ? app.label : pkg;
            ThreatDb.Known known = ThreatDb.find(pkg);
            boolean expected = pkg.startsWith("com.android.") || pkg.contains("mdm")
                    || pkg.contains("findmydevice") || pkg.contains("devicepolicy")
                    || pkg.contains("google.android.gms");
            if (known != null) {
                out.add(new Finding("ADMIN_KNOWN", cat,
                        "ADMIN DEL DEVICE SU STALKERWARE: " + known.name,
                        Severity.CRITICAL,
                        known.name + " e' amministratore: puo' bloccarti lo schermo e impedire la disinstallazione.",
                        "Disattiva l'amministratore: Impostazioni > Sicurezza > App di amministrazione, "
                        + "poi disinstalla l'app.").detail("Pacchetto", pkg));
            } else if (!expected) {
                out.add(new Finding("ADMIN_APP", cat,
                        "App con privilegi di amministratore: " + label,
                        Severity.WARNING,
                        pkg + " puo' cancellare dati, bloccare lo schermo, impedire la disinstallazione.",
                        "Se e' un'app aziendale (MDM) o 'Trova il mio dispositivo' va bene. "
                        + "Altrimenti rimuovi i privilegi da Sicurezza > App di amministrazione.")
                        .detail("Pacchetto", pkg));
            }
        }

        // --- tastiere --------------------------------------------------------
        Set<String> imes = data.access.uniqueInputMethodPackages();
        for (String pkg : imes) {
            InstalledApps.App app = data.apps.get(pkg);
            String label = app != null ? app.label : pkg;
            if (!KNOWN_KEYBOARDS.contains(pkg)) {
                out.add(new Finding("IME", cat, "Tastiera di terze parti: " + label,
                        Severity.ATTENTION,
                        pkg + " puo' registrare tutto quello che digiti, password comprese.",
                        "Usa la tastiera predefinita del produttore o Gboard. Se non riconosci "
                        + "questa tastiera, cambiala subito da Impostazioni > Sistema > Tastiere.")
                        .detail("Pacchetto", pkg));
            }
        }

        // --- app SMS predefinita --------------------------------------------
        String sms = data.access.defaultSmsPackage;
        if (!sms.isEmpty() && !KNOWN_SMS.contains(sms)) {
            ThreatDb.Known known = ThreatDb.find(sms);
            out.add(new Finding("SMS_APP", cat,
                    known != null ? "APP SMS = STALKERWARE: " + known.name
                                  : "App SMS predefinita non standard: " + sms,
                    known != null ? Severity.CRITICAL : Severity.WARNING,
                    "Le app SMS predefinite leggono e inviano tutti i messaggi.",
                    known != null
                        ? "Torna subito a Messaggi di Google e disinstalla l'app: i tuoi SMS (incluse "
                          + "le notifiche bancarie e gli OTP) passano da li'."
                        : "Imposta come app SMS quella di sistema/Google da Impostazioni > App > App predefinite.")
                    .detail("Pacchetto", sms));
        }

        // --- VPN -------------------------------------------------------------
        if (!data.access.vpnPackage.isEmpty()) {
            out.add(new Finding("VPN_ALWAYS", cat, "VPN sempre attiva configurata",
                    Severity.ATTENTION, "always_on_vpn_app = " + data.access.vpnPackage,
                    "Tutto il traffico passa da questa app: se non l'hai configurata tu, e' un "
                    + "intercettatore. Controlla Impostazioni > Rete > VPN."));
        } else if (data.access.vpnActive) {
            out.add(new Finding("VPN_ACTIVE", cat, "VPN attiva in questo momento",
                    Severity.INFO, "Connessione VPN rilevata.",
                    "Se non e' la tua VPN (o un'app aziendale), verifica chi sta instradando il traffico."));
        }
        return out;
    }
}
