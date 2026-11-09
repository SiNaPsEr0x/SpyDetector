package it.spydetector.app.core;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Piccolo database locale di app note: kit spyware commerciali, stalkerware e
 * app che nella pratica abusano di permessi di accessibilita' / lettura notifiche.
 *
 * Le voci sono un sottoinsieme curato (non un elenco esaustivo) e vanno usate
 * come SEGNALAZIONE da verificare, non come prova legale. E' compito dei singoli
 * controlli confrontare i permessi effettivamente dichiarati sul dispositivo.
 */
public final class ThreatDb {

    private ThreatDb() {}

    public static final class Known {
        public final String pkg;
        public final String name;
        public final String kind;
        public final Severity severity;

        Known(String pkg, String name, String kind, Severity severity) {
            this.pkg = pkg;
            this.name = name;
            this.kind = kind;
            this.severity = severity;
        }
    }

    private static final List<Known> KNOWN = new ArrayList<>();

    private static void k(String pkg, String name, String kind, Severity sev) {
        KNOWN.add(new Known(pkg, name, kind, sev));
    }

    static {
        // --- stalkerware / monitoring commerciale ------------------------------
        k("com.mspy.monitor", "mSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.mspy.application", "mSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.flexispy.android", "FlexiSPY", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.flexispy.omega", "FlexiSPY Omega", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.cyberlink.gethalftone", "FlexiSPY (modulo)", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.kidlogger.android", "KidLogger", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.hoverwatch.android", "Hoverwatch", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.tracker.mobiletracker", "Highster Mobile", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.mobiletracker.android", "MobileTracker", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.spybubble.app", "SpyBubble", "Stalkerware commerciale", Severity.CRITICAL);
        k("net.spyapp.minispy", "MiniSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.thetruthspy.app", "TheTruthSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.spyera.app", "Spyera", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.cocospy.app", "Cocospy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.fonewatcher.app", "FoneWatcher", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.eyezy.monitor", "Eyezy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.hoverwatch.monitor", "Hoverwatch", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.letspy.app", "LetSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.spyzie.app", "Spyzie", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.wifispy.monitor", "WifiSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.mobilemonitor.android", "Mobile Monitor", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.locspy.app", "LocSpy", "Stalkerware / localizzazione", Severity.CRITICAL);
        k("com.gpsphonetracker.android", "GPS Phone Tracker", "Stalkerware / localizzazione", Severity.CRITICAL);
        k("com.famspy.family", "Famspy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.andromoney.spy", "AndroSpy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.bosspy.android", "Bosspy", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.ikeymonitor.app", "iKeyMonitor", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.pctattoolkit.app", "PCTattoolkit", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.timesheet.spy", "TimeSheet", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.spymaster.app", "SpyMaster", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.smsorganizer.spy", "SMS Tracker", "Stalkerware commerciale", Severity.CRITICAL);
        k("com.familykeylogger.app", "Family Keylogger", "Keylogger", Severity.CRITICAL);
        k("com.keystroke.logger", "Keylogger", "Keylogger", Severity.CRITICAL);
        k("com.accuchek.spy", "AccuSpy", "Stalkerware commerciale", Severity.CRITICAL);
    }

    public static Known find(String pkg) {
        for (Known x : KNOWN) if (x.pkg.equals(pkg)) return x;
        return null;
    }

    // --- crowdsourced: app "normali" che chiedono accessibilita' o lettura notifiche
    private static final Set<String> ACCESSIBILITY_ABUSERS = new HashSet<>(Arrays.asList(
            "com.downloader.max", "com.videodownloader.app", "com.spy.callrecorder",
            "com.callrecorder.spy", "com.hidden.camera.spy", "com.remote.screen.monitor"));

    public static boolean isAccessibilityAbuser(String pkg) {
        return ACCESSIBILITY_ABUSERS.contains(pkg);
    }

    /** Permessi che vedono contenuti altrui: se chiesti da app non di sistema sono sospetti. */
    private static final Map<String, String> RISKY_PERMISSIONS = new HashMap<>();
    static {
        RISKY_PERMISSIONS.put("android.permission.READ_SMS", "legge gli SMS");
        RISKY_PERMISSIONS.put("android.permission.RECEIVE_SMS", "intercetta gli SMS in arrivo");
        RISKY_PERMISSIONS.put("android.permission.RECORD_AUDIO", "registra il microfono");
        RISKY_PERMISSIONS.put("android.permission.CAMERA", "usa la fotocamera");
        RISKY_PERMISSIONS.put("android.permission.READ_CALL_LOG", "legge il registro chiamate");
        RISKY_PERMISSIONS.put("android.permission.ACCESS_FINE_LOCATION", "traccia la posizione precisa");
        RISKY_PERMISSIONS.put("android.permission.ACCESS_BACKGROUND_LOCATION", "traccia la posizione in background");
        RISKY_PERMISSIONS.put("android.permission.SYSTEM_ALERT_WINDOW", "disegna sopra altre app (overlay)");
        RISKY_PERMISSIONS.put("android.permission.READ_CONTACTS", "legge la rubrica");
        RISKY_PERMISSIONS.put("android.permission.READ_PHONE_STATE", "legge dati della SIM/telefono");
        RISKY_PERMISSIONS.put("android.permission.BIND_ACCESSIBILITY_SERVICE", "controlla l'interfaccia");
        RISKY_PERMISSIONS.put("android.permission.SEND_SMS", "invia SMS a tua insaputa");
        RISKY_PERMISSIONS.put("android.permission.READ_CALENDAR", "legge il calendario");
    }

    public static Map<String, String> riskyPermissions() {
        return Collections.unmodifiableMap(RISKY_PERMISSIONS);
    }

    /** Permessi che, combinati, indicano quasi sempre un tool di sorveglianza. */
    public static final String[] SPYWARE_COMBO = {
            "android.permission.RECEIVE_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION"
    };

    public static PackageInfo info(Context ctx, String pkg) {
        try {
            return ctx.getPackageManager().getPackageInfo(pkg, PackageManager.GET_PERMISSIONS);
        } catch (Exception e) {
            return null;
        }
    }
}
