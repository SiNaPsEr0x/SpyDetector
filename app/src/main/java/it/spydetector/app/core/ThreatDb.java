package it.spydetector.app.core;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Piccolo database locale di app note: kit spyware commerciali, stalkerware e
 * app che nella pratica abusano di permessi di accessibilita' / lettura notifiche.
 *
 * Oltre alle voci esatte (pkg), contiene PATTERN PUBBLICI di spyware
 * (nomi di famiglie nel pacchetto, hash di firme, nomi di componenti) che
 * catturano le varianti rinominate e il repackaging.
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
        // Le voci vivono in ThreatDbGenerated.java, rigenerato ogni giorno da
        // scripts/update-threat-db.py a partire da data/threat-seed.txt.
        for (String row : ThreatDbGenerated.ENTRIES) {
            String[] p = row.split("\\|");
            if (p.length != 4) continue;
            Severity sev;
            try {
                sev = Severity.valueOf(p[3]);
            } catch (IllegalArgumentException e) {
                sev = Severity.CRITICAL;
            }
            k(p[0], p[1], p[2], sev);
        }
    }

    /**
     * Pattern pubblico di spyware. tipo: "PKG" (sottostringo del pacchetto),
     * "CERT" (SHA-256 del certificato), "COMP" (sottostringo del nome componente).
     */
    public static final class Pattern {
        public final String type;
        public final String value;
        public final String name;
        public final String kind;
        public final Severity severity;

        Pattern(String type, String value, String name, String kind, Severity severity) {
            this.type = type;
            this.value = value;
            this.name = name;
            this.kind = kind;
            this.severity = severity;
        }
    }

    private static final List<Pattern> PATTERNS = new ArrayList<>();

    static {
        // Le voci vivono in ThreatDbGenerated.java, rigenerato ogni giorno da
        // scripts/update-threat-db.py a partire da data/threat-patterns.txt.
        for (String row : ThreatDbGenerated.PATTERNS) {
            String[] p = row.split("\\|");
            if (p.length != 5) continue;
            Severity sev;
            try {
                sev = Severity.valueOf(p[4]);
            } catch (IllegalArgumentException e) {
                sev = Severity.WARNING;
            }
            PATTERNS.add(new Pattern(p[0].trim().toUpperCase(Locale.ROOT),
                    p[1].trim().toLowerCase(Locale.ROOT),
                    p[2].trim(), p[3].trim(), sev));
        }
        // Piu' specifici prima: CRITICAL davanti a WARNING e valore piu' lungo
        // davanti a piu' corto (cosi' "mspy" scatta prima di "spy").
        PATTERNS.sort(new Comparator<Pattern>() {
            @Override public int compare(Pattern a, Pattern b) {
                if (a.severity != b.severity)
                    return a.severity.ordinal() > b.severity.ordinal() ? -1 : 1;
                return b.value.length() - a.value.length();
            }
        });
    }

    public static Known find(String pkg) {
        for (Known x : KNOWN) if (x.pkg.equals(pkg)) return x;
        return null;
    }

    /** Pattern PKG che corrisponde al nome del pacchetto (substring, case-insensitive). */
    public static Pattern matchPkgPattern(String pkg) {
        String s = pkg.toLowerCase(Locale.ROOT);
        for (Pattern p : PATTERNS) {
            if (p.type.equals("PKG") && s.contains(p.value)) return p;
        }
        return null;
    }

    /** Pattern COMP che corrisponde al nome di un componente (substring, case-insensitive). */
    public static Pattern matchComponentPattern(String component) {
        String s = component.toLowerCase(Locale.ROOT);
        for (Pattern p : PATTERNS) {
            if (p.type.equals("COMP") && s.contains(p.value)) return p;
        }
        return null;
    }

    /** Pattern CERT che corrisponde all'hash SHA-256 della firma (exact, case-insensitive). */
    public static Pattern matchCert(String sha256) {
        String s = sha256.trim().toLowerCase(Locale.ROOT);
        for (Pattern p : PATTERNS) {
            if (p.type.equals("CERT") && p.value.equals(s)) return p;
        }
        return null;
    }

    /**
     * Firme ufficiali di app popolari: pacchetto -> SHA-256 del certificato
     * di firma ufficiale. Se un'app installata ha una firma che corrisponde,
     * e' l'app genuina e non deve essere segnalata come warning.
     *
     * Le firme sono pubbliche e stabili: un'app che cambia il certificato
     * di firma (raro) apparirebbe come "firma non ufficiale" finche' non
     * si aggiorna questa tabella. Le firme vengono verificate da APKMirror
     * e fonti ufficiali.
     *
     * Questa tabella viene anche scaricata aggiornata da GitHub (vedi
     * UpdateChecker): il database remoto puo' aggiungere firme nuove.
     */
    private static final Map<String, String> OFFICIAL_SIGNATURES = new HashMap<>();
    static {
        // WhatsApp — certificato ufficiale (CN=Brian Acton, O=WhatsApp Inc.)
        // Verificato su APKMirror per versioni 2.18.71 - 2.25.33.71 (2018-2025).
        OFFICIAL_SIGNATURES.put("com.whatsapp",
            "3987d043d10aefaf5a8710b3671418fe57e0e19b653c9df82558feb5ffce5d44");
        // WhatsApp Business — stesso certificato di WhatsApp
        OFFICIAL_SIGNATURES.put("com.whatsapp.w4b",
            "3987d043d10aefaf5a8710b3671418fe57e0e19b653c9df82558feb5ffce5d44");
        // Instagram — certificato ufficiale (CN=Kevin Systrom, O=Instagram Inc.)
        // Verificato su APKMirror / privacyguides/verified-apps.
        OFFICIAL_SIGNATURES.put("com.instagram.android",
            "5f3e50f435583c9ae626302a71f7340044087a7e2c60adacfc254205a993e305");
        OFFICIAL_SIGNATURES.put("com.instagram.lite",
            "5f3e50f435583c9ae626302a71f7340044087a7e2c60adacfc254205a993e305");
        // Telegram — certificato ufficiale (Telegram FZ-LLC)
        // Verificato su APKPure/APKMirror.
        OFFICIAL_SIGNATURES.put("org.telegram.messenger",
            "637cea357d17e2d025431602d9b980a6d7631830a9d1923ab6806bf8dcc300e5");
        OFFICIAL_SIGNATURES.put("org.telegram.messenger.web",
            "637cea357d17e2d025431602d9b980a6d7631830a9d1923ab6806bf8dcc300e5");
        OFFICIAL_SIGNATURES.put("org.thunderdog.challegram",
            "637cea357d17e2d025431602d9b980a6d7631830a9d1923ab6806bf8dcc300e5");
        // Snapchat — certificato ufficiale (CN=Daniel Smith, Snap Inc.)
        // Verificato su APKMirror.
        OFFICIAL_SIGNATURES.put("com.snapchat.android",
            "2f1caafca1ed30d0b4e38863eefabea0e815711fa4cf79b822519a8259d95a58");
    }

    /** True se la firma dell'app corrisponde a quella ufficiale nota. */
    public static boolean isOfficialSignature(Context ctx, String pkg) {
        String official = OFFICIAL_SIGNATURES.get(pkg);
        if (official == null || official.isEmpty()) return false;
        String actual = certSha256(ctx, pkg);
        return !actual.isEmpty() && actual.equalsIgnoreCase(official);
    }

    /** La firma ufficiale nota per un pacchetto, o "" se nessuna. */
    public static String officialSignature(String pkg) {
        return OFFICIAL_SIGNATURES.getOrDefault(pkg, "");
    }

    /** Aggiunge firme ufficiali da un database remoto (formato: pkg=hash). */
    public static void addOfficialSignature(String pkg, String sha256) {
        if (pkg != null && sha256 != null && !pkg.isEmpty()
                && sha256.matches("[0-9a-fA-F]{64}")) {
            OFFICIAL_SIGNATURES.put(pkg.trim(), sha256.trim().toLowerCase(Locale.ROOT));
        }
    }

    /**
     * SHA-256 del primo certificato di firma dell'app, o "" se non leggibile.
     * Si usa GET_SIGNING_CERTIFICATES su API 28+, GET_SIGNATURES sulle versioni
     * precedenti. Niente permesso extra serve: le firme sono leggibili da qualsiasi
     * appinstallata.
     */
    public static String certSha256(Context ctx, String pkg) {
        try {
            PackageManager pm = ctx.getPackageManager();
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                sigs = pi.signingInfo == null
                        ? null : pi.signingInfo.getApkContentsSigners();
            } else {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }
            if (sigs == null || sigs.length == 0) return "";
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(sigs[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format(Locale.ROOT, "%02x", b));
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
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
