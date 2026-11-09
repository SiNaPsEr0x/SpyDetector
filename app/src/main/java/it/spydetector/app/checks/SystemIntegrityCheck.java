package it.spydetector.app.checks;

import android.os.Build;

import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;
import it.spydetector.app.util.Sys;

import java.util.ArrayList;
import java.util.List;

/**
 * Integrita' del sistema: root, bootloader sbloccato, Verified Boot,
 * SELinux, build "test-keys" e residui di Magisk/KernelSU.
 */
public class SystemIntegrityCheck implements Check {

    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/system/xbin/busybox",
            "/system/app/Superuser.apk", "/data/adb/magisk", "/data/adb/modules",
            "/sbin/.magisk", "/debug_ramdisk/su"
    };

    @Override public String id() { return "SYS_INTEGRITY"; }
    @Override public String category() { return "Sistema"; }
    @Override public String label() { return "Integrita' di sistema / root"; }

    @Override public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();

        // --- binari su / root ---------------------------------------------
        List<String> found = new ArrayList<>();
        for (String p : SU_PATHS) if (Sys.exists(p)) found.add(p);
        boolean suBinary = false;
        for (String p : new String[]{"/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su"}) {
            if (Sys.canRead(p)) suBinary = true;
        }
        if (!found.isEmpty() || suBinary) {
            out.add(new Finding("ROOT", cat, "Dispositivo potenzialmente rooted",
                    Severity.WARNING,
                    "Trovati " + found.size() + " indicatori: " + join(found),
                    "Un device rooted permette a qualsiasi app con permessi di root di leggere "
                    + "messaggi, foto e tastiera di tutte le altre app. Se non sei tu ad aver fatto "
                    + "il root, questo e' un forte segnale di compromissione: valuta un reset ai dati "
                    + "di fabbrica e non usare home banking da questo telefono.")
                    .detail("Indicatori", join(found)));
        } else {
            out.add(new Finding("ROOT", cat, "Nessun binario root standard",
                    Severity.OK, "Non risultano su/busybox/Magisk nei percorsi noti.",
                    "Nessuna azione necessaria."));
        }

        // --- build tags / test-keys --------------------------------------
        String tags = Build.TAGS == null ? "" : Build.TAGS;
        if (tags.contains("test-keys")) {
            out.add(new Finding("BUILD_TAGS", cat, "Firma di build non ufficiale (test-keys)",
                    Severity.WARNING, "Build.TAGS = " + tags,
                    "La ROM non e' firmata con le chiavi del produttore: potrebbe essere una "
                    + "custom ROM. Verifica di averla installata tu."));
        }

        // --- bootloader ---------------------------------------------------
        String boot = Build.BOOTLOADER == null ? "" : Build.BOOTLOADER.toLowerCase();
        String verifiedBoot = "";
        try {
            verifiedBoot = Sys.firstLine("/proc/cmdline");
        } catch (Throwable ignored) {}
        boolean vbOrange = verifiedBoot.contains("androidboot.verifiedbootstate=orange")
                || verifiedBoot.contains("verifiedbootstate=orange");
        if (vbOrange) {
            out.add(new Finding("VERIFIED_BOOT", cat, "Verified Boot disattivato (stato arancione)",
                    Severity.WARNING, "androidboot.verifiedbootstate=orange",
                    "Il sistema operativo non e' piu' quello originale verificato dal produttore. "
                    + "Su un telefono che non hai modificato tu, e' un segnale grave di manomissione."));
        }
        if (!boot.isEmpty() && (boot.contains("unlock") || boot.contains("unknown"))) {
            out.add(new Finding("BOOTLOADER", cat, "Bootloader sbloccato o sconosciuto",
                    Severity.ATTENTION, "Build.BOOTLOADER = " + Build.BOOTLOADER,
                    "Con bootloader sbloccato chiunque abbia il telefono in mano puo' installare "
                    + "un sistema modificato. Se non l'hai fatto tu, fai controllare il device."));
        }

        // --- SELinux -------------------------------------------------------
        String selinux = readSelinux();
        if (selinux.contains("Permissive")) {
            out.add(new Finding("SELINUX", cat, "SELinux in modalita' Permissive",
                    Severity.WARNING, "getenforce = Permissive",
                    "Le protezioni del kernel sono disattivate: tipico di ROM modificate o exploit "
                    + "kernel applicati. Riporta il telefono a una build ufficiale."));
        } else if (!selinux.isEmpty()) {
            out.add(new Finding("SELINUX", cat, "SELinux attivo", Severity.OK,
                    "getenforce = " + selinux, "Nessuna azione necessaria."));
        }

        // --- debug build ---------------------------------------------------
        if ((Build.TYPE != null && Build.TYPE.contains("userdebug"))
                || (Build.FINGERPRINT != null && Build.FINGERPRINT.contains("test-keys"))) {
            out.add(new Finding("DEBUG_BUILD", cat, "Build di tipo debug/userdebug",
                    Severity.INFO, "Build.TYPE = " + Build.TYPE,
                    "Build non destinata al pubblico: se non e' un telefono di sviluppo, chiedi "
                    + "chi l'ha installata."));
        }
        return out;
    }

    private static String readSelinux() {
        String s = Sys.firstLine("/sys/fs/selinux/enforce");
        if ("1".equals(s)) return "Enforcing";
        if ("0".equals(s)) return "Permissive";
        return "";
    }

    private static String join(List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(l.get(i));
        }
        return sb.length() == 0 ? "-" : sb.toString();
    }
}
