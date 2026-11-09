package it.spydetector.app.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Piccole utilita' di sistema, senza root e senza rete. */
public final class Sys {

    private Sys() {}

    public static boolean canRead(String path) {
        try {
            File f = new File(path);
            return f.exists() && f.canRead();
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean exists(String path) {
        try { return new File(path).exists(); } catch (Throwable t) { return false; }
    }

    public static String firstLine(String path) {
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            String l = r.readLine();
            return l == null ? "" : l.trim();
        } catch (Throwable t) {
            return "";
        }
    }

    public static long date(String isoDate) {
        try {
            String d = isoDate.replace("-", "");
            return new SimpleDateFormat("yyyyMMdd", Locale.US).parse(d).getTime();
        } catch (Throwable t) {
            return 0L;
        }
    }

    public static int monthsAgo(long ts) {
        if (ts <= 0) return -1;
        long diff = System.currentTimeMillis() - ts;
        return (int) (diff / (1000L * 60 * 60 * 24 * 30));
    }

    public static String fmtDate(long ts) {
        try {
            return new SimpleDateFormat("dd/MM/yyyy", Locale.ITALY).format(new Date(ts));
        } catch (Throwable t) {
            return "n/d";
        }
    }

    public static String fmtDuration(long ms) {
        long s = ms / 1000;
        if (s < 60) return s + "s";
        return (s / 60) + "m " + (s % 60) + "s";
    }

    public static String human(long bytes) {
        if (bytes <= 0) return "0 B";
        String[] u = {"B", "KB", "MB", "GB"};
        int i = 0;
        double b = bytes;
        while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
        return String.format(Locale.ITALY, "%.1f %s", b, u[i]);
    }

    /** Nome breve dell'ultimo segmento di un package. */
    public static String shortPkg(String pkg) {
        if (pkg == null) return "";
        return pkg;
    }
}
