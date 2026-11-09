package it.spydetector.app.core;

/** Conserva l'ultimo report per la schermata di dettaglio (nessuna serializzazione). */
public final class ReportHolder {
    private static Report last;

    private ReportHolder() {}

    public static void set(Report r) { last = r; }

    public static Report get() { return last; }

    public static Finding finding(String checkId) {
        if (last == null || checkId == null) return null;
        for (Finding f : last.findings) {
            if (checkId.equals(f.checkId)) return f;
        }
        return null;
    }
}
