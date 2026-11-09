package it.spydetector.app.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Risultato completo di una scansione. */
public final class Report {

    public final List<Finding> findings = new ArrayList<>();
    public final Map<String, String> deviceInfo = new LinkedHashMap<>();
    public long startedAt;
    public long finishedAt;

    public void add(Finding f) {
        if (f != null) findings.add(f);
    }

    public void addAll(List<Finding> fs) {
        if (fs != null) findings.addAll(fs);
    }

    public int count(Severity s) {
        int n = 0;
        for (Finding f : findings) if (f.severity == s) n++;
        return n;
    }

    public int problems() {
        int n = 0;
        for (Finding f : findings) if (f.severity.atLeast(Severity.ATTENTION)) n++;
        return n;
    }

    /** Punteggio di rischio 0-100 (0 = pulito). */
    public int score() {
        int raw = 0;
        for (Finding f : findings) raw += f.severity.weight();
        return Math.min(100, raw);
    }

    public String verdict() {
        int s = score();
        if (s == 0) return "NESSUN RISCHIO RILEVATO";
        if (s < 10) return "BASSO";
        if (s < 25) return "MEDIO";
        if (s < 50) return "ALTO";
        return "CRITICO";
    }

    public long durationMs() {
        return Math.max(0, finishedAt - startedAt);
    }

    public List<Finding> byCategory(String cat) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) if (f.category.equals(cat)) out.add(f);
        return out;
    }
}
