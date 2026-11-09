package it.spydetector.app.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Un singolo risultato di controllo: cosa e' stato verificato, cosa e' emerso e
 * cosa dovrebbe fare l'utente. Nessun testo e' generato a caso: ogni voce nasce
 * da un controllo reale sul dispositivo.
 */
public final class Finding {

    public final String checkId;
    public final String category;
    public final String title;
    public final Severity severity;
    public final String evidence;
    public final String advice;
    /** Dati strutturati opzionali (es. permessi, package) mostrati nel dettaglio. */
    public final Map<String, String> details = new LinkedHashMap<>();

    public Finding(String checkId, String category, String title, Severity severity,
                   String evidence, String advice) {
        this.checkId = checkId;
        this.category = category;
        this.title = title;
        this.severity = severity;
        this.evidence = evidence;
        this.advice = advice;
    }

    public Finding detail(String key, String value) {
        if (value != null && !value.isEmpty()) details.put(key, value);
        return this;
    }

    public static List<Finding> list() {
        return new ArrayList<>();
    }
}
