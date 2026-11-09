package it.spydetector.app.core;

/**
 * Gravita' di un problema rilevato. L'ordine dichiarativo determina il
 * punteggio di rischio (vedi {@link Report#score()}).
 */
public enum Severity {
    OK, INFO, ATTENTION, WARNING, CRITICAL;

    public String label() {
        switch (this) {
            case OK: return "OK";
            case INFO: return "INFO";
            case ATTENTION: return "ATTENZIONE";
            case WARNING: return "RISCHIO";
            case CRITICAL: return "CRITICO";
            default: return "?";
        }
    }

    /** Peso usato nel calcolo del punteggio di rischio finale (0-100). */
    public int weight() {
        switch (this) {
            case OK: return 0;
            case INFO: return 1;
            case ATTENTION: return 5;
            case WARNING: return 12;
            case CRITICAL: return 25;
            default: return 0;
        }
    }

    public boolean atLeast(Severity other) {
        return ordinal() >= other.ordinal();
    }
}
