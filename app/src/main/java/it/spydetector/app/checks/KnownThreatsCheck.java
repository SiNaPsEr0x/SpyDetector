package it.spydetector.app.checks;

import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.InstalledApps;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;
import it.spydetector.app.core.ThreatDb;

import java.util.ArrayList;
import java.util.List;

/** Confronta i pacchetti installati con il database locale di stalkerware. */
public class KnownThreatsCheck implements Check {

    @Override public String id() { return "KNOWN_THREATS"; }
    @Override public String category() { return "Sorveglianza"; }
    @Override public String label() { return "Database stalkerware / spyware"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        int hits = 0;

        for (InstalledApps.App app : data.apps.all()) {
            ThreatDb.Known k = ThreatDb.find(app.pkg);
            if (k == null) continue;
            hits++;
            out.add(new Finding("KNOWN_" + k.pkg, cat,
                    "APP DI SORVEGLIANZA INSTALLATA: " + k.name,
                    Severity.CRITICAL,
                    k.name + " (" + k.kind + ") e' presente sul dispositivo"
                    + (app.enabled ? " e attiva." : " (disattivata)."),
                    "Disinstalla l'app: Impostazioni > App > " + k.name + " > Disinstalla/Disattiva. "
                    + "Se non riesci, e' probabilmente amministratore del dispositivo o ha "
                    + "accessibilita' attiva: revoca prima quei permessi. Poi cambia le password "
                    + "di Google, WhatsApp, email e banca da un ALTRO dispositivo sicuro.")
                    .detail("Pacchetto", app.pkg)
                    .detail("Tipo", k.kind)
                    .detail("Installata il", app.firstInstall > 0
                            ? new java.text.SimpleDateFormat("dd/MM/yyyy", java.util.Locale.ITALY)
                              .format(new java.util.Date(app.firstInstall)) : "n/d")
                    .detail("Installata da", app.installer.isEmpty() ? "sconosciuto (sideload)" : app.installer));
        }

        if (hits == 0) {
            out.add(new Finding("KNOWN_NONE", cat, "Nessun kit di sorveglianza noto",
                    Severity.OK, "Nessun pacchetto corrisponde al database locale ("
                            + "mSpy, FlexiSPY, Hoverwatch, KidLogger, Spyzie, ecc.).",
                    "Nessuna azione necessaria. Nota: il database e' un sottoinsieme curato e "
                    + "non copre varianti con nome pacchetto modificato."));
        }
        return out;
    }
}
