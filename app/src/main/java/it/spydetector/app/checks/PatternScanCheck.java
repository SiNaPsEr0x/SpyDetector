package it.spydetector.app.checks;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.InstalledApps;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;
import it.spydetector.app.core.ThreatDb;

import java.util.ArrayList;
import java.util.List;

/**
 * Cerca le tracce di spyware usando i PATTERN PUBBLICI (da report di vendors,
 * ricerche accademiche e feed di threat intelligence):
 *
 *  1. CERT — hash SHA-256 del certificato di firma: cattura il repackaging di
 *     spyware anche quando il nome del pacchetto viene cambiato; la firma
 *     resta quella originale.
 *  2. PKG — sottostringhi del nome pacchetto tipici delle famiglie note
 *     (mspy, flexispy, ...): cattura varianti con nome modificato.
 *  3. COMP — nomi di servizi/receiver che riportano alla stessa famiglia:
 *     i payload rimenzionati spesso conservono le classi originali.
 *
 * Nessun dati viene letto fuori dai metadati dell'app: nessun permesso extra,
 * tutto via PackageManager. Per ogni app viene segnalata solo la corrispondenza
 * piu' forte (CERT > PKG > COMP) per evitare doppie segnalazioni.
 */
public class PatternScanCheck implements Check {

    @Override public String id() { return "PATTERNS"; }
    @Override public String category() { return "Sorveglianza"; }
    @Override public String label() { return "Pattern pubblici di spyware"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        int hits = 0;

        for (InstalledApps.App app : data.apps.all()) {
            if (app.pkg.equals(data.ctx.getPackageName())) continue;
            if (ThreatDb.find(app.pkg) != null) continue;   // gia' in KnownThreatsCheck

            ThreatDb.Pattern hit = null;
            String kind = "";
            String extra = "";

            // 1) firma: la prova piu' forte (sovrasta i pattern di nome)
            String hash = ThreatDb.certSha256(data.ctx, app.pkg);
            if (!hash.isEmpty()) {
                ThreatDb.Pattern c = ThreatDb.matchCert(hash);
                if (c != null) { hit = c; kind = "CERT"; extra = hash; }
            }

            // 2) nome pacchetto
            if (hit == null) {
                hit = ThreatDb.matchPkgPattern(app.pkg);
                if (hit != null) kind = "PKG";
            }

            // 3) componenti
            if (hit == null) {
                String comp = suspiciousComponent(data.ctx, app.pkg);
                if (comp != null) {
                    hit = ThreatDb.matchComponentPattern(comp);
                    if (hit != null) { kind = "COMP"; extra = comp; }
                }
            }

            if (hit == null) continue;
            hits++;

            String proof;
            if (kind.equals("CERT")) {
                proof = "La firma dell'app (SHA-256 " + extra.substring(0, Math.min(16, extra.length()))
                        + "…) corrisponde a un certificato noto associato a '" + hit.name
                        + "'. Anche se il nome del pacchetto e' diverso, e' la stessa identita' "
                        + "digitale dello spyware: si tratta di repackaging/camuffamento.";
            } else if (kind.equals("PKG")) {
                proof = app.pkg + " contiene il pattern pubblico '" + hit.value
                        + "' della famiglia '" + hit.name + "' (" + hit.kind + ").";
            } else {
                proof = "L'app ha un componente (" + extra + ") con nome riconducibile a '"
                        + hit.name + "' (" + hit.kind + "). I payload rimenzionati spesso "
                        + "conservano le classi originali.";
            }

            Finding f = new Finding("PATTERN_" + kind + "_" + slug(app.pkg), cat,
                    "App con pattern pubblico di spyware: " + app.label,
                    hit.severity, proof,
                    "Verifica immediatamente: Impostazioni > App > " + app.label
                    + ". Se non riconosci questa app o non ricordi di averla installata, "
                    + "disinstallala e controlla accessibilita' e permessi.");
            f.detail("Pacchetto", app.pkg)
             .detail("Tipo pattern", kind + " (" + hit.value + ")")
             .detail("Famiglia", hit.name)
             .detail("Tipo", hit.kind);
            if (kind.equals("CERT")) {
                f.detail("Firma SHA-256", extra);
            }
            if (kind.equals("COMP")) {
                f.detail("Componente", extra);
            }
            if (app.enabled) {
                f.detail("Stato", "attiva");
            } else {
                f.detail("Stato", "disattivata");
            }
            out.add(f);
        }

        if (hits == 0) {
            out.add(new Finding("PATTERN_NONE", cat, "Nessuna corrispondenza con i pattern pubblici",
                    Severity.OK,
                    "Nessuna app corrisponde ai pattern pubblici (nomi di famiglie, firme, "
                    + "componenti) del database locale.",
                    "Nessuna azione necessaria. Nota: i pattern catturano le varianti piu' "
                    + "comunici; uno spyware completamente sconosciuto passa inosservato."));
        }
        return out;
    }

    /** Prima componente (servizio/receiver) il cui nome corrisponde a un pattern COMP. */
    private static String suspiciousComponent(Context ctx, String pkg) {
        try {
            PackageManager pm = ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(pkg,
                    PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS);
            List<String> names = new ArrayList<>();
            if (pi.services != null) {
                for (android.content.pm.ServiceInfo c : pi.services) names.add(c.name);
            }
            if (pi.receivers != null) {
                for (android.content.pm.ActivityInfo c : pi.receivers) names.add(c.name);
            }
            for (String n : names) {
                if (ThreatDb.matchComponentPattern(n) != null) return n;
            }
        } catch (Throwable ignored) {
            // alcune ROM nascondono i componenti alle app: niente da segnalare
        }
        return null;
    }

    private static String slug(String pkg) {
        return pkg.replaceAll("[^A-Za-z0-9]", "_");
    }
}
