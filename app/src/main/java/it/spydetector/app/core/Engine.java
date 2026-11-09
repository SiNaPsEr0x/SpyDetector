package it.spydetector.app.core;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import it.spydetector.app.checks.AccessibilityCheck;
import it.spydetector.app.checks.AppPermissionsCheck;
import it.spydetector.app.checks.DeviceHardeningCheck;
import it.spydetector.app.checks.KnownThreatsCheck;
import it.spydetector.app.checks.MessagingCheck;
import it.spydetector.app.checks.NetworkCheck;
import it.spydetector.app.checks.PatternScanCheck;
import it.spydetector.app.checks.PersistenceCheck;
import it.spydetector.app.checks.SystemIntegrityCheck;
import it.spydetector.app.checks.UnknownSideloadCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Orchestratore della scansione: esegue i check in background, aggiorna i
 * progressi sul thread UI e restituisce un {@link Report}.
 */
public final class Engine {

    public interface Listener {
        /** Chiamato sul main thread. */
        void onProgress(int index, int total, String label);
        /** Chiamato sul main thread con il report finale. */
        void onDone(Report report);
    }

    private static List<Check> defaultChecks() {
        List<Check> l = new ArrayList<>();
        l.add(new SystemIntegrityCheck());
        l.add(new DeviceHardeningCheck());
        l.add(new AccessibilityCheck());
        l.add(new PersistenceCheck());
        l.add(new KnownThreatsCheck());
        l.add(new PatternScanCheck());
        l.add(new UnknownSideloadCheck());
        l.add(new MessagingCheck());
        l.add(new AppPermissionsCheck());
        l.add(new NetworkCheck());
        return l;
    }

    private Engine() {}

    public static List<Check> checks() {
        return defaultChecks();
    }

    public static void run(final Context ctx, final Listener listener) {
        final ExecutorService ex = Executors.newSingleThreadExecutor();
        final Handler main = new Handler(Looper.getMainLooper());
        final List<Check> checks = defaultChecks();

        ex.execute(new Runnable() {
            @Override public void run() {
                final Report report = new Report();
                report.startedAt = System.currentTimeMillis();
                final ScanData data;
                try {
                    data = new ScanData(ctx);
                } catch (Throwable t) {
                    report.add(new Finding("BOOT", "Sistema", "Impossibile raccogliere i dati di base",
                            Severity.CRITICAL, String.valueOf(t), "Riavvia l'app e riprova."));
                    report.finishedAt = System.currentTimeMillis();
                    main.post(new Runnable() { @Override public void run() { listener.onDone(report); } });
                    ex.shutdown();
                    return;
                }
                report.deviceInfo.put("Dispositivo", data.device.summary());
                report.deviceInfo.put("Android", data.device.androidVersion + " (API " + data.device.sdk + ")");
                if (!data.device.securityPatch.isEmpty())
                    report.deviceInfo.put("Patch sicurezza", data.device.securityPatch);
                if (data.device.ramMb > 0)
                    report.deviceInfo.put("RAM", data.device.ramMb + " MB");
                report.deviceInfo.put("App installate", String.valueOf(data.apps.count()));

                final Report rep = report;
                for (int i = 0; i < checks.size(); i++) {
                    final Check c = checks.get(i);
                    final int idx = i;
                    main.post(new Runnable() {
                        @Override public void run() { listener.onProgress(idx, checks.size(), c.label()); }
                    });
                    long t0 = System.currentTimeMillis();
                    try {
                        List<Finding> fs = c.run(data);
                        if (fs != null) rep.addAll(fs);
                    } catch (Throwable t) {
                        rep.add(new Finding(c.id(), c.category(), "Controllo non completato: " + c.label(),
                                Severity.INFO, t.getClass().getSimpleName()
                                + (t.getMessage() == null ? "" : ": " + t.getMessage()),
                                "Il controllo e' stato saltato su questo dispositivo. Gli altri risultati restano validi."));
                    }
                    long dt = System.currentTimeMillis() - t0;
                    rep.deviceInfo.put("~" + c.id(), dt + " ms");
                }
                rep.finishedAt = System.currentTimeMillis();
                main.post(new Runnable() {
                    @Override public void run() {
                        listener.onProgress(checks.size(), checks.size(), "Completato");
                        listener.onDone(rep);
                    }
                });
                ex.shutdown();
            }
        });
    }
}
