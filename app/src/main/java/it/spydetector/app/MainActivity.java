package it.spydetector.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import it.spydetector.app.core.Engine;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.Report;
import it.spydetector.app.core.ReportHolder;
import it.spydetector.app.core.Severity;
import it.spydetector.app.ui.HudBackground;
import it.spydetector.app.ui.RiskGauge;
import it.spydetector.app.ui.Ui;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Dashboard principale: anello di rischio, contatori, log live dei controlli e
 * schede per categoria. Tema HUD: nero, ciano, verde acido.
 */
public class MainActivity extends Activity implements Engine.Listener {

    private HudBackground hud;
    private RiskGauge gauge;
    private TextView statusLabel;
    private TextView statusValue;
    private TextView liveLog;
    private LinearLayout countersRow;
    private LinearLayout categoriesBox;
    private LinearLayout verdictBox;
    private TextView scanBtn;
    private TextView detailsBtn;
    private TextView shareBtn;
    private TextView exportJsonBtn;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final List<String> logLines = new ArrayList<>();
    private Report report;
    private boolean running;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        Report r = ReportHolder.get();
        if (r != null) {
            report = r;
            renderReport(r, false);
        } else {
            ui.postDelayed(new Runnable() {
                @Override public void run() { startScan(); }
            }, 550);
        }
    }

    // ------------------------------------------------------------------ UI --
    private void buildUi() {
        FrameLayout root = new FrameLayout(this);
        hud = new HudBackground(this);
        root.addView(hud, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        ScrollView.LayoutParams slp = new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        scroll.setLayoutParams(slp);

        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int pad = Ui.dp(this, 18);
        col.setPadding(pad, Ui.dp(this, 26), pad, Ui.dp(this, 40));
        scroll.addView(col, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // --- header -------------------------------------------------------
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout titleBox = new LinearLayout(this);
        titleBox.setOrientation(LinearLayout.VERTICAL);

        TextView logo = Ui.text(this, "SPY", 30f, Ui.CYAN, Ui.BLACK);
        logo.setLetterSpacing(0.05f);
        LinearLayout logoRow = new LinearLayout(this);
        logoRow.setOrientation(LinearLayout.HORIZONTAL);
        logoRow.addView(logo);
        TextView dot = Ui.text(this, "·", 30f, Ui.OK, Ui.BLACK);
        logoRow.addView(dot);
        TextView rest = Ui.text(this, "DETECTOR", 30f, Ui.TXT, Ui.BLACK);
        rest.setLetterSpacing(0.05f);
        logoRow.addView(rest);
        titleBox.addView(logoRow);

        TextView tag = Ui.label(this, getString(R.string.tagline));
        tag.setPadding(0, Ui.dp(this, 6), 0, 0);
        titleBox.addView(tag);
        head.addView(titleBox, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView version = Ui.chip(this, "v" + BuildConfig.VERSION_NAME, Ui.CYAN);
        head.addView(version);
        col.addView(head);

        col.addView(Ui.vspace(this, 20));

        // --- gauges -------------------------------------------------------
        gauge = new RiskGauge(this);
        int gsize = Math.min(Ui.dp(this, 268), getResources().getDisplayMetrics().widthPixels
                - Ui.dp(this, 90));
        LinearLayout gaugeRow = new LinearLayout(this);
        gaugeRow.setGravity(Gravity.CENTER_HORIZONTAL);
        gaugeRow.addView(gauge, new LinearLayout.LayoutParams(gsize, gsize));
        col.addView(gaugeRow);

        col.addView(Ui.vspace(this, 14));

        // --- stato corrente -----------------------------------------------
        statusLabel = Ui.label(this, "STATO");
        statusValue = Ui.text(this, "IN ATTESA", 13f, Ui.TXT, Ui.MONO);
        LinearLayout statusBox = new LinearLayout(this);
        statusBox.setOrientation(LinearLayout.VERTICAL);
        statusBox.setGravity(Gravity.CENTER_HORIZONTAL);
        statusBox.addView(statusLabel);
        statusLabel.setGravity(Gravity.CENTER);
        statusValue.setPadding(0, Ui.dp(this, 6), 0, 0);
        statusBox.addView(statusValue);
        col.addView(statusBox);

        col.addView(Ui.vspace(this, 18));

        // --- contatori -----------------------------------------------------
        countersRow = new LinearLayout(this);
        countersRow.setOrientation(LinearLayout.HORIZONTAL);
        countersRow.setGravity(Gravity.CENTER);
        col.addView(countersRow);

        col.addView(Ui.vspace(this, 20));

        // --- pulsanti ------------------------------------------------------
        scanBtn = Ui.button(this, "AVVIA SCANSIONE COMPLETA", Ui.CYAN, true);
        scanBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { if (!running) startScan(); }
        });
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 54));
        col.addView(scanBtn, blp);

        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams half = new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f);
        half.rightMargin = Ui.dp(this, 6);

        detailsBtn = Ui.button(this, "DETTAGLI", Ui.OK, false);
        detailsBtn.setEnabled(false);
        detailsBtn.setAlpha(0.45f);
        detailsBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { openDetails(null); }
        });
        btnRow.addView(detailsBtn, half);

        shareBtn = Ui.button(this, "CONDIVIDI", Ui.TXT, false);
        shareBtn.setAlpha(0.45f);
        shareBtn.setEnabled(false);
        shareBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { shareReport(); }
        });
        LinearLayout.LayoutParams half2 = new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f);
        half2.leftMargin = Ui.dp(this, 6);
        btnRow.addView(shareBtn, half2);
        col.addView(btnRow);
        LinearLayout.LayoutParams btnRowLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        btnRowLp.topMargin = Ui.dp(this, 10);
        btnRow.setLayoutParams(btnRowLp);

        LinearLayout btnRow2 = new LinearLayout(this);
        btnRow2.setOrientation(LinearLayout.HORIZONTAL);
        exportJsonBtn = Ui.button(this, "ESPORTA JSON", Ui.TXT, false);
        exportJsonBtn.setAlpha(0.45f);
        exportJsonBtn.setEnabled(false);
        exportJsonBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { shareJsonReport(); }
        });
        btnRow2.addView(exportJsonBtn, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 48)));
        LinearLayout.LayoutParams btnRow2Lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        btnRow2Lp.topMargin = Ui.dp(this, 10);
        btnRow2.setLayoutParams(btnRow2Lp);
        col.addView(btnRow2);

        col.addView(Ui.vspace(this, 24));

        verdictBox = new LinearLayout(this);
        verdictBox.setOrientation(LinearLayout.VERTICAL);
        col.addView(verdictBox);

        col.addView(Ui.vspace(this, 22));

        // --- log live ------------------------------------------------------
        LinearLayout logBox = new LinearLayout(this);
        logBox.setOrientation(LinearLayout.VERTICAL);
        logBox.setBackground(Ui.panel(this, 0x3300E5FF));
        logBox.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 14));

        LinearLayout logHead = new LinearLayout(this);
        logHead.setOrientation(LinearLayout.HORIZONTAL);
        logHead.setGravity(Gravity.CENTER_VERTICAL);
        logHead.addView(Ui.label(this, "LIVE SCAN LOG"));
        View spacer = new View(this);
        logHead.addView(spacer, new LinearLayout.LayoutParams(0, 1, 1f));
        logHead.addView(Ui.chip(this, "ON-DEVICE", Ui.OK));
        logBox.addView(logHead);

        liveLog = Ui.text(this, "> in attesa di comandi…", 11.5f, 0xFF7CF7D0, Ui.MONO);
        liveLog.setLineSpacing(Ui.dp(this, 3), 1f);
        liveLog.setPadding(0, Ui.dp(this, 10), 0, 0);
        logBox.addView(liveLog);
        col.addView(logBox);

        col.addView(Ui.vspace(this, 22));

        LinearLayout catHead = new LinearLayout(this);
        catHead.setGravity(Gravity.CENTER_VERTICAL);
        catHead.setOrientation(LinearLayout.HORIZONTAL);
        catHead.addView(Ui.label(this, "AREE ANALIZZATE"));
        catHead.addView(new View(this), new LinearLayout.LayoutParams(0, 1, 1f));
        catHead.addView(Ui.label(this, "TOCCA PER DETTAGLI"));
        col.addView(catHead);
        col.addView(Ui.vspace(this, 10));

        categoriesBox = new LinearLayout(this);
        categoriesBox.setOrientation(LinearLayout.VERTICAL);
        col.addView(categoriesBox);

        col.addView(Ui.vspace(this, 26));

        TextView foot = Ui.text(this,
                "Analisi 100% locale: SpyDetector non ha il permesso INTERNET e non invia "
                + "nessun dato. I risultati sono indicatori tecnici, non prove legali.",
                10.5f, 0xFF56687D, Ui.SANS);
        foot.setLineSpacing(Ui.dp(this, 2), 1f);
        col.addView(foot);

        root.addView(scroll);
        Ui.applyInsets(root, col);
        setContentView(root);
        renderCounters(null);
    }

    // --------------------------------------------------------------- scan --
    private void startScan() {
        running = true;
        logLines.clear();
        liveLog.setText("> avvio sequenza di analisi…");
        gauge.reset();
        gauge.setProgress(0.02f);
        statusValue.setText("INIZIALIZZAZIONE…");
        statusValue.setTextColor(Ui.CYAN);
        categoriesBox.removeAllViews();
        verdictBox.removeAllViews();
        renderCounters(null);
        scanBtn.setText("SCANSIONE IN CORSO…");
        scanBtn.setAlpha(0.7f);
        detailsBtn.setEnabled(false);
        detailsBtn.setAlpha(0.45f);
        shareBtn.setEnabled(false);
        shareBtn.setAlpha(0.45f);
        if (exportJsonBtn != null) {
            exportJsonBtn.setEnabled(false);
            exportJsonBtn.setAlpha(0.45f);
        }
        Engine.run(this, this);
    }

    @Override
    public void onProgress(int index, int total, String label) {
        float p = total == 0 ? 0f : (float) index / total;
        gauge.setProgress(Math.max(0.02f, p));
        statusLabel.setText("CHECK " + Math.min(index + 1, total) + " / " + total);
        statusValue.setText(label.toUpperCase());
        if (!label.equals("Completato")) {
            appendLog("• " + label);
        }
    }

    private void appendLog(String line) {
        logLines.add(line);
        while (logLines.size() > 9) logLines.remove(0);
        StringBuilder sb = new StringBuilder();
        for (String l : logLines) {
            if (sb.length() > 0) sb.append('\n');
            sb.append(l);
        }
        liveLog.setText(sb.toString());
    }

    @Override
    public void onDone(final Report r) {
        running = false;
        report = r;
        ReportHolder.set(r);
        renderReport(r, true);
    }

    // ------------------------------------------------------------- render --
    private void renderReport(Report r, boolean animate) {
        int score = r.score();
        int color = scoreColor(score);
        gauge.setResult(score, r.verdict(), color);
        gauge.setProgress(1f);

        statusLabel.setText("SCANSIONE COMPLETATA IN " + r.durationMs() + " MS");
        statusValue.setText(r.problems() == 0 ? "NESSUNA ANOMALIA"
                : r.problems() + (r.problems() == 1 ? " ANOMALIA DA VERIFICARE"
                : " ANOMALIE DA VERIFICARE"));
        statusValue.setTextColor(r.problems() == 0 ? Ui.OK : color);

        appendLog("> scan completata: " + r.findings.size() + " controlli, "
                + r.problems() + " problemi");

        renderCounters(r);
        renderVerdict(r, color);
        renderCategories(r);

        scanBtn.setText("RIPETI SCANSIONE");
        scanBtn.setAlpha(1f);
        detailsBtn.setEnabled(true);
        detailsBtn.setAlpha(1f);
        shareBtn.setEnabled(true);
        shareBtn.setAlpha(1f);
        if (exportJsonBtn != null) {
            exportJsonBtn.setEnabled(true);
            exportJsonBtn.setAlpha(1f);
        }
    }

    private static int scoreColor(int score) {
        if (score >= 50) return Ui.CRIT;
        if (score >= 25) return 0xFFFF8A3D;
        if (score >= 10) return Ui.WARN;
        return Ui.OK;
    }

    private void renderCounters(Report r) {
        countersRow.removeAllViews();
        addCounter("CRITICI", r == null ? 0 : r.count(Severity.CRITICAL), Ui.CRIT);
        addCounter("RISCHI", r == null ? 0 : r.count(Severity.WARNING), Ui.WARN);
        addCounter("ATTENZ.", r == null ? 0 : r.count(Severity.ATTENTION), 0xFFFF8A3D);
        addCounter("OK", r == null ? 0 : r.count(Severity.OK), Ui.OK);
    }

    private void addCounter(String label, int value, int color) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER);
        card.setPadding(Ui.dp(this, 6), Ui.dp(this, 12), Ui.dp(this, 6), Ui.dp(this, 12));
        card.setBackground(Ui.box(0xCC0A1322, Ui.alpha(color, 90), Math.max(1, Ui.dp(this, 1)),
                Ui.dp(this, 10)));

        TextView v = Ui.text(this, String.valueOf(value), 22f, color, Ui.BLACK);
        v.setGravity(Gravity.CENTER);
        card.addView(v);
        TextView l = Ui.text(this, label, 9f, Ui.DIM, Ui.MONO);
        l.setLetterSpacing(0.1f);
        l.setGravity(Gravity.CENTER);
        l.setPadding(0, Ui.dp(this, 4), 0, 0);
        card.addView(l);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(Ui.dp(this, 3), 0, Ui.dp(this, 3), 0);
        countersRow.addView(card, lp);
    }

    private void renderVerdict(Report r, int color) {
        verdictBox.removeAllViews();
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(Ui.dp(this, 16), Ui.dp(this, 14), Ui.dp(this, 16), Ui.dp(this, 16));
        box.setBackground(Ui.box(0xCC0A1322, Ui.alpha(color, 120), Math.max(1, Ui.dp(this, 1)),
                Ui.dp(this, 12)));

        TextView h = Ui.label(this, "VERDETTO");
        box.addView(h);
        TextView v = Ui.text(this, r.verdict(), 20f, color, Ui.BLACK);
        v.setPadding(0, Ui.dp(this, 6), 0, 0);
        box.addView(v);

        StringBuilder sb = new StringBuilder();
        for (java.util.Map.Entry<String, String> e : r.deviceInfo.entrySet()) {
            if (e.getKey().startsWith("~")) continue;
            sb.append(e.getKey()).append(": ").append(e.getValue()).append('\n');
        }
        TextView d = Ui.text(this, sb.toString().trim(), 11f, 0xFF9FB3C8, Ui.MONO);
        d.setLineSpacing(Ui.dp(this, 3), 1f);
        d.setPadding(0, Ui.dp(this, 10), 0, 0);
        box.addView(d);
        verdictBox.addView(box);
    }

    private void renderCategories(Report r) {
        categoriesBox.removeAllViews();
        Set<String> cats = new LinkedHashSet<>();
        for (Finding f : r.findings) cats.add(f.category);

        for (String cat : cats) {
            List<Finding> fs = r.byCategory(cat);
            Severity worst = Severity.OK;
            int problems = 0;
            for (Finding f : fs) {
                if (f.severity.ordinal() > worst.ordinal()) worst = f.severity;
                if (f.severity.atLeast(Severity.ATTENTION)) problems++;
            }
            final String catFinal = cat;
            int color = Ui.colorFor(worst);

            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.HORIZONTAL);
            card.setGravity(Gravity.CENTER_VERTICAL);
            card.setPadding(Ui.dp(this, 14), Ui.dp(this, 14), Ui.dp(this, 14), Ui.dp(this, 14));
            card.setBackground(Ui.box(0xE60A1322, 0x2600E5FF, Math.max(1, Ui.dp(this, 1)),
                    Ui.dp(this, 10)));
            card.setClickable(true);

            View bar = new View(this);
            bar.setBackground(Ui.box(color, color, 0, Ui.dp(this, 2)));
            card.addView(bar, new LinearLayout.LayoutParams(Ui.dp(this, 4), Ui.dp(this, 34)));

            LinearLayout text = new LinearLayout(this);
            text.setOrientation(LinearLayout.VERTICAL);
            text.setPadding(Ui.dp(this, 12), 0, 0, 0);
            text.addView(Ui.text(this, cat.toUpperCase(), 13f, Ui.TXT, Ui.MONO_B));
            String sub = problems == 0 ? "nessuna anomalia"
                    : problems + (problems == 1 ? " punto da verificare" : " punti da verificare");
            text.addView(Ui.text(this, sub, 11f, Ui.DIM, Ui.SANS));
            card.addView(text, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

            card.addView(Ui.chip(this, String.valueOf(problems), problems == 0 ? Ui.OK : color));
            card.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { openDetails(catFinal); }
            });

            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.bottomMargin = Ui.dp(this, 9);
            categoriesBox.addView(card, lp);
        }
    }

    private void openDetails(String category) {
        if (report == null) return;
        Intent i = new Intent(this, DetailActivity.class);
        if (category != null) i.putExtra("category", category);
        startActivity(i);
    }

    private void shareReport() {
        if (report == null) return;
        Report r = report;
        StringBuilder sb = new StringBuilder();
        sb.append("SPYDETECTOR // DEVICE SECURITY REPORT\n");
        sb.append("=====================================\n");
        for (java.util.Map.Entry<String, String> e : r.deviceInfo.entrySet()) {
            if (e.getKey().startsWith("~")) continue;
            sb.append(e.getKey()).append(": ").append(e.getValue()).append('\n');
        }
        sb.append("Risk index: ").append(r.score()).append("/100 (").append(r.verdict()).append(")\n");
        sb.append("Controlli: ").append(r.findings.size())
          .append(" | Da verificare: ").append(r.problems()).append("\n\n");
        for (Finding f : r.findings) {
            if (!f.severity.atLeast(Severity.ATTENTION)) continue;
            sb.append("[").append(f.severity.label()).append("] ").append(f.title).append('\n');
            sb.append("  ").append(f.evidence).append('\n');
            sb.append("  -> ").append(f.advice).append("\n\n");
        }
        sb.append("Generato da SpyDetector v").append(BuildConfig.VERSION_NAME)
          .append(" - analisi locale, nessun dato inviato.");
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "SpyDetector report");
        send.putExtra(Intent.EXTRA_TEXT, sb.toString());
        startActivity(Intent.createChooser(send, "Condividi report"));
    }

    private void shareJsonReport() {
        if (report == null) return;
        Report r = report;
        
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"app\": \"SpyDetector\",\n");
        sb.append("  \"version\": \"").append(BuildConfig.VERSION_NAME).append("\",\n");
        sb.append("  \"score\": ").append(r.score()).append(",\n");
        sb.append("  \"verdict\": \"").append(escapeJson(r.verdict())).append("\",\n");
        sb.append("  \"problems\": ").append(r.problems()).append(",\n");
        sb.append("  \"deviceInfo\": {\n");
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : r.deviceInfo.entrySet()) {
            if (e.getKey().startsWith("~")) continue;
            if (!first) sb.append(",\n");
            sb.append("    \"").append(escapeJson(e.getKey())).append("\": \"")
              .append(escapeJson(e.getValue())).append("\"");
            first = false;
        }
        sb.append("\n  },\n");
        sb.append("  \"findings\": [\n");
        first = true;
        for (Finding f : r.findings) {
            if (!first) sb.append(",\n");
            sb.append("    {\n");
            sb.append("      \"id\": \"").append(escapeJson(f.checkId)).append("\",\n");
            sb.append("      \"category\": \"").append(escapeJson(f.category)).append("\",\n");
            sb.append("      \"title\": \"").append(escapeJson(f.title)).append("\",\n");
            sb.append("      \"severity\": \"").append(f.severity.name()).append("\",\n");
            sb.append("      \"evidence\": \"").append(escapeJson(f.evidence)).append("\",\n");
            sb.append("      \"advice\": \"").append(escapeJson(f.advice)).append("\"\n");
            sb.append("    }");
            first = false;
        }
        sb.append("\n  ]\n");
        sb.append("}\n");
        
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("application/json");
        send.putExtra(Intent.EXTRA_SUBJECT, "SpyDetector report JSON");
        send.putExtra(Intent.EXTRA_TEXT, sb.toString());
        startActivity(Intent.createChooser(send, "Esporta report JSON"));
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (hud != null) hud.animate(true);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (hud != null) hud.animate(false);
    }
}
