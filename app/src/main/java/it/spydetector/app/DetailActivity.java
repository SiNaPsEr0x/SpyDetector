package it.spydetector.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import it.spydetector.app.core.Finding;
import it.spydetector.app.core.Report;
import it.spydetector.app.core.ReportHolder;
import it.spydetector.app.core.Severity;
import it.spydetector.app.ui.HudBackground;
import it.spydetector.app.ui.Ui;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Elenco completo dei risultati, filtrabile per categoria. */
public class DetailActivity extends Activity {

    private LinearLayout list;
    private String category;
    private final Set<String> expanded = new java.util.LinkedHashSet<>();

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        category = getIntent() == null ? null : getIntent().getStringExtra("category");

        FrameLayout root = new FrameLayout(this);
        HudBackground hud = new HudBackground(this);
        root.addView(hud, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        ScrollView sc = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(Ui.dp(this, 18), Ui.dp(this, 26), Ui.dp(this, 18), Ui.dp(this, 40));
        sc.addView(col, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(sc);
        Ui.applyInsets(root, col);
        setContentView(root);

        TextView back = Ui.textS(this, "‹ INDIETRO", 12f, Ui.CYAN, Ui.MONO_B);
        back.setPadding(0, 0, 0, Ui.dp(this, 16));
        back.setClickable(true);
        back.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { finish(); }
        });
        col.addView(back);

        TextView t = Ui.textS(this, category == null ? "TUTTI I RISULTATI" : category.toUpperCase(),
                24f, Ui.TXT, Ui.BLACK);
        t.setLetterSpacing(0.03f);
        col.addView(t);
        col.addView(Ui.vspace(this, 6));
        col.addView(Ui.labelS(this, "SPYDETECTOR // REPORT"));
        col.addView(Ui.vspace(this, 18));

        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        col.addView(list);

        fill();
        hud.animate(true);
    }

    private void fill() {
        list.removeAllViews();
        Report r = ReportHolder.get();
        if (r == null) {
            list.addView(Ui.textS(this, "Nessun risultato disponibile. Avvia una scansione.",
                    13f, Ui.DIM, Ui.SANS));
            return;
        }

        List<Finding> items = new ArrayList<>();
        for (Finding f : r.findings) {
            if (category == null || f.category.equals(category)) items.add(f);
        }
        // ordina per gravita' decrescente
        items.sort(new java.util.Comparator<Finding>() {
            @Override public int compare(Finding a, Finding b) {
                int c = Integer.compare(b.severity.ordinal(), a.severity.ordinal());
                return c != 0 ? c : a.title.compareTo(b.title);
            }
        });

        if (items.isEmpty()) {
            list.addView(Ui.textS(this, "Nessun controllo in questa categoria.",
                    13f, Ui.DIM, Ui.SANS));
            return;
        }

        for (final Finding f : items) {
            list.addView(card(f));
            list.addView(Ui.vspace(this, 10));
        }

        list.addView(Ui.vspace(this, 14));
        TextView note = Ui.textS(this,
                "SpyDetector rileva indicatori tecnici (permessi, servizi attivi, pacchetti noti). "
                + "Non e' un antivirus e non puo' garantire l'assenza di software malevolo: "
                + "in caso di dubbio fai un reset ai dati di fabbrica e cambia le password.",
                10.5f, 0xFF56687D, Ui.SANS);
        note.setLineSpacing(Ui.dp(this, 2), 1f);
        list.addView(note);
    }

    private View card(final Finding f) {
        final int color = Ui.colorFor(f.severity);
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(Ui.dp(this, 14), Ui.dp(this, 13), Ui.dp(this, 14), Ui.dp(this, 13));
        card.setBackground(Ui.box(0xE60A1322, Ui.alpha(color, f.severity == Severity.OK ? 60 : 110),
                Math.max(1, Ui.dp(this, 1)), Ui.dp(this, 10)));

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.TOP);
        head.addView(Ui.chipS(this, f.severity.label(), color));
        TextView title = Ui.textS(this, f.title, 13.5f,
                f.severity == Severity.OK ? 0xFFB9C7D6 : Ui.TXT, Ui.SANS_B);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tlp.leftMargin = Ui.dp(this, 10);
        head.addView(title, tlp);
        card.addView(head);

        TextView ev = Ui.textS(this, f.evidence, 11f, 0xFF9FB3C8, Ui.MONO);
        ev.setPadding(0, Ui.dp(this, 9), 0, 0);
        ev.setLineSpacing(Ui.dp(this, 2), 1f);
        card.addView(ev);

        // --- bottoni azione se la finding ha un pacchetto ----------------
        String pkg = f.details.get("Pacchetto");
        if (pkg != null && !pkg.isEmpty() && !pkg.equals(getPackageName())) {
            LinearLayout actions = new LinearLayout(this);
            actions.setOrientation(LinearLayout.HORIZONTAL);
            actions.setGravity(Gravity.CENTER_VERTICAL);
            actions.setPadding(0, Ui.dp(this, 10), 0, 0);
            // consuma i click su quest'area per impedire il toggle della card
            actions.setClickable(true);
            actions.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) { /* no-op: consuma */ }
            });

            // pulsante DISINSTALLA — larghezza uguale a APERTI
            TextView uninstallBtn = Ui.buttonCompact(this, "DISINSTALLA", Ui.CRIT);
            uninstallBtn.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    Intent di = new Intent("android.intent.action.DELETE_PACKAGE");
                    di.setData(Uri.parse("package:" + pkg));
                    startActivity(di);
                }
            });
            LinearLayout.LayoutParams blp1 = new LinearLayout.LayoutParams(0,
                    Ui.dp(this, 44), 1f);
            blp1.rightMargin = Ui.dp(this, 3);
            actions.addView(uninstallBtn, blp1);

            // pulsante APERTI — apre Impostazioni > App > [app] (non lancia l'app)
            TextView openBtn = Ui.buttonCompact(this, "APERTI", Ui.CYAN);
            openBtn.setOnClickListener(new View.OnClickListener() {
                @Override public void onClick(View v) {
                    Intent settings = new Intent(
                            android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    settings.setData(Uri.parse("package:" + pkg));
                    startActivity(settings);
                }
            });
            LinearLayout.LayoutParams blp2 = new LinearLayout.LayoutParams(0,
                    Ui.dp(this, 44), 1f);
            blp2.leftMargin = Ui.dp(this, 3);
            actions.addView(openBtn, blp2);

            card.addView(actions);
        }

        final LinearLayout more = new LinearLayout(this);
        more.setOrientation(LinearLayout.VERTICAL);
        more.setVisibility(expanded.contains(f.checkId) ? View.VISIBLE : View.GONE);

        if (!f.advice.isEmpty()) {
            TextView adv = Ui.textS(this, "▸ " + f.advice, 11.5f, 0xFFD9E9F7, Ui.SANS);
            adv.setLineSpacing(Ui.dp(this, 3), 1f);
            adv.setPadding(0, Ui.dp(this, 10), 0, 0);
            more.addView(adv);
        }
        for (Map.Entry<String, String> e : f.details.entrySet()) {
            TextView d = Ui.textS(this, e.getKey() + ": " + e.getValue(), 10.5f, Ui.DIM, Ui.MONO);
            d.setPadding(0, Ui.dp(this, 6), 0, 0);
            more.addView(d);
        }
        TextView id = Ui.textS(this, "check: " + f.checkId + " · area: " + f.category,
                9.5f, 0xFF4E6076, Ui.MONO);
        id.setPadding(0, Ui.dp(this, 8), 0, 0);
        more.addView(id);
        card.addView(more);

        card.setClickable(true);
        card.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                boolean open = more.getVisibility() == View.VISIBLE;
                more.setVisibility(open ? View.GONE : View.VISIBLE);
                if (open) expanded.remove(f.checkId); else expanded.add(f.checkId);
            }
        });
        return card;
    }
}
