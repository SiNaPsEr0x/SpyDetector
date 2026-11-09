package it.spydetector.app.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.view.View;

/**
 * Anello di progresso con punteggio di rischio centrale, stile HUD.
 * Mostra: punteggio 0-100, verdetto testuale e avanzamento scansione.
 */
public class RiskGauge extends View {

    private final Paint track = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint arc = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glowArc = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint big = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint small = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint label = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint tick = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF oval = new RectF();

    private float progress = 0f;      // 0..1
    private int score = -1;           // -1 = ancora nessun risultato
    private String verdict = "PRONTO";
    private String sub = "PREMI SCAN PER INIZIARE";
    private int color = 0xFF00E5FF;

    public RiskGauge(Context c) { super(c); init(); }

    private void init() {
        setLayerType(LAYER_TYPE_SOFTWARE, null);
        track.setStyle(Paint.Style.STROKE);
        track.setStrokeCap(Paint.Cap.ROUND);
        track.setColor(0x22FFFFFF);

        arc.setStyle(Paint.Style.STROKE);
        arc.setStrokeCap(Paint.Cap.ROUND);
        glowArc.setStyle(Paint.Style.STROKE);
        glowArc.setStrokeCap(Paint.Cap.ROUND);

        big.setTypeface(Typeface.create("sans-serif-light", Typeface.BOLD));
        big.setTextAlign(Paint.Align.CENTER);
        small.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        small.setTextAlign(Paint.Align.CENTER);
        label.setTypeface(Typeface.create("monospace", Typeface.NORMAL));
        label.setTextAlign(Paint.Align.CENTER);
        tick.setColor(0x3300E5FF);
        tick.setStrokeWidth(2f);
    }

    public void setProgress(float p) {
        progress = Math.max(0f, Math.min(1f, p));
        invalidate();
    }

    public void setResult(int score, String verdict, int color) {
        this.score = score;
        this.verdict = verdict;
        this.color = color;
        this.sub = "RISK INDEX";
        invalidate();
    }

    public void reset() {
        score = -1;
        progress = 0f;
        verdict = "PRONTO";
        sub = "PREMI SCAN PER INIZIARE";
        color = 0xFF00E5FF;
        invalidate();
    }

    @Override
    protected void onDraw(Canvas c) {
        float w = getWidth(), h = getHeight();
        float size = Math.min(w, h);
        float stroke = size * 0.055f;
        float pad = stroke * 1.6f;
        oval.set(pad, pad, w - pad, h - pad);

        track.setStrokeWidth(stroke);
        c.drawArc(oval, 0, 360, false, track);

        // tacche decorative
        for (int i = 0; i < 60; i++) {
            float ang = (float) Math.toRadians(i * 6 - 90);
            float r1 = size * 0.475f, r2 = r1 - (i % 5 == 0 ? size * 0.03f : size * 0.015f);
            float cx = w / 2f, cy = h / 2f;
            c.drawLine(cx + (float) Math.cos(ang) * r1, cy + (float) Math.sin(ang) * r1,
                    cx + (float) Math.cos(ang) * r2, cy + (float) Math.sin(ang) * r2, tick);
        }

        float sweep = 360f * progress;
        arc.setStrokeWidth(stroke);
        arc.setColor(color);
        glowArc.setStrokeWidth(stroke * 2f);
        glowArc.setColor(color);
        glowArc.setAlpha(60);
        glowArc.setShadowLayer(stroke, 0, 0, color);
        c.drawArc(oval, -90, sweep, false, glowArc);
        c.drawArc(oval, -90, sweep, false, arc);

        // testo centrale
        float cx = w / 2f, cy = h / 2f;
        if (score >= 0) {
            big.setColor(color);
            big.setTextSize(size * 0.30f);
            c.drawText(String.valueOf(score), cx, cy + size * 0.06f, big);
            label.setColor(0xFF74879C);
            label.setTextSize(size * 0.052f);
            c.drawText(sub, cx, cy + size * 0.155f, label);
        } else {
            big.setColor(0xFF00E5FF);
            big.setTextSize(size * 0.17f);
            c.drawText(String.valueOf((int) (progress * 100)) + "%", cx, cy + size * 0.05f, big);
            label.setColor(0xFF74879C);
            label.setTextSize(size * 0.045f);
            c.drawText("ANALISI", cx, cy + size * 0.13f, label);
        }

        small.setColor(0xFFE6F1FF);
        small.setTextSize(size * 0.065f);
        c.drawText(verdict, cx, cy - size * 0.20f, small);
    }
}
