package it.spydetector.app.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.RectF;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;

/**
 * Sfondo "HUD": griglia prospettica, anelli concentrici, scanline e un bagliore
 * che pulsa. Disegnato a mano: nessuna libreria esterna, zero dipendenze.
 */
public class HudBackground extends View {

    private final Paint grid = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glow = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint scan = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint horizon = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path ringPath = new Path();
    private final RectF oval = new RectF();
    private float phase = 0f;
    private long lastTick = 0L;

    public HudBackground(Context c) { super(c); init(); }
    public HudBackground(Context c, AttributeSet a) { super(c, a); init(); }

    private void init() {
        setWillNotDraw(false);
        grid.setStyle(Paint.Style.STROKE);
        grid.setStrokeWidth(1f);
        grid.setColor(0x2200E5FF);
        ring.setStyle(Paint.Style.STROKE);
        ring.setStrokeWidth(2f);
        ring.setColor(0x4400E5FF);
        scan.setStyle(Paint.Style.STROKE);
        scan.setStrokeWidth(1.5f);
        scan.setColor(0x3300FFA3);
        horizon.setStrokeWidth(3f);
        horizon.setColor(0x5500E5FF);
    }

    @Override
    protected void onDraw(Canvas c) {
        int w = getWidth(), h = getHeight();
        if (w == 0 || h == 0) return;

        c.drawColor(0xFF04070E);

        // bagliore radiale in alto
        glow.setShader(new RadialGradient(w * 0.5f, h * 0.16f, w * 0.95f,
                new int[]{0x3300E5FF, 0x1100FFA3, 0x0004070E},
                new float[]{0f, 0.45f, 1f}, Shader.TileMode.CLAMP));
        c.drawRect(0, 0, w, h, glow);

        // orizzonte
        float hz = h * 0.62f;
        horizon.setShader(new LinearGradient(0, 0, w, 0,
                new int[]{0x0000E5FF, 0x8800E5FF, 0x0000E5FF},
                new float[]{0f, 0.5f, 1f}, Shader.TileMode.CLAMP));
        c.drawLine(0, hz, w, h, horizon);

        // griglia prospettica
        int rows = 14;
        for (int i = 0; i < rows; i++) {
            float t = (i + phase) / rows;
            float y = hz + (h - hz) * t * t;
            if (y > h) continue;
            int alpha = (int) (60 * (1f - t));
            grid.setColor(Color.argb(Math.max(0, alpha), 0, 229, 255));
            c.drawLine(0, y, w, y, grid);
        }
        for (int i = -8; i <= 8; i++) {
            float x0 = w * 0.5f + i * (w / 9f);
            grid.setColor(0x1E00E5FF);
            c.drawLine(w * 0.5f, hz, x0 * 1.6f, h, grid);
        }

        // anelli concentrici
        float cx = w * 0.5f, cy = h * 0.30f;
        for (int i = 0; i < 4; i++) {
            float r = w * (0.22f + i * 0.11f);
            oval.set(cx - r, cy - r, cx + r, cy + r);
            ring.setAlpha(70 - i * 14);
            c.drawOval(oval, ring);
        }

        // arco di scansione rotante
        float r = w * 0.34f;
        ringPath.reset();
        oval.set(cx - r, cy - r, cx + r, cy + r);
        float start = (phase * 360f * 2f) % 360f;
        ringPath.addArc(oval, start, 70);
        scan.setColor(0x8800FFA3);
        c.drawPath(ringPath, scan);

        // scanline verticale
        float sy = (phase * h * 2f) % h;
        scan.setColor(0x2200E5FF);
        c.drawLine(0, sy, w, sy, scan);
    }

    private boolean animating = false;

    /** Avvia/ferma l'animazione. Idempotente: un solo ticker attivo. */
    public void animate(boolean run) {
        removeCallbacks(ticker);
        animating = run;
        if (run) {
            lastTick = System.currentTimeMillis();
            postDelayed(ticker, 40);
        }
    }

    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            if (!animating) return;
            long now = System.currentTimeMillis();
            float dt = Math.min(0.2f, (now - lastTick) / 1000f);
            lastTick = now;
            phase = (phase + dt * 0.25f) % 1f;
            invalidate();
            postDelayed(this, 40);
        }
    };

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        animate(true);
    }

    @Override
    protected void onDetachedFromWindow() {
        animate(false);
        super.onDetachedFromWindow();
    }
}
