package it.spydetector.app.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.content.res.ColorStateList;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import it.spydetector.app.core.Severity;

/** Helper per costruire la UI "HUD" a runtime (nessun layout XML). */
public final class Ui {

    public static final int BG      = 0xFF04070E;
    public static final int PANEL   = 0xFF0A1322;
    public static final int PANEL2  = 0xFF0E1B2E;
    public static final int CYAN    = 0xFF00E5FF;
    public static final int OK      = 0xFF00FFA3;
    public static final int WARN    = 0xFFFFC400;
    public static final int CRIT    = 0xFFFF3B5C;
    public static final int TXT     = 0xFFE6F1FF;
    public static final int DIM     = 0xFF74879C;

    public static final Typeface MONO = Typeface.create("monospace", Typeface.NORMAL);
    public static final Typeface MONO_B = Typeface.create("monospace", Typeface.BOLD);
    public static final Typeface SANS = Typeface.create("sans-serif-light", Typeface.NORMAL);
    public static final Typeface SANS_B = Typeface.create("sans-serif-medium", Typeface.NORMAL);
    public static final Typeface BLACK = Typeface.create("sans-serif-black", Typeface.NORMAL);

    private Ui() {}

    public static int dp(Context c, float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                c.getResources().getDisplayMetrics());
    }

    public static int colorFor(Severity s) {
        switch (s) {
            case CRITICAL: return CRIT;
            case WARNING: return WARN;
            case ATTENTION: return 0xFFFF8A3D;
            case INFO: return CYAN;
            default: return OK;
        }
    }

    public static GradientDrawable box(int fill, int strokeColor, int strokeWidth, float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.RECTANGLE);
        d.setColor(fill);
        d.setCornerRadius(radius);
        if (strokeWidth > 0) d.setStroke(strokeWidth, strokeColor);
        return d;
    }

    public static GradientDrawable panel(Context c, int strokeColor) {
        return box(0xE60A1322, strokeColor, Math.max(1, dp(c, 1)), dp(c, 14));
    }

    public static TextView text(Context c, String s, float sizeSp, int color, Typeface tf) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sizeSp);
        t.setTextColor(color);
        t.setTypeface(tf);
        t.setIncludeFontPadding(false);
        return t;
    }

    public static TextView label(Context c, String s) {
        TextView t = text(c, s, 10f, DIM, MONO);
        t.setLetterSpacing(0.18f);
        return t;
    }

    public static TextView chip(Context c, String s, int color) {
        TextView t = text(c, s, 10.5f, color, MONO_B);
        t.setLetterSpacing(0.08f);
        t.setPadding(dp(c, 9), dp(c, 5), dp(c, 9), dp(c, 5));
        t.setBackground(box(0x1AFFFFFF, color, Math.max(1, dp(c, 1)), dp(c, 20)));
        return t;
    }

    /** Pulsante "HUD" con angoli netti, bordo ciano e ripple. */
    public static TextView button(Context c, String s, int accent, boolean filled) {
        TextView t = text(c, s, 14f, filled ? BG : accent, MONO_B);
        t.setLetterSpacing(0.12f);
        t.setGravity(Gravity.CENTER);
        t.setPadding(dp(c, 18), dp(c, 15), dp(c, 18), dp(c, 15));
        GradientDrawable base = box(filled ? accent : 0x00000000, accent, Math.max(1, dp(c, 1)), dp(c, 4));
        ColorStateList rip = ColorStateList.valueOf(0x40FFFFFF);
        t.setBackground(new RippleDrawable(rip, base, null));
        t.setClickable(true);
        t.setFocusable(true);
        return t;
    }

    public static View divider(Context c) {
        View v = new View(c);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Math.max(1, dp(c, 1)));
        v.setLayoutParams(lp);
        v.setBackgroundColor(0x2600E5FF);
        return v;
    }

    public static View vspace(Context c, int dp) {
        View v = new View(c);
        v.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(c, dp)));
        return v;
    }

    public static LinearLayout.LayoutParams lp(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    /**
     * Compensa le system bar (Android 15 forza l'edge-to-edge): aggiunge gli
     * inset al padding gia' impostato sul contenuto.
     */
    public static void applyInsets(View root, final View content) {
        final int l = content.getPaddingLeft();
        final int t = content.getPaddingTop();
        final int r = content.getPaddingRight();
        final int b = content.getPaddingBottom();
        root.setOnApplyWindowInsetsListener(new android.view.View.OnApplyWindowInsetsListener() {
            @Override
            public android.view.WindowInsets onApplyWindowInsets(View v, android.view.WindowInsets insets) {
                int top, bottom, left, right;
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    android.graphics.Insets sb = insets.getInsets(
                            android.view.WindowInsets.Type.systemBars());
                    top = sb.top; bottom = sb.bottom; left = sb.left; right = sb.right;
                } else {
                    top = insets.getSystemWindowInsetTop();
                    bottom = insets.getSystemWindowInsetBottom();
                    left = insets.getSystemWindowInsetLeft();
                    right = insets.getSystemWindowInsetRight();
                }
                content.setPadding(l + left, t + top, r + right, b + bottom);
                return insets;
            }
        });
    }

    public static int alpha(int color, int a) {
        return Color.argb(a, Color.red(color), Color.green(color), Color.blue(color));
    }

    // ---------------------------------------------------------------- font scaling

    /** Larghezza di riferimento in dp per il scaling dei font. */
    private static final int REF_WIDTH_DP = 360;

    /**
     * Calcola il fattore di scaling dei font basato sulla larghezza dello
     * schermo. Schermo piccolo → font più piccolo, schermo grande → font più
     * grande. La scala è clampata tra 0.85 e 1.4 per evitare estremi.
     */
    public static float fontScale(Context c) {
        float w = c.getResources().getDisplayMetrics().widthPixels
                / c.getResources().getDisplayMetrics().density;
        float scale = w / REF_WIDTH_DP;
        return Math.max(0.85f, Math.min(1.4f, scale));
    }

    /**
     * Converte un valore SP base in un valore SP scalato per lo schermo
     * attuale. Usa `Ui.sp(c, 14f)` invece di `14f` direttamente.
     */
    public static float sp(Context c, float base) {
        return base * fontScale(c);
    }

    /**
     * TextView con testo scalato dinamicamente. Sostituisce Ui.text(c, s, size, ...).
     */
    public static TextView textS(Context c, String s, float baseSize, int color, Typeface tf) {
        return text(c, s, sp(c, baseSize), color, tf);
    }

    /**
     * Label con testo scalato dinamicamente.
     */
    public static TextView labelS(Context c, String s) {
        TextView t = textS(c, s, 10f, DIM, MONO);
        t.setLetterSpacing(0.18f);
        return t;
    }

    /**
     * Chip con testo scalato dinamicamente.
     */
    public static TextView chipS(Context c, String s, int color) {
        TextView t = textS(c, s, 10.5f, color, MONO_B);
        t.setLetterSpacing(0.08f);
        t.setPadding(dp(c, 9), dp(c, 5), dp(c, 9), dp(c, 5));
        t.setBackground(box(0x1AFFFFFF, color, Math.max(1, dp(c, 1)), dp(c, 20)));
        return t;
    }

    /**
     * Pulsante "HUD" con testo scalato dinamicamente.
     */
    public static TextView buttonS(Context c, String s, int accent, boolean filled) {
        TextView t = textS(c, s, 14f, filled ? BG : accent, MONO_B);
        t.setLetterSpacing(0.12f);
        t.setGravity(Gravity.CENTER);
        t.setPadding(dp(c, 18), dp(c, 15), dp(c, 18), dp(c, 15));
        GradientDrawable base = box(filled ? accent : 0x00000000, accent,
                Math.max(1, dp(c, 1)), dp(c, 4));
        ColorStateList rip = ColorStateList.valueOf(0x40FFFFFF);
        t.setBackground(new RippleDrawable(rip, base, null));
        t.setClickable(true);
        t.setFocusable(true);
        return t;
    }
}
