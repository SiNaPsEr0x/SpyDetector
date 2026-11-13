#!/usr/bin/env python3
"""
Genera docs/preview.png (banner del README) in modo deterministico.

Perche' uno script: l'immagine precedente era un SVG disegnato a mano con
coordinate sparse, quindi gauge, card e pulsante si sovrapponevano e la colonna
di sinistra non era centrata sull'anello. Qui tutto parte da una griglia:

  margine 64 · gutter 32 · due colonne (testo 636 px, mockup 376 px)

Si disegna a 2x e si ridimensiona (anti-aliasing), poi si salva in PNG cosi'
GitHub la mostra identica su desktop e mobile.

    python3 scripts/make-preview.py
"""
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "preview.png")

W, H = 1200, 675
SS = 2                     # supersampling
FONTS = "/usr/share/fonts/truetype/dejavu"

# --- palette (identica alla UI dell'app) -----------------------------------
BG = (4, 7, 14)
PANEL = (10, 19, 34)
CYAN = (0, 229, 255)
OK = (0, 255, 163)
WARN = (255, 196, 0)
ORANGE = (255, 138, 61)
CRIT = (255, 59, 92)
TXT = (230, 241, 255)
DIM = (116, 135, 156)
FAINT = (86, 104, 125)
MONO_LIVE = (124, 247, 208)

# --- griglia ---------------------------------------------------------------
M = 64                     # margine
GUT = 32                   # gutter
LEFT_X = M
LEFT_W = 636
PHONE_X = LEFT_X + LEFT_W + GUT          # 732
PHONE_W = W - M - PHONE_X                # 404
PHONE_Y = 52
PHONE_H = H - 2 * PHONE_Y                # 571


def s(v):
    return int(round(v * SS))


def font(name, size):
    return ImageFont.truetype(os.path.join(FONTS, name), s(size))


def track(draw, xy, text, f, fill, spacing=0.0, anchor_left=True):
    """Testo con letter-spacing manuale (Pillow non lo supporta)."""
    x, y = s(xy[0]), s(xy[1])
    for ch in text:
        draw.text((x, y), ch, font=f, fill=fill)
        adv = draw.textlength(ch, font=f)
        x += adv + s(spacing) if spacing else adv
    return x


def track_width(draw, text, f, spacing=0.0):
    w = sum(draw.textlength(c, font=f) for c in text)
    return w + spacing * (len(text) - 1) * SS


def chip(draw, x, y, label, f, color, pad_x=14, pad_y=9, radius=6, spacing=1.2):
    tw = track_width(draw, label, f, spacing) / SS      # unita' logiche
    w = tw + 2 * pad_x
    h = f.size / SS + 2 * pad_y
    draw.rounded_rectangle([s(x), s(y), s(x + w), s(y + h)], radius=s(radius),
                           fill=(10, 25, 38), outline=color + (90,), width=s(1.2))
    track(draw, (x + pad_x, y + pad_y + 3), label, f, color, spacing)
    return w, h


def rounded(draw, box, radius, fill=None, outline=None, width=1):
    draw.rounded_rectangle([s(box[0]), s(box[1]), s(box[2]), s(box[3])],
                           radius=s(radius), fill=fill, outline=outline, width=s(width))


def arc(draw, center, radius, start, end, color, width):
    """Arco su layer separato (4x) per bordi puliti."""
    R = s(radius)
    pad = s(width) + s(4)
    size = 2 * (R + pad)
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    d.arc([pad, pad, size - pad, size - pad], start, end, fill=color, width=s(width))
    cx, cy = s(center[0]), s(center[1])
    return layer, (cx - size // 2, cy - size // 2)


def radial_glow(cx, cy, radius):
    """Layer RGBA con falloff radiale morbido (calcolato su una griglia piccola
    e poi ingrandita: nessun artefatto a bande)."""
    small = 220
    layer = Image.new("RGBA", (small, small), (0, 0, 0, 0))
    px = layer.load()
    for y in range(small):
        for x in range(small):
            dx = (x - small / 2) / (small / 2)
            dy = (y - small / 2) / (small / 2)
            r = min(1.0, (dx * dx + dy * dy) ** 0.5)
            a = int(150 * (1 - r) ** 2.4) if r < 1 else 0
            # RGB sempre definito, anche dove alpha = 0: altrimenti l'interpolazione
            # del resize mescola il nero dei pixel trasparenti e crea aloni scuri.
            px[x, y] = (10 + int(6 * (1 - r)), 40 + int(45 * (1 - r)),
                        58 + int(60 * (1 - r)), a)
    return layer.resize((radius * 2, radius * 2), Image.BICUBIC)


def build():
    img = Image.new("RGB", (s(W), s(H)), BG)
    d = ImageDraw.Draw(img, "RGBA")

    # --- sfondo: bagliore (gradiente radiale vero, niente banding) --------
    glow = radial_glow(s(660), s(-60), s(950))          # layer quadrato
    base = img.convert("RGBA")
    # il bagliore e' fuori centro in alto: lo incollo con offset negativo
    tmp = Image.new("RGBA", base.size, (0, 0, 0, 0))
    tmp.paste(glow, (s(660) - glow.width // 2, s(-60) - glow.height // 2), glow)
    img = Image.alpha_composite(base, tmp).convert("RGB")
    d = ImageDraw.Draw(img, "RGBA")

    hz = s(H) * 0.86
    for i in range(9):                       # linee orizzontali in prospettiva
        t = (i / 9.0) ** 1.9
        y = hz + (s(H) - hz) * t
        d.line([0, y, s(W), y], fill=CYAN + (18,), width=s(1))
    for i in range(-7, 8):                   # linee verticali convergenti
        x_end = s(W / 2) + i * s(W / 6.2)
        d.line([s(W / 2), hz, x_end, s(H)], fill=CYAN + (14,), width=s(1))
    d.line([0, hz, s(W), hz], fill=CYAN + (40,), width=s(1.5))

    # ======================================================================
    # COLONNA SINISTRA
    # ======================================================================
    mono_s = font("DejaVuSansMono.ttf", 13)
    track(d, (LEFT_X, 132), "ANDROID SECURITY SCANNER  //  ON-DEVICE", mono_s,
          DIM, spacing=2.6)

    f_logo = font("DejaVuSans-Bold.ttf", 62)
    x = track(d, (LEFT_X, 158), "SPY", f_logo, CYAN)
    x = track(d, (x / SS, 158), "·", f_logo, OK)
    track(d, (x / SS + 2, 158), "DETECTOR", f_logo, TXT)

    f_sub = font("DejaVuSans.ttf", 19)
    d.text((s(LEFT_X), s(256)), "Check totale del telefono: root, accessibilità,",
           font=f_sub, fill=(185, 199, 214))
    d.text((s(LEFT_X), s(282)), "stalkerware, permessi, WhatsApp modificato.",
           font=f_sub, fill=(185, 199, 214))

    # --- chip (allineate sulla stessa baseline) ---------------------------
    f_chip = font("DejaVuSansMono-Bold.ttf", 12)
    chips = [("NESSUN PERMESSO INTERNET", OK),
             ("APK FIRMATO v2+v3", CYAN),
             ("BUILD SU GITHUB ACTIONS", ORANGE)]
    cx, cy = LEFT_X, 330
    for label, color in chips:
        w, h = chip(d, cx, cy, label, f_chip, color)
        cx += w + 10

    # --- elenco aree ------------------------------------------------------
    f_row = font("DejaVuSans.ttf", 17)
    f_row_b = font("DejaVuSans-Bold.ttf", 17)
    rows = [
        ("Sistema", "root · bootloader · SELinux · patch", OK),
        ("Accessibilità", "servizi attivi · app camuffate", CRIT),
        ("Persistenza", "notifiche · admin · tastiere · VPN", WARN),
        ("Messaggistica", "client modificati · sessioni collegate", CYAN),
    ]
    y = 396
    for name, desc, color in rows:
        d.ellipse([s(LEFT_X), s(y + 7), s(LEFT_X + 9), s(y + 16)], fill=color)
        d.text((s(LEFT_X + 24), s(y)), name, font=f_row_b, fill=TXT)
        name_w = d.textlength(name, font=f_row_b) / SS
        d.text((s(LEFT_X + 34 + name_w), s(y + 1)), "— " + desc, font=f_row, fill=DIM)
        y += 38

    # --- riga finale: comando build ---------------------------------------
    f_code = font("DejaVuSansMono.ttf", 14)
    box_bottom = PHONE_Y + PHONE_H          # 623: stesso bordo del mockup
    box_top = box_bottom - 34
    box_right = min(LEFT_X + 300, PHONE_X - GUT)
    rounded(d, (LEFT_X, box_top, box_right, box_bottom), 6,
            fill=(8, 15, 26), outline=CYAN + (70,), width=1.2)
    d.text((s(LEFT_X + 14), s(box_top + 11)), "./build.sh", font=f_code, fill=OK)
    d.text((s(LEFT_X + 114), s(box_top + 11)), "→  APK firmato in 10 s",
           font=f_code, fill=DIM)

    # ======================================================================
    # MOCKUP DELL'APP (colonna destra)
    # ======================================================================
    px0, py0 = PHONE_X, PHONE_Y
    px1, py1 = px0 + PHONE_W, py0 + PHONE_H
    rounded(d, (px0, py0, px1, py1), 26, fill=PANEL + (255,),
            outline=CYAN + (46,), width=1.4)

    pad = 22
    ix0, ix1 = px0 + pad, px1 - pad
    inner_w = ix1 - ix0

    # header dell'app
    f_app = font("DejaVuSans-Bold.ttf", 17)
    ax = px0 + pad + 4
    ax = track(d, (ax, py0 + 26), "SPY", f_app, CYAN) / SS
    ax = track(d, (ax, py0 + 26), "·", f_app, OK) / SS
    track(d, (ax + 1, py0 + 26), "DETECTOR", f_app, TXT)
    f_ver = font("DejaVuSansMono.ttf", 10)
    vw = track_width(d, "v1.0.0", f_ver, 0.6)
    rounded(d, (ix1 - vw / SS - 16, py0 + 24, ix1, py0 + 44), 5,
            fill=(8, 20, 32), outline=CYAN + (80,), width=1)
    track(d, (ix1 - vw / SS - 8, py0 + 29), "v1.0.0", f_ver, CYAN, 0.6)

    # --- gauge ------------------------------------------------------------
    gc = ((px0 + px1) / 2, py0 + 152)          # centro anello
    g_r = 80
    d.ellipse([s(gc[0] - g_r), s(gc[1] - g_r), s(gc[0] + g_r), s(gc[1] + g_r)],
              outline=(18, 49, 74), width=s(11))
    progress = 0.22
    layer, pos = arc(d, gc, g_r, -90, -90 + 360 * progress, WARN, 11)
    img.paste(layer, pos, layer)
    d = ImageDraw.Draw(img, "RGBA")

    # tacche decorative
    for i in range(36):
        import math
        a = math.radians(i * 10 - 90)
        r1, r2 = g_r - 6, g_r - 11
        d.line([s(gc[0] + math.cos(a) * r1), s(gc[1] + math.sin(a) * r1),
                s(gc[0] + math.cos(a) * r2), s(gc[1] + math.sin(a) * r2)],
               fill=CYAN + (34,), width=s(1))

    f_score = font("DejaVuSans-Bold.ttf", 46)
    f_lbl = font("DejaVuSansMono.ttf", 9)
    score = "12"
    sw = d.textlength(score, font=f_score) / SS
    d.text((s(gc[0]) - d.textlength(score, font=f_score) / 2, s(gc[1] - 22)),
           score, font=f_score, fill=WARN)
    idx = "RISK INDEX"
    track(d, (gc[0] - track_width(d, idx, f_lbl, 1.8) / SS / 2, gc[1] + 30),
          idx, f_lbl, DIM, 1.8)
    f_verdict = font("DejaVuSans-Bold.ttf", 13)
    verdict = "MEDIO"
    d.text((s(gc[0]) - d.textlength(verdict, font=f_verdict) / 2, s(gc[1] - 56)),
           verdict, font=f_verdict, fill=TXT)

    # --- contatori (4 card, stessa larghezza, stesso gutter) --------------
    f_num = font("DejaVuSans-Bold.ttf", 19)
    f_cap = font("DejaVuSansMono.ttf", 8)
    counters = [("0", "CRITICI", CRIT), ("2", "RISCHI", WARN),
                ("1", "ATTENZ.", ORANGE), ("21", "OK", OK)]
    cg = 6
    cw = (inner_w - cg * 3) / 4
    cy0, ch = gc[1] + g_r + 22, 54
    for i, (num, cap, color) in enumerate(counters):
        x0 = ix0 + i * (cw + cg)
        rounded(d, (x0, cy0, x0 + cw, cy0 + ch), 8, fill=(8, 17, 29),
                outline=color + (80,), width=1)
        d.text((s(x0 + cw / 2) - d.textlength(num, font=f_num) / 2, s(cy0 + 8)),
               num, font=f_num, fill=color)
        track(d, (x0 + cw / 2 - track_width(d, cap, f_cap, 1.0) / SS / 2, cy0 + 33),
              cap, f_cap, DIM, 1.0)

    # --- due card "area" ---------------------------------------------------
    f_area = font("DejaVuSans-Bold.ttf", 13)
    f_areasub = font("DejaVuSans.ttf", 11)
    f_areachip = font("DejaVuSansMono-Bold.ttf", 10)
    areas = [("ACCESSIBILITÀ", "1 punto da verificare", CRIT, "1"),
             ("PERSISTENZA", "livello notifiche", WARN, "2")]
    ay = cy0 + ch + 14
    for name, sub, color, count in areas:
        ah = 46
        rounded(d, (ix0, ay, ix1, ay + ah), 8, fill=(8, 17, 29),
                outline=CYAN + (30,), width=1)
        d.rounded_rectangle([s(ix0 + 10), s(ay + 12), s(ix0 + 13), s(ay + 34)],
                            radius=s(2), fill=color)
        d.text((s(ix0 + 22), s(ay + 8)), name, font=f_area, fill=TXT)
        d.text((s(ix0 + 22), s(ay + 24)), sub, font=f_areasub, fill=DIM)
        cw2 = track_width(d, count, f_areachip, 1.0) / SS
        bxx = ix1 - max(cw2 + 22, 30)
        rounded(d, (bxx, ay + 13, ix1 - 10, ay + 35), 11,
                fill=(14, 26, 40), outline=color + (130,), width=1)
        track(d, (bxx + (max(cw2 + 22, 30) - 10 - cw2) / 2, ay + 19),
              count, f_areachip, color, 1.0)
        ay += ah + 10

    # --- pannello log: occupa lo spazio rimasto, senza vuoti --------------
    f_logh = font("DejaVuSansMono.ttf", 9)
    f_logl = font("DejaVuSansMono.ttf", 9.5)
    ly0 = ay + 6
    ly1 = py1 - pad - 40 - 34
    rounded(d, (ix0, ly0, ix1, ly1), 9, fill=(7, 14, 24), outline=CYAN + (34,), width=1)
    track(d, (ix0 + 12, ly0 + 10), "LIVE SCAN LOG", f_logh, DIM, 1.6)
    lx = ix0 + 12
    for i, (txt, col) in enumerate([
            ("• Integrita' di sistema", OK),
            ("• Accessibilita' attiva", CRIT),
            ("• Messaggistica / client", CYAN)]):
        d.text((s(lx), s(ly0 + 28 + i * 14)), txt, font=f_logl, fill=col)

    # --- CTA (allineata ai bordi interni) ---------------------------------
    f_cta = font("DejaVuSansMono-Bold.ttf", 11)
    cta = "AVVIA SCANSIONE COMPLETA"
    by0 = py1 - pad - 40
    d.rounded_rectangle([s(ix0), s(by0), s(ix1), s(by0 + 40)], radius=s(5), fill=CYAN)
    ctaw = track_width(d, cta, f_cta, 1.0)
    track(d, ((ix0 + ix1) / 2 - ctaw / SS / 2, by0 + 14), cta, f_cta, (4, 7, 14), 1.0)

    # --- log riga singola sopra la CTA ------------------------------------
    # --- cornice esterna: etichetta in alto ---------------------------------
    f_tag = font("DejaVuSansMono.ttf", 9)
    track(d, (px0 + pad, py0 + 8), "", f_tag, DIM)

    img = img.resize((W, H), Image.LANCZOS)
    img.save(OUT, optimize=True)
    print("scritto %s (%dx%d, %.1f KB)" % (OUT, W, H, os.path.getsize(OUT) / 1024))


if __name__ == "__main__":
    build()
