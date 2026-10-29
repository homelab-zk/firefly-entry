# Draws the app icon (white receipt on the app's accent blue) at the sizes a PWA needs.
# The receipt stays inside the central 60% so the same image works as a maskable icon.
import io, sys, tarfile
from PIL import Image, ImageDraw

BG, FG, INK = (79, 140, 255), (255, 255, 255), (79, 140, 255)


def icon(n: int) -> Image.Image:
    S = 4 * n  # supersample, then shrink for smooth edges
    im = Image.new("RGB", (S, S), BG)
    d = ImageDraw.Draw(im)
    w, h = 0.40 * S, 0.54 * S
    x0, y0 = (S - w) / 2, (S - h) / 2
    x1, y1 = x0 + w, y0 + h
    teeth, tooth = 6, w / 6
    zig = [(x1, y1)]
    for i in range(teeth):
        zig += [(x1 - (i + 0.5) * tooth, y1 - tooth * 0.5), (x1 - (i + 1) * tooth, y1)]
    d.polygon([(x0, y0), (x1, y0)] + zig + [(x0, y1)], fill=FG)
    lw, pad = 0.035 * S, 0.07 * S
    for k, frac in enumerate((0.8, 0.6, 0.8, 0.45)):
        y = y0 + pad + k * 0.075 * S
        d.rounded_rectangle([x0 + pad, y, x0 + pad + (w - 2 * pad) * frac, y + lw], radius=lw / 2, fill=INK)
    y = y0 + pad + 4 * 0.075 * S + 0.02 * S
    d.rounded_rectangle([x0 + pad, y, x1 - pad, y + lw * 1.4], radius=lw / 2, fill=INK)  # total line
    return im.resize((n, n), Image.LANCZOS)


buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tar:
    for name, n in (("icon-192.png", 192), ("icon-512.png", 512), ("apple-touch-icon.png", 180), ("favicon-32.png", 32)):
        b = io.BytesIO()
        icon(n).save(b, "PNG", optimize=True)
        info = tarfile.TarInfo(name)
        info.size = b.tell()
        b.seek(0)
        tar.addfile(info, b)
sys.stdout.buffer.write(buf.getvalue())
