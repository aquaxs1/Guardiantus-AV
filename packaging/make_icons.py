"""Render the Guardiantus AV shield mark to .ico (Windows) and .icns (macOS).

Draws the same shield + "G/A" glyph as ``guardiantus/ui/static/img/logo.svg``
directly with Pillow, at each size, rather than depending on an SVG
rasterizer that may not be present on the machine doing the build.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent / "icons"
OUT.mkdir(exist_ok=True)

# Same viewBox as the SVG mark, so points line up if anyone compares them.
VB = 200.0
SHIELD = [
    (100, 20), (122, 34), (148, 42), (174, 44), (174, 104),
    (174, 141), (143, 170), (100, 184), (57, 170), (26, 141),
    (26, 104), (26, 44), (52, 42), (78, 34),
]


def render(size: int, dark: bool) -> Image.Image:
    """Supersample at 4x and downscale for clean anti-aliased edges."""
    scale = 4
    canvas = size * scale
    img = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    def pt(x: float, y: float) -> tuple[float, float]:
        return (x / VB) * canvas, (y / VB) * canvas

    fg = (244, 244, 246, 255) if dark else (22, 22, 25, 255)
    stroke_w = max(2, round(canvas * 0.035))

    shield_pts = [pt(x, y) for x, y in SHIELD]
    draw.line(shield_pts + [shield_pts[0]], fill=fg, width=stroke_w, joint="curve")

    # A simplified "G" (arc) and "A" (two strokes + crossbar), bold enough to
    # read at 16px, unlike the full SVG glyph.
    g_box = [pt(72, 62)[0], pt(72, 62)[1], pt(128, 132)[0], pt(128, 132)[1]]
    draw.arc(g_box, start=40, end=310, fill=fg, width=stroke_w)
    draw.line([pt(118, 100), pt(140, 100)], fill=fg, width=stroke_w)

    draw.line([pt(96, 148), pt(119, 76)], fill=fg, width=stroke_w)
    draw.line([pt(142, 148), pt(119, 76)], fill=fg, width=stroke_w)
    draw.line([pt(104, 124), pt(134, 124)], fill=fg, width=stroke_w)

    return img.resize((size, size), Image.LANCZOS)


def build_ico() -> Path:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    base = render(256, dark=False)
    path = OUT / "guardiantus.ico"
    base.save(path, format="ICO", sizes=[(s, s) for s in sizes])
    return path


def build_png_set(dark: bool, suffix: str, sizes: list[int]) -> list[Path]:
    paths = []
    for size in sizes:
        path = OUT / f"icon_{suffix}_{size}.png"
        render(size, dark=dark).save(path)
        paths.append(path)
    return paths


def build_icns() -> Path | None:
    """Multi-resolution .icns for macOS, via the pure-Python icnsutil package."""
    try:
        import icnsutil
    except ImportError:
        print("icnsutil not installed -- skipping .icns (PyInstaller will use a default icon on macOS)")
        return None

    # icnsutil only recognises Apple's own icon side lengths.
    pngs = build_png_set(dark=False, suffix="mac", sizes=[16, 32, 128, 256, 512, 1024])
    path = OUT / "guardiantus.icns"
    writer = icnsutil.IcnsFile()
    for png in pngs:
        writer.add_media(file=str(png))
    writer.write(str(path))
    return path


if __name__ == "__main__":
    ico = build_ico()
    print("wrote", ico)
    icns = build_icns()
    if icns:
        print("wrote", icns)
    # A square PNG is also handy: favicon-quality app icon for Linux desktop
    # entries and for the site itself if ever needed.
    for stale in OUT.glob("icon_mac_*.png"):
        stale.unlink()
    render(512, dark=False).save(OUT / "guardiantus.png")
    print("wrote", OUT / "guardiantus.png")
