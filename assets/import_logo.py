#!/usr/bin/env python3
"""Turn any image file into the complete Br1zz Security icon set.

    python3 assets/import_logo.py path/to/logo.png [--install]

Loads through GdkPixbuf, so it accepts PNG, JPEG, WebP, TIFF, BMP and - where a
loader is present - SVG. Non-square input is centre-cropped to a square first,
because icon themes assume square art and a squashed logo looks broken in a
taskbar.

With --install it also copies the results into ~/.local/share/icons/hicolor and
refreshes the icon cache, which is everything needed for the desktop entry and
the app window to pick the new icon up.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import gi

gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf, GLib  # noqa: E402

SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
ICON_NAME = "br1zz-security"
HICOLOR = Path.home() / ".local/share/icons/hicolor"


def _content_bbox(pixbuf: GdkPixbuf.Pixbuf, threshold: int = 8):
    """Bounding box of pixels that are not effectively transparent."""
    if not pixbuf.get_has_alpha():
        return None
    width, height = pixbuf.get_width(), pixbuf.get_height()
    stride, channels = pixbuf.get_rowstride(), pixbuf.get_n_channels()
    data = pixbuf.get_pixels()

    top, bottom = None, None
    left, right = width, -1
    for y in range(height):
        row = data[y * stride: y * stride + width * channels]
        alpha = row[3::channels]
        if max(alpha) <= threshold:
            continue
        if top is None:
            top = y
        bottom = y
        # narrow the horizontal bounds using this row
        for x in range(width):
            if alpha[x] > threshold:
                if x < left:
                    left = x
                break
        for x in range(width - 1, -1, -1):
            if alpha[x] > threshold:
                if x > right:
                    right = x
                break

    if top is None or right < left:
        return None
    return left, top, right - left + 1, bottom - top + 1


def load_square(path: Path) -> GdkPixbuf.Pixbuf:
    """Load an image and return it as a square, artwork centred.

    Transparent margins are trimmed first and the result is padded to a square
    rather than centre-cropped. Cropping a wide logo throws away its edges;
    padding keeps the whole mark and lets it fill as much of the icon as the
    aspect ratio allows.
    """
    try:
        pixbuf = GdkPixbuf.Pixbuf.new_from_file(str(path))
    except GLib.Error as exc:
        raise SystemExit(f"cannot read {path}: {exc.message}")

    original = (pixbuf.get_width(), pixbuf.get_height())
    box = _content_bbox(pixbuf)
    if box is not None and (box[2], box[3]) != original:
        pixbuf = GdkPixbuf.Pixbuf.new_subpixbuf(pixbuf, *box)
        print(f"  trimmed transparent margin: {original[0]}x{original[1]}"
              f" -> {box[2]}x{box[3]}")

    width, height = pixbuf.get_width(), pixbuf.get_height()
    if width == height:
        return pixbuf

    if pixbuf.get_has_alpha():
        side = max(width, height)
        canvas = GdkPixbuf.Pixbuf.new(pixbuf.get_colorspace(), True,
                                      pixbuf.get_bits_per_sample(), side, side)
        canvas.fill(0x00000000)
        pixbuf.copy_area(0, 0, width, height, canvas,
                         (side - width) // 2, (side - height) // 2)
        print(f"  padded to square: {side}x{side}")
        return canvas

    # No alpha to pad with, so fall back to a centre crop.
    side = min(width, height)
    print(f"  centre-cropped to {side}x{side}")
    return GdkPixbuf.Pixbuf.new_subpixbuf(
        pixbuf, (width - side) // 2, (height - side) // 2, side, side
    )


def _ensure_alpha(pixbuf: GdkPixbuf.Pixbuf) -> GdkPixbuf.Pixbuf:
    return pixbuf if pixbuf.get_has_alpha() else pixbuf.add_alpha(False, 0, 0, 0)


def _rebuild(pixbuf: GdkPixbuf.Pixbuf, data: bytearray) -> GdkPixbuf.Pixbuf:
    return GdkPixbuf.Pixbuf.new_from_bytes(
        GLib.Bytes.new(bytes(data)), pixbuf.get_colorspace(), True,
        pixbuf.get_bits_per_sample(), pixbuf.get_width(), pixbuf.get_height(),
        pixbuf.get_rowstride(),
    )


def knockout_background(pixbuf: GdkPixbuf.Pixbuf, tolerance: int = 40) -> GdkPixbuf.Pixbuf:
    """Make the outer background transparent.

    Flood-fills inward from the edges rather than replacing every pixel of the
    background colour globally, so a colour that also appears *inside* the
    artwork is left alone.
    """
    from collections import deque

    pixbuf = _ensure_alpha(pixbuf)
    width, height = pixbuf.get_width(), pixbuf.get_height()
    stride, channels = pixbuf.get_rowstride(), pixbuf.get_n_channels()
    data = bytearray(pixbuf.get_pixels())

    def rgb(x: int, y: int) -> tuple[int, int, int]:
        off = y * stride + x * channels
        return data[off], data[off + 1], data[off + 2]

    # Seed colour: the most common of the four corners.
    corners = [rgb(0, 0), rgb(width - 1, 0), rgb(0, height - 1), rgb(width - 1, height - 1)]
    seed = max(set(corners), key=corners.count)
    limit = tolerance * tolerance

    def matches(x: int, y: int) -> bool:
        r, g, b = rgb(x, y)
        dr, dg, db = r - seed[0], g - seed[1], b - seed[2]
        return dr * dr + dg * dg + db * db <= limit

    seen = bytearray(width * height)
    queue = deque()
    for x in range(width):
        for y in (0, height - 1):
            if not seen[y * width + x] and matches(x, y):
                seen[y * width + x] = 1
                queue.append((x, y))
    for y in range(height):
        for x in (0, width - 1):
            if not seen[y * width + x] and matches(x, y):
                seen[y * width + x] = 1
                queue.append((x, y))

    cleared = 0
    while queue:
        x, y = queue.popleft()
        data[y * stride + x * channels + 3] = 0
        cleared += 1
        for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
            if 0 <= nx < width and 0 <= ny < height and not seen[ny * width + nx]:
                if matches(nx, ny):
                    seen[ny * width + nx] = 1
                    queue.append((nx, ny))

    print(f"  background knocked out: {cleared} px "
          f"({100 * cleared / (width * height):.0f}%), seed rgb{seed}")
    return _rebuild(pixbuf, data)


def round_corners(pixbuf: GdkPixbuf.Pixbuf, percent: float = 22.0) -> GdkPixbuf.Pixbuf:
    """Apply a rounded-square alpha mask, antialiased at the arc."""
    pixbuf = _ensure_alpha(pixbuf)
    width, height = pixbuf.get_width(), pixbuf.get_height()
    stride, channels = pixbuf.get_rowstride(), pixbuf.get_n_channels()
    data = bytearray(pixbuf.get_pixels())

    radius = min(width, height) * percent / 100.0
    centres = ((radius, radius), (width - radius, radius),
               (radius, height - radius), (width - radius, height - radius))

    for cx, cy in centres:
        x0, x1 = int(min(cx, radius)) - 1, int(max(cx, radius)) + 1
        y0, y1 = int(min(cy, radius)) - 1, int(max(cy, radius)) + 1
        for y in range(max(0, y0 - int(radius)), min(height, y1 + int(radius))):
            for x in range(max(0, x0 - int(radius)), min(width, x1 + int(radius))):
                # only the region outside the arc's quadrant matters
                if (x < cx) != (cx < width / 2) or (y < cy) != (cy < height / 2):
                    continue
                dx, dy = x + 0.5 - cx, y + 0.5 - cy
                dist = (dx * dx + dy * dy) ** 0.5
                if dist <= radius - 0.5:
                    continue
                off = y * stride + x * channels + 3
                if dist >= radius + 0.5:
                    data[off] = 0
                else:  # one-pixel feather along the arc
                    coverage = radius + 0.5 - dist
                    data[off] = int(data[off] * max(0.0, min(1.0, coverage)))

    print(f"  corners rounded at {percent:.0f}% (radius {radius:.0f}px)")
    return _rebuild(pixbuf, data)


def render_set(source: Path, outdir: Path, knockout: bool = False,
               rounded: float | None = None) -> list[Path]:
    pixbuf = load_square(source)
    # Both effects run at full resolution, before downscaling, so the edges
    # they create get the same antialiasing as the rest of the artwork.
    if knockout:
        pixbuf = knockout_background(pixbuf)
    if rounded:
        pixbuf = round_corners(pixbuf, rounded)
    print(f"  source {source.name}: {pixbuf.get_width()}x{pixbuf.get_height()}"
          f"{' (cropped square)' if pixbuf.get_width() != pixbuf.get_height() else ''}")
    outdir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for size in SIZES:
        # HYPER is the best downscaler gdk-pixbuf offers; icons are downscaled
        # far more often than upscaled, and the difference is visible at 16px.
        interp = (GdkPixbuf.InterpType.HYPER if size <= pixbuf.get_width()
                  else GdkPixbuf.InterpType.BILINEAR)
        scaled = pixbuf.scale_simple(size, size, interp)
        target = outdir / f"{ICON_NAME}-{size}.png"
        scaled.savev(str(target), "png", [], [])
        written.append(target)
        print(f"  {target.name}")
    return written


def install(files: list[Path]) -> None:
    for path in files:
        size = path.stem.rsplit("-", 1)[-1]
        dest = HICOLOR / f"{size}x{size}" / "apps"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest / f"{ICON_NAME}.png")

    # A scalable SVG in the theme wins over PNGs for any size without an exact
    # match, so a stale one from a previous logo would shadow these.
    stale = HICOLOR / "scalable" / "apps" / f"{ICON_NAME}.svg"
    if stale.exists():
        stale.unlink()
        print(f"  removed stale {stale}")

    if shutil.which("gtk-update-icon-cache"):
        subprocess.run(["gtk-update-icon-cache", "-f", "-t", str(HICOLOR)],
                       check=False, capture_output=True)
    print(f"  installed into {HICOLOR}")
    print("  restart the app to pick up the new icon")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Build the icon set from a logo image")
    parser.add_argument("source", type=Path, help="logo image (png/jpg/webp/svg)")
    parser.add_argument("--install", action="store_true",
                        help="also install into ~/.local/share/icons/hicolor")
    parser.add_argument("-o", "--outdir", type=Path,
                        default=Path(__file__).resolve().parent / "icons",
                        help="where to write the PNGs")
    parser.add_argument("--knockout", action="store_true",
                        help="make the flat outer background transparent")
    parser.add_argument("--round", dest="rounded", type=float, nargs="?", const=22.0,
                        metavar="PERCENT",
                        help="round the corners (default 22%% of the icon size)")
    args = parser.parse_args(argv[1:])

    if not args.source.is_file():
        print(f"error: no such file: {args.source}", file=sys.stderr)
        return 1

    files = render_set(args.source, args.outdir,
                       knockout=args.knockout, rounded=args.rounded)
    if args.install:
        install(files)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
