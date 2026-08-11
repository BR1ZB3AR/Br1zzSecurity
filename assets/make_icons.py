#!/usr/bin/env python3
"""Render the Br1zz Security icon to PNG at every size the icon theme wants.

Why not just ship the SVG: gdk-pixbuf's SVG loader is not registered on every
system (it is missing from the loader cache on the machine this was built on),
and GTK then refuses the icon entirely. PNGs always load. The SVG is still
shipped for `scalable/`, but the PNGs are what make the icon reliably appear.

Drawing with cairo rather than converting the SVG keeps the two in sync from one
description and avoids depending on an SVG rasteriser at build time.

    python3 assets/make_icons.py [outdir]
"""

from __future__ import annotations

import sys
from pathlib import Path

import cairo

SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
GRID = 128.0  # the coordinate system the artwork is designed in


def shield_path(ctx: cairo.Context) -> None:
    """A faceted shield: straight edges and hard angles, no classic curves."""
    ctx.move_to(64, 6)
    ctx.line_to(110, 23)
    ctx.line_to(110, 40)     # chamfered upper-right shoulder
    ctx.line_to(104, 48)
    ctx.line_to(102, 74)     # taper begins
    ctx.line_to(64, 123)     # point
    ctx.line_to(26, 74)
    ctx.line_to(24, 48)
    ctx.line_to(18, 40)
    ctx.line_to(18, 23)
    ctx.close_path()


def monogram_path(ctx: cairo.Context) -> None:
    """An angular, technical B.

    Built from straight edges and 45-degree chamfers rather than round bowls,
    and split at the waist so the letter reads as two stacked modules. Counters
    are chamfered on the outer corner to echo the bowls.
    """
    # Every stroke is 10 units. Keeping the bars and the counters at a
    # comparable weight is what makes the bowls read as bowls instead of as
    # solid blocks with notches cut out of them.

    # --- upper bowl: y 32..62, outer edge at x 80 -------------------------
    # The stem's outer corners are chamfered to match the bowls, so every
    # corner in the mark is either square or cut at 45 degrees.
    ctx.move_to(50, 32)
    ctx.line_to(72, 32)
    ctx.line_to(80, 40)     # chamfer out
    ctx.line_to(80, 54)
    ctx.line_to(72, 62)     # chamfer in
    ctx.line_to(44, 62)
    ctx.line_to(44, 38)     # chamfered stem corner
    ctx.close_path()

    ctx.move_to(56, 42)     # counter, 10 tall
    ctx.line_to(65, 42)
    ctx.line_to(70, 47)
    ctx.line_to(70, 52)
    ctx.line_to(56, 52)
    ctx.close_path()

    # --- lower bowl: y 65..98, wider, outer edge at x 86 ------------------
    ctx.move_to(44, 65)
    ctx.line_to(76, 65)
    ctx.line_to(86, 75)     # chamfer out
    ctx.line_to(86, 88)
    ctx.line_to(76, 98)     # chamfer in
    ctx.line_to(50, 98)
    ctx.line_to(44, 92)     # chamfered stem corner
    ctx.close_path()

    ctx.move_to(56, 75)     # counter, 13 tall
    ctx.line_to(71, 75)
    ctx.line_to(76, 80)
    ctx.line_to(76, 88)
    ctx.line_to(56, 88)
    ctx.close_path()


def draw(ctx: cairo.Context, size: int) -> None:
    scale = size / GRID
    ctx.scale(scale, scale)

    # Fine detail disappears below ~32px and only muddies the silhouette.
    detailed = size >= 32

    # shield body
    gradient = cairo.LinearGradient(20, 8, 60, 121)
    gradient.add_color_stop_rgb(0.00, 0.31, 0.89, 0.66)
    gradient.add_color_stop_rgb(0.55, 0.16, 0.75, 0.54)
    gradient.add_color_stop_rgb(1.00, 0.07, 0.53, 0.42)
    shield_path(ctx)
    ctx.set_source(gradient)
    ctx.fill_preserve()

    # rim, drawn inside the fill so it never grows the silhouette
    ctx.set_source_rgba(0.04, 0.37, 0.30, 0.55)
    ctx.set_line_width(3 if detailed else 4)
    ctx.stroke()

    if detailed:
        # top sheen, clipped to the shield
        ctx.save()
        shield_path(ctx)
        ctx.clip()
        sheen = cairo.LinearGradient(20, 8, 80, 95)
        sheen.add_color_stop_rgba(0, 1, 1, 1, 0.30)
        sheen.add_color_stop_rgba(1, 1, 1, 1, 0.0)
        ctx.move_to(64, 8)
        ctx.line_to(112, 26)
        ctx.line_to(112, 50)
        ctx.line_to(16, 92)
        ctx.line_to(16, 26)
        ctx.close_path()
        ctx.set_source(sheen)
        ctx.fill()
        ctx.restore()

    # monogram
    ctx.set_fill_rule(cairo.FILL_RULE_EVEN_ODD)
    monogram_path(ctx)
    ctx.set_source_rgb(1, 1, 1)
    ctx.fill()
    ctx.set_fill_rule(cairo.FILL_RULE_WINDING)

    if detailed:
        ctx.save()
        shield_path(ctx)
        ctx.clip()

        # scan line across the mark
        ctx.rectangle(16, 62.2, 96, 2.6)
        ctx.set_source_rgba(1, 1, 1, 0.5)
        ctx.fill()

        # HUD brackets in the shoulders, and tick marks down the taper
        ctx.set_source_rgba(1, 1, 1, 0.30)
        ctx.set_line_width(2.4)
        ctx.set_line_cap(cairo.LINE_CAP_BUTT)
        for x_out, direction in ((28, 1), (100, -1)):
            ctx.move_to(x_out, 30)
            ctx.line_to(x_out + 9 * direction, 30)
            ctx.move_to(x_out, 30)
            ctx.line_to(x_out, 39)
            ctx.stroke()

        ctx.set_source_rgba(1, 1, 1, 0.22)
        ctx.set_line_width(1.8)
        for y in (78, 84, 90):
            ctx.move_to(34, y)
            ctx.line_to(40, y)
            ctx.move_to(94, y)
            ctx.line_to(88, y)
            ctx.stroke()
        ctx.restore()


def render(size: int, path: Path) -> None:
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    ctx = cairo.Context(surface)
    ctx.set_antialias(cairo.ANTIALIAS_BEST)
    draw(ctx, size)
    surface.write_to_png(str(path))


def main(argv: list[str]) -> int:
    outdir = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent / "icons"
    outdir.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        target = outdir / f"br1zz-security-{size}.png"
        render(size, target)
        print(f"  {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
