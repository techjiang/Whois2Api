#!/usr/bin/env python3
"""Re-encode the PNG logo variants from web/logo.svg.

The SVG is the source of truth: it is what the UI loads and what the favicon is
generated from. Keep this script dependency-light (cairosvg + Pillow).
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SVG = ROOT / "web" / "logo.svg"

def main() -> int:
    try:
        import cairosvg
    except ImportError:
        print("cairosvg is required: pip install cairosvg", file=sys.stderr)
        return 1
    if not SVG.exists():
        print(f"missing {SVG}", file=sys.stderr)
        return 1
    for size, name in ((512, "logo-512.png"), (180, "logo-180.png"), (32, "favicon-32.png")):
        target = ROOT / "web" / name
        cairosvg.svg2png(url=str(SVG), write_to=str(target),
                         output_width=size, output_height=size)
        print(f"wrote {target.relative_to(ROOT)} ({size}x{size})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
