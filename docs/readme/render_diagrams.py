"""Render the same Graphviz geometry with checked light and dark palettes."""

from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent
PALETTES = {
    "light": ["#ffffff", "#172033", "#475569", "#eff3f8",
              "#fff4cc", "#e2f3e8", "#fde8e7"],
    "dark": ["#0f172a", "#f1f5f9", "#94a3b8", "#1e293b",
             "#3a2d13", "#15392a", "#442327"],
}
DESCRIPTIONS = {
    "subsystems": (
        "Inside Sibuna",
        "Eight modules handle connections, HTTP, proofs, puzzles, access rules, "
        "request limits, storage and the operator console.",
    ),
    "protection-surfaces": (
        "How Sibuna protects a request",
        "Shield checks requests for web attacks; Gate skips those checks. "
        "Both apply access rules, sessions and request limits. "
        "A request can reach the app, receive a puzzle or be stopped.",
    ),
    "admission-session": (
        "Solve a puzzle, then keep browsing",
        "The browser solves a puzzle. An accepted solution earns a signed "
        "session cookie, which the browser sends on later requests. "
        "Rules and request limits still apply, and Shield still checks attacks. "
        "Later requests can reach the app, need new work or be stopped.",
    ),
}
SVG = "http://www.w3.org/2000/svg"


def luminance(color):
    values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
              for v in values]
    return sum(v * w for v, w in zip(linear, (0.2126, 0.7152, 0.0722)))


def contrast(first, second):
    low, high = sorted((luminance(first), luminance(second)))
    return (high + 0.05) / (low + 0.05)


def check_palette(theme, palette):
    canvas, text, line, *fills = palette
    backgrounds = [canvas, *fills]
    text_min = min(contrast(text, bg) for bg in backgrounds)
    line_min = min(contrast(line, bg) for bg in backgrounds)
    assert text_min >= 4.5, f"{theme}: text contrast {text_min}"
    assert line_min >= 3.0, f"{theme}: diagram contrast {line_min}"
    print(f"{theme}: text >= {text_min:.2f}:1; lines >= {line_min:.2f}:1")


def describe_svg(path, name):
    ET.register_namespace("", SVG)
    tree = ET.parse(path)
    root = tree.getroot()
    title = ET.Element(f"{{{SVG}}}title", {"id": "diagram-title"})
    title.text, description = DESCRIPTIONS[name]
    root.insert(0, title)
    desc = ET.Element(f"{{{SVG}}}desc", {"id": "diagram-description"})
    desc.text = description
    root.insert(1, desc)
    root.set("role", "img")
    root.set("aria-labelledby", "diagram-title diagram-description")
    tree.write(path, encoding="utf-8", xml_declaration=True)


def render(source, theme, palette):
    original = source.read_text()
    assert set(re.findall(r"#[0-9a-f]{6}", original)) <= set(PALETTES["light"])
    colors = dict(zip(PALETTES["light"], palette))
    themed = re.sub(r"#[0-9a-f]{6}", lambda match: colors[match[0]], original)
    suffix = "" if theme == "light" else "-dark"
    for fmt in ("svg", "png"):
        output = ROOT / "images" / f"{source.stem}{suffix}.{fmt}"
        subprocess.run(["dot", f"-T{fmt}", "-Gdpi=160", "-o", str(output)],
                       input=themed, text=True, check=True)
        if fmt == "svg":
            describe_svg(output, source.stem)


def main():
    for theme, palette in PALETTES.items():
        check_palette(theme, palette)
        for name in sorted(DESCRIPTIONS):
            render(ROOT / "diagrams" / f"{name}.dot", theme, palette)


if __name__ == "__main__":
    main()
