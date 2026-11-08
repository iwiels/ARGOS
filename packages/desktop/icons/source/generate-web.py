from pathlib import Path
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT
REPO = ROOT.parent.parent
MASTER = Image.open(ROOT / "source" / "argos-mark.png").convert("RGBA")


def render(size: int) -> Image.Image:
    return MASTER.resize((size, size), Image.LANCZOS)


APP_PUBLIC = os.path.join(REPO, "app", "public")
UI_FAVICON = os.path.join(REPO, "ui", "src", "assets", "favicon")

# ── 2. favicon set (both mirrors) ──
for target in (APP_PUBLIC, UI_FAVICON):
    os.makedirs(target, exist_ok=True)
    render(96).save(os.path.join(target, "favicon-96x96-v3.png"))
    render(180).save(os.path.join(target, "apple-touch-icon-v3.png"))
    ico_img = render(256)
    ico_img.save(
        os.path.join(target, "favicon-v3.ico"),
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    svg = (ROOT / "source" / "argos-mark.svg").read_text(encoding="utf-8")
    with open(os.path.join(target, "favicon-v3.svg"), "w", encoding="utf-8") as f:
        f.write(svg)

# ── 3. remove stale, unreferenced legacy (non -v3) favicon files ──
for target in (APP_PUBLIC, UI_FAVICON):
    for stale in ("favicon.ico", "favicon.svg", "favicon-96x96.png", "apple-touch-icon.png"):
        p = os.path.join(target, stale)
        if os.path.exists(p):
            os.remove(p)
            print("removed stale", p)

# ── 4. PWA manifest icons (transparent) ──
render(192).save(os.path.join(APP_PUBLIC, "web-app-manifest-192x192.png"))
render(512).save(os.path.join(APP_PUBLIC, "web-app-manifest-512x512.png"))

# ── 5. OG / social-share card ──
W, H = 1200, 630
card = Image.new("RGB", (W, H), (9, 13, 22))  # dark bg token
draw = ImageDraw.Draw(card)

icon_size = 220
icon = render(icon_size)
icon_x = (W - icon_size) // 2
icon_y = 110
card.paste(icon, (icon_x, icon_y), icon)

try:
    font_title = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 64)
    font_sub = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 30)
except Exception:
    font_title = ImageFont.load_default()
    font_sub = ImageFont.load_default()

title = "Argos"
sub = "Security audits"

tw = draw.textlength(title, font=font_title)
draw.text(((W - tw) / 2, icon_y + icon_size + 34), title, font=font_title, fill=(243, 244, 246))

sw = draw.textlength(sub, font=font_sub)
draw.text(((W - sw) / 2, icon_y + icon_size + 34 + 78), sub, font=font_sub, fill=(156, 163, 175))

card.save(os.path.join(APP_PUBLIC, "social-share.png"))
card.save(os.path.join(APP_PUBLIC, "social-share-zen.png"))

print("web assets regenerated with transparent background")
