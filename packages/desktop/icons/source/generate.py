from pathlib import Path
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT
REPO = ROOT.parent.parent
MASTER = Image.open(ROOT / "source" / "argos-mark.png").convert("RGBA")


def render(size: int) -> Image.Image:
    return MASTER.resize((size, size), Image.LANCZOS)


def save(im: Image.Image, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    im.save(path)


# ── Per-channel file manifest ──
FLAT_SIZES = {
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "32x32.png": 32,
    "64x64.png": 64,
    "Square107x107Logo.png": 107,
    "Square142x142Logo.png": 142,
    "Square150x150Logo.png": 150,
    "Square284x284Logo.png": 284,
    "Square30x30Logo.png": 30,
    "Square310x310Logo.png": 310,
    "Square44x44Logo.png": 44,
    "Square71x71Logo.png": 71,
    "Square89x89Logo.png": 89,
    "StoreLogo.png": 50,
    "dock.png": 256,
    "icon.png": 512,
}

ANDROID_SIZES = {
    "hdpi": (49, 162),
    "mdpi": (48, 108),
    "xhdpi": (96, 216),
    "xxhdpi": (144, 324),
    "xxxhdpi": (192, 432),
}

IOS_SIZES = {
    "AppIcon-20x20@1x.png": 20,
    "AppIcon-20x20@2x-1.png": 40,
    "AppIcon-20x20@2x.png": 40,
    "AppIcon-20x20@3x.png": 60,
    "AppIcon-29x29@1x.png": 29,
    "AppIcon-29x29@2x-1.png": 58,
    "AppIcon-29x29@2x.png": 58,
    "AppIcon-29x29@3x.png": 87,
    "AppIcon-40x40@1x.png": 40,
    "AppIcon-40x40@2x-1.png": 80,
    "AppIcon-40x40@2x.png": 80,
    "AppIcon-40x40@3x.png": 120,
    "AppIcon-512@2x.png": 1024,
    "AppIcon-60x60@2x.png": 120,
    "AppIcon-60x60@3x.png": 180,
    "AppIcon-76x76@1x.png": 76,
    "AppIcon-76x76@2x.png": 152,
    "AppIcon-83.5x83.5@2x.png": 167,
}

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

targets = [("dev", os.path.join(ICONS, "dev")), ("beta", os.path.join(ICONS, "beta")), ("prod", os.path.join(ICONS, "prod")), ("resources", os.path.join(ROOT.parent, "resources", "icons"))]
for channel, base in targets:

    for name, size in FLAT_SIZES.items():
        save(render(size), os.path.join(base, name))

    for density, (launcher, fg) in ANDROID_SIZES.items():
        save(render(launcher), os.path.join(base, "android", f"mipmap-{density}", "ic_launcher.png"))
        save(render(launcher), os.path.join(base, "android", f"mipmap-{density}", "ic_launcher_round.png"))
        save(render(fg), os.path.join(base, "android", f"mipmap-{density}", "ic_launcher_foreground.png"))

    for name, size in IOS_SIZES.items():
        save(render(size), os.path.join(base, "ios", name))

    ico_img = render(256)
    ico_img.save(
        os.path.join(base, "icon.ico"),
        sizes=[(s, s) for s in ICO_SIZES],
    )

    icns_img = render(1024)
    icns_img.save(os.path.join(base, "icon.icns"))

    print(f"channel {channel}: done")

print("icons/{dev,beta,prod} regenerated with transparent background")
