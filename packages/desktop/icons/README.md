# Argos brand assets

The Argos mark combines a watchful eye and a shield. The vector source is `source/argos-mark.svg`; `source/argos-mark.png` is its 1024 px transparent raster master. Keep their geometry and colors aligned when editing the mark.

Generate desktop channel icons, web favicons, PWA icons and social cards with Python 3 and Pillow:

```sh
python packages/desktop/icons/source/generate.py
python packages/desktop/icons/source/generate-web.py
```

The dev, beta and prod channels use the same mark. The SolidJS component in `packages/ui/src/components/argos-logo.tsx` uses the same paths and supports a monochrome foreground.
