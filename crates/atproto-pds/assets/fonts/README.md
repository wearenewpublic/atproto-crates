# Fonts

Served from this origin at `/static/fonts/` by `src/http/static_assets.rs`, embedded in the binary with
`include_bytes!`. Nothing here is fetched at runtime and nothing external is
ever requested — the portal's CSP forbids it.

## `jetbrains-mono-var.woff2`

JetBrains Mono, variable weight axis (100–800), subset to the characters the
portal actually renders in monospace: ASCII printable plus the punctuation and
arrows the UI uses.

Monospace here is **semantic**, not decorative. It marks machine values — DIDs,
CIDs, AT-URIs, scope strings, record JSON — which a person compares character
by character, and JetBrains Mono was chosen because it disambiguates `0`/`O`
and `1`/`l`/`I` explicitly. A misread character in a DID is a real failure.

- **Upstream:** <https://github.com/JetBrains/JetBrainsMono>
- **Licence:** SIL Open Font License 1.1 — `OFL-JetBrainsMono.txt`.
- **Size:** 12.4 KB. The unsubsetted static Regular is 92 KB and the variable
  TTF is 296 KB; the subset covers every weight in a fraction of one static cut.

### Regenerating

Download the upstream release, then, from its `fonts/variable/` directory:

```sh
python3 -m fontTools.subset "JetBrainsMono[wght].ttf" \
  --unicodes='U+0020-007E,U+00A0,U+00B7,U+2013,U+2014,U+2018-201D,U+2022,U+2026,U+2190-2193' \
  --flavor=woff2 --layout-features='' \
  --output-file=jetbrains-mono-var.woff2
```

Requires `fontTools` and `brotli`. If you add characters to the portal that
fall outside that range, widen `--unicodes` and regenerate — a missing glyph
falls back to the system monospace and only shows up visually.

## `archivo-{400,400-italic,500,600,700}.woff2`

Archivo, static weights, subset to Latin-1 plus Latin Extended-A, general
punctuation and arrows. The wider range than the mono is deliberate: the portal
renders user-controlled strings in this face — a space's name, for one — and a
missing glyph produces a word rendered half in Archivo and half in the system
font, which looks like a fault and is hard to diagnose.

Upstream ships no variable cut, hence one file per weight. 400 body, 500 label,
600 heading, 700 for `<b>`, plus a real italic because the spaces pages use
`<em>` and a synthesised oblique is a sheared roman. A browser fetches only the
cuts a given page actually uses.

- **Upstream:** <https://github.com/Omnibus-Type/Archivo>
- **Licence:** SIL Open Font License 1.1 — `OFL-Archivo.txt`.

### Regenerating

```sh
UNI='U+0020-007E,U+00A0-00FF,U+0100-017F,U+2000-206F,U+2190-2193'
for f in Regular:400 Medium:500 SemiBold:600 Bold:700 Italic:400-italic; do
  python3 -m fontTools.subset "ttf/Archivo-${f%%:*}.ttf" \
    --unicodes="$UNI" --flavor=woff2 \
    --output-file="archivo-${f##*:}.woff2"
done
```
