# Font binaries

## `system.ttf`

Pinned Wine **System** face used as the Windows System compatibility font
(retail font family 0). It is not part of the GOG `Data/*.ttf` set.

- Family name: `System`
- Copyright: Huw D M Davies, Dmitry Timoshkov, 2004
- License: LGPL-2.1-or-later (see the font's name table license notice)
- Upstream source: https://gitlab.winehq.org/wine/wine/-/blob/master/fonts/system.sfd
- SHA-256: `b3a4cdcae000aed598d3eeb5e5af3ae3db6b6cb7dc3be7592e10107725f72411`

## `test_outline.ttf`

Synthetic TrueType (`ImperialismTestOutline`) produced once with fontTools
`FontBuilder`. Rectangular outline glyphs cover the characters used by the
raster painter tests, with a descender and negative left bearing on `j`.

## `test_ebdt.ttf`

Synthetic TrueType (`ImperialismTestEbdt`) produced once with fontTools
`FontBuilder`. Glyph outlines are empty; a 12ppem 1-bit `EBDT`/`EBLC` strike
supplies the ink. Used to prove System-family rasterization reads bitmap
strikes when outlines do not.
