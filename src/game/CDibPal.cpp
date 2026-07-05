#include "game/CDibPal.h"

#include <stdlib.h>

// FUNCTION: IMPERIALISM 0x0047e360
CDibPal::CDibPal() : CPalette() {
  m_pLogPalette = NULL;
}

// The scalar deleting destructor is compiler-generated from the virtual dtor.
// SYNTHETIC: IMPERIALISM 0x0047e390
// CDibPal::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0047e3c0
CDibPal::~CDibPal() {
  if (m_pLogPalette != NULL) {
    free(m_pLogPalette);
  }
}

// FUNCTION: IMPERIALISM 0x0047e440
int CDibPal::BuildPaletteFromBitmapColorTable(CDib* dib) {
  int colorCount = dib->m_paletteCount;
  if (colorCount == 0) {
    return 0;
  }

  const BYTE* source = static_cast<const BYTE*>(dib->m_colorTablePixels);
  if (m_pLogPalette != NULL) {
    free(m_pLogPalette);
  }

  m_pLogPalette = static_cast<LOGPALETTE*>(malloc(colorCount * sizeof(PALETTEENTRY) + 8));
  if (m_pLogPalette == NULL) {
    return 0;
  }

  m_pLogPalette->palVersion = 0x300;
  m_pLogPalette->palNumEntries = static_cast<WORD>(colorCount);
  for (int i = 0; i < colorCount; i++) {
    m_pLogPalette->palPalEntry[i].peRed = source[2];
    m_pLogPalette->palPalEntry[i].peGreen = source[1];
    m_pLogPalette->palPalEntry[i].peBlue = source[0];
    m_pLogPalette->palPalEntry[i].peFlags = 0;
    source += sizeof(RGBQUAD);
  }

  return Attach(::CreatePalette(m_pLogPalette));
}

// FUNCTION: IMPERIALISM 0x0047e930
UINT CDibPal::SelectIntoDcAndRealize(CDC* dc, BOOL background) {
  // LIBRARY: CDC::SelectPalette (0x00612a78)
  dc->SelectPalette(this, background);
  return ::RealizePalette(dc->m_hDC);
}
