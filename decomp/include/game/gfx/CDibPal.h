#pragma once

#include "game/gfx/CDib.h"
#include "game/mfc.h"

#include <mmsystem.h>

// VTABLE: IMPERIALISM 0x00646a68
class CDibPal : public CPalette {
public:
  LOGPALETTE* m_pLogPalette; // 0x08 transient LOGPALETTE buffer (malloc/free)

  CDibPal();                   // 0x0047e360
  virtual ~CDibPal() override; // 0x0047e3c0 (scalar dtor 0x0047e390)

  // Build the HPALETTE from a CDib's RGBQUAD color table and Attach it. 0x0047e440
  int BuildPaletteFromBitmapColorTable(CDib* dib);
  // Select this palette into the DC (MFC CDC::SelectPalette) and realize it. 0x0047e930
  UINT SelectIntoDcAndRealize(CDC* dc, BOOL background);

  void DrawPalettePreviewGridRectangles(CDC* dc, RECT* bounds, BOOL bForceBackground);
  BOOL CreateIdentityPalette();

  // Load a RIFF PAL palette, prompting for a file when fileName is null or empty. 0x0047e960
  int LoadPaletteFile(LPCSTR fileName);
  int LoadPalette(CFile* file);      // 0x0047ec70
  int LoadPalette(UINT fileHandle);  // 0x0047ecf0
  int LoadPalette(HMMIO mmioHandle); // 0x0047ed70
  int SavePalette(CFile* file);      // 0x0047eea0
  int SavePalette(UINT fileHandle);  // 0x0047ef20
  int SavePalette(HMMIO mmioHandle); // 0x0047efa0
};

ASSERT_SIZE(CDibPal, 0x0c);
