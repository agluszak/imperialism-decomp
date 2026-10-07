#pragma once

#include "game/gfx/CDib.h"
#include "game/mfc.h"

#include <mmsystem.h>

// VTABLE: IMPERIALISM 0x00646a68
class CDibPal : public CPalette {
public:
  LOGPALETTE* m_pLogPalette; // 0x08 transient LOGPALETTE buffer (malloc/free)

  CDibPal();
  virtual ~CDibPal() override;

  // Build the HPALETTE from a CDib's RGBQUAD color table and Attach it. 0x0047e440
  int BuildPaletteFromBitmapColorTable(CDib* dib);
  // Select this palette into the DC (MFC CDC::SelectPalette) and realize it
  UINT SelectIntoDcAndRealize(CDC* dc, BOOL background);

  void DrawPalettePreviewGridRectangles(CDC* dc, RECT* bounds, BOOL bForceBackground);
  BOOL CreateIdentityPalette();

  // Load a RIFF PAL palette, prompting for a file when fileName is null or empty
  int LoadPaletteFile(LPCSTR fileName);
  int LoadPalette(CFile* file);
  int LoadPalette(UINT fileHandle);
  int LoadPalette(HMMIO mmioHandle);
  int SavePalette(CFile* file);
  int SavePalette(UINT fileHandle);
  int SavePalette(HMMIO mmioHandle);
};

ASSERT_SIZE(CDibPal, 0x0c);
