#pragma once

#include "game/CDib.h"
#include "game/mfc.h"

// CDibPal: the DIB palette companion to CDib (Prosise / MSDN DIBLOOK lineage), compiled into the
// game from source. A subclass of MFC CPalette (CPalette : CGdiObject : CObject -- all real MFC,
// inherited and linked, NEVER modeled here). Slot 0 is inherited from CPalette and returns
// CPalette's CRuntimeClass at 0x672358; the game-owned vtable at 0x646a68 exists because this
// subclass overrides the destructor. Adds one field: a transient LOGPALETTE build buffer at +0x08.
// The asset cache holds a global CDibPal singleton in m_field0.
//
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
};

ASSERT_SIZE(CDibPal, 0x0c);
