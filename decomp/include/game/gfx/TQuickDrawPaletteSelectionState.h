#pragma once

#include "game/mfc.h"

// Two-field palette-selection state emitted in QuickDraw.cpp immediately before the
// resource cache. The no-argument overload operates on the already-bound DC; the other
// overload binds a DC first. Both retain the palette that CDC::SelectPalette replaces.
class TQuickDrawPaletteSelectionState {
public:
  TQuickDrawPaletteSelectionState* SelectDefaultDibPalette();
  TQuickDrawPaletteSelectionState* SelectDefaultDibPalette(CDC* dc);

  CDC* m_dc;
  CPalette* m_previousPalette;
};

ASSERT_SIZE(TQuickDrawPaletteSelectionState, 0x08);
