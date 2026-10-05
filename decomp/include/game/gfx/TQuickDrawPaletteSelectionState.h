#pragma once

#include "game/mfc.h"

class TQuickDrawPaletteSelectionState {
public:
  TQuickDrawPaletteSelectionState* SelectDefaultDibPalette();
  TQuickDrawPaletteSelectionState* SelectDefaultDibPalette(CDC* dc);

  CDC* m_dc;
  CPalette* m_previousPalette;
};

ASSERT_SIZE(TQuickDrawPaletteSelectionState, 0x08);
