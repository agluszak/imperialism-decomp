#include "game/gfx/TQuickDrawPaletteSelectionState.h"

#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00498e00
TQuickDrawPaletteSelectionState* TQuickDrawPaletteSelectionState::SelectDefaultDibPalette() {
  m_previousPalette =
      m_dc->SelectPalette(g_pModuleLibraryCacheState->EnsureDefaultDibPalette(), FALSE);
  return this;
}

// FUNCTION: IMPERIALISM 0x00498e30
TQuickDrawPaletteSelectionState* TQuickDrawPaletteSelectionState::SelectDefaultDibPalette(CDC* dc) {
  m_dc = dc;
  m_previousPalette =
      m_dc->SelectPalette(g_pModuleLibraryCacheState->EnsureDefaultDibPalette(), FALSE);
  return this;
}
