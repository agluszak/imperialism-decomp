#include "game/gfx/TScopedQuickDrawPen.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00498610
TScopedQuickDrawPen::~TScopedQuickDrawPen() {
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  dc->SelectObject(previousPen08);
}

// SYNTHETIC: IMPERIALISM 0x004986a0
// TScopedQuickDrawPen::`scalar deleting destructor'
