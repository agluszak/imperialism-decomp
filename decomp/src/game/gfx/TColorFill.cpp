#include "game/gfx/TColorFill.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x004ff180
TColorFill::~TColorFill() {}

IMPLEMENT_DYNCREATE(TColorFill, TAdorner)

// FUNCTION: IMPERIALISM 0x004ff1c0
void TColorFill::Draw(TView*, const RECT&) {
  if (g_colorFillAssertGuard_006a30b4 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UDisplayMgr.cpp", 0x2da);
  }
}
