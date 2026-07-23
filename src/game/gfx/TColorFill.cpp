#include "game/TColorFill.h"

#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_invalidation_guard.h"

// SYNTHETIC: IMPERIALISM 0x004ff150
// TColorFill::`scalar deleting destructor'
TColorFill::~TColorFill() {}
// SYNTHETIC: IMPERIALISM 0x004ff0c0
// TColorFill::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ff1a0
// TColorFill::GetRuntimeClass

IMPLEMENT_DYNCREATE(TColorFill, TAdorner)

TColorFill::TColorFill() {}

// FUNCTION: IMPERIALISM 0x004ff1c0
void TColorFill::Draw(TView*, const RECT&) {
  if (g_colorFillAssertGuard_006a30b4 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UDisplayMgr.cpp", 0x2da);
  }
}
