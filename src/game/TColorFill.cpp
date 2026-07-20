#include "game/TColorFill.h"

#include "game/global_data_tables.h"
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

namespace {
// Same original source file as TDisplayMgr.cpp's own kSourceFileUDisplayMgr constant (both
// classes were compiled from D:\Ambit\Cross\UDisplayMgr.cpp) -- circumstantial evidence
// TDisplayMgr is the eventual adorner owner (see TAdorner.h).
const char kSourceFileUDisplayMgr[] = "D:\\Ambit\\Cross\\UDisplayMgr.cpp";
} // namespace

// FUNCTION: IMPERIALISM 0x004ff1c0
undefined TColorFill::AdornerSlot0C(int, int) {
  if (g_colorFillAssertGuard_006a30b4 == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag(kSourceFileUDisplayMgr, 0x2da);
  }
  return 0;
}
