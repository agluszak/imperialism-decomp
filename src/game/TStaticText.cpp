// Manual decompilation file.

#include "game/TStaticText.h"

#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"
#include <new>
CRuntimeClass g_pClassDescTStaticText = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x004294d0
undefined TStaticText::AssignSharedStringFromField84() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048F710
void* __cdecl CreateTStaticTextInstance(void) {
  return new TStaticText();
}

// MFC RTTI slot 0x00 override: return this class's CRuntimeClass descriptor (0x649678).
// FUNCTION: IMPERIALISM 0x0048F870
CRuntimeClass* TStaticText::GetRuntimeClass() const {
  return &g_pClassDescTStaticText;
}

// FUNCTION: IMPERIALISM 0x0048F890
TStaticText::TStaticText()
    : TControl(), text(), field88((void*)0xffffffff), field8C(0), field90(0) {
  hasCommandTagResource = 13;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0048f9a0
// TStaticText::`scalar deleting destructor'

TStaticText::~TStaticText() {}

// FUNCTION: IMPERIALISM 0x0048fc00
TObject* TStaticText::ShallowClone() {
  TObject* cloned = TView::ShallowClone();
  if (cloned != 0) {
    reinterpret_cast<TView*>(cloned)->CopyCityDialogStateFromSource(this);
  }
  return cloned;
}

// FUNCTION: IMPERIALISM 0x0048fe60
undefined TStaticText::AssignTextSharedRefIfChangedAndMaybeInvalidate() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048fed0
undefined TStaticText::LoadUiStringAndDispatchViaVslot1C8() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048ff70
undefined TStaticText::OrphanCallChain_C1_I09_0048ff70() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0048ffb0
void TStaticText::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x004900a0
undefined TStaticText::RenderControlStateTextBySelectionCode() {
  return 0;
}
