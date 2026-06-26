// Manual decompilation file.

#include "game/TStaticText.h"
#include "game/TViewMgr.h"

extern "C" {
extern int g_nUiResourceEntryDefaultParam0;
}

undefined4 LoadUiStringResourceByGroupAndIndex(void);




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

// FUNCTION: IMPERIALISM 0x0048fb10
void TStaticText::CopyCityDialogStateFromSource(TView* source) {
  TView::CopyCityDialogStateFromSource(source);
  TStaticText* src = static_cast<TStaticText*>(source);
  this->hasCommandTagResource = src->hasCommandTagResource;
  this->commandTagResourceByte = src->commandTagResourceByte;
  this->contentMargins68 = src->contentMargins68;
  this->commandTagDefaultParam0 = src->commandTagDefaultParam0;
  this->commandTagDefaultParam1 = src->commandTagDefaultParam1;
  this->commandTagDefaultParam2 = src->commandTagDefaultParam2;
  this->text = src->text;
}

// FUNCTION: IMPERIALISM 0x0048fc00
TObject* TStaticText::ShallowClone() {
  TObject* cloned = this->ShallowFree();
  if (cloned != 0) {
    static_cast<TStaticText*>(cloned)->CopyCityDialogStateFromSource(this);
  }
  return cloned;
}

// FUNCTION: IMPERIALISM 0x0048fd00
void TStaticText::InitializeTextEntryBaseAndOptionalStringResource(
    TControl* panel, int* offsetLayout, int* sizeLayout, int layoutParam6, int layoutParam7,
    short stringResourceGroup, short stringResourceIndex) {
  (void)layoutParam6;
  (void)layoutParam7;
  if (panel != 0) {
    nativeWindow50 = panel->nativeWindow50;
  }
  controlTag = 0x20202020;
  field04 = 1;
  field08 = 1;
  field0c = reinterpret_cast<int>(panel);
  ownerOffsetX = offsetLayout[0];
  ownerOffsetY = offsetLayout[1];
  field34 = sizeLayout[0];
  field38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, 0);
  }
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x40) = 0;
  SetCityProductionDialogPictureRectAndMaybeRefresh(
      reinterpret_cast<TControlPictureRectState*>(&g_nUiResourceEntryDefaultParam0), 0);
  field88 = reinterpret_cast<void*>(static_cast<int>(stringResourceGroup));
  field8C = stringResourceIndex;
  if (stringResourceGroup != -1) {
    CString loadedString;
    reinterpret_cast<void(__cdecl*)(void*, CString*, int, int)>(
        reinterpret_cast<void (*)()>(LoadUiStringResourceByGroupAndIndex))(
        g_pUiRuntimeContext, &loadedString, stringResourceGroup, stringResourceIndex);
    AssignTextSharedRefIfChangedAndMaybeInvalidate(&loadedString, 0);
  }
  HandleCursorHoverFallback(0, 0);
}

// FUNCTION: IMPERIALISM 0x0048fe60
undefined TStaticText::AssignTextSharedRefIfChangedAndMaybeInvalidate(CString* sharedString,
                                                                      char refreshNow) {
  (void)sharedString;
  (void)refreshNow;
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
