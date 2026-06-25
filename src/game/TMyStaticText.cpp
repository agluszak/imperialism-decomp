#include "game/TMyStaticText.h"

#include "game/CString.h"
#include "game/TControl.h"
#include "game/TStaticText.h"
#include "game/TViewMgr.h"

extern "C" {
extern int g_nUiResourceEntryDefaultParam0;
}

undefined4 LoadUiStringResourceByGroupAndIndex(void);

// FUNCTION: IMPERIALISM 0x0048fd00
void TMyStaticText::InitializeTextEntryBaseAndOptionalStringResource(
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

// FUNCTION: IMPERIALISM 0x005b5400
CRuntimeClass* TMyStaticText::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005b5420
TMyStaticText::TMyStaticText() : TStaticText() {}

// SYNTHETIC: IMPERIALISM 0x005b5450
// TMyStaticText::`scalar deleting destructor'
TMyStaticText::~TMyStaticText() {}
