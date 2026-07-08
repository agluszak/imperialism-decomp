#include "game/TMapKey.h"

#include "game/CString.h"
#include "game/TSimMgr.h"
#include "game/TView.h"
#include "game/global_data_tables.h" // g_pSimMgr
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x00430900
// TMapKey::`scalar deleting destructor'
TMapKey::~TMapKey() {}
// SYNTHETIC: IMPERIALISM 0x004fc9c0
// TMapKey::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fca70
// TMapKey::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapKey, TPicture)

TMapKey::TMapKey() {}

// FUNCTION: IMPERIALISM 0x004fcac0
void TMapKey::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x004fcf80
void TMapKey::ApplyRectSlot110(RECT* rectBuffer) {
  TPicture::ApplyRectSlot110(rectBuffer);
  switch (this->viewMode90) {
  case 0:
    RenderMapHintOverlayMode0();
    break;
  }
}

// Legend labels for view mode 0: a heading and a body line, each drawn twice
// (offset drop shadow then main color) at coordinates relative to the anchor view.
// FUNCTION: IMPERIALISM 0x004fd000
void TMapKey::RenderMapHintOverlayMode0() {
  TView* anchor = this->ownerContext;
  short baseX = (short)this->ownerLocalX + (short)anchor->ownerLocalX;
  short baseY = (short)this->ownerLocalY + (short)anchor->ownerLocalY;

  CString label;
  int shadowStyle = 0;
  int mainStyle = 0;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xa, 0x2b68, 3);
  MapUiThemeCodeToStyleFlags(0x2b6b, &mainStyle);
  MapUiThemeCodeToStyleFlags(0x2b68, &shadowStyle);

  g_pSimMgr->GetString(0x2733, 5, &label);
  short x = 0x1de - baseX;
  short y = 0x1d1 - baseY;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(x + 1, y + 1);
  DrawTextWithCachedQuickDrawStyleState(&label);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(x, y);
  DrawTextWithCachedQuickDrawStyleState(&label);

  g_pSimMgr->GetString(0x2733, 0x1e, &label);
  short x2 = 0x1af - baseX;
  short y2 = 0x171 - baseY;
  SetQuickDrawColorAndSyncGlobals(shadowStyle);
  SetQuickDrawTextOriginWithContextOffset(x2 + 1, y2 + 1);
  DrawTextWithCachedQuickDrawStyleState(&label);
  SetQuickDrawColorAndSyncGlobals(mainStyle);
  SetQuickDrawTextOriginWithContextOffset(x2, y2);
  DrawTextWithCachedQuickDrawStyleState(&label);
}
