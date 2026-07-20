#include "game/TFrameRadioView.h"

#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004fdf50
// TFrameRadioView::`scalar deleting destructor'
TFrameRadioView::~TFrameRadioView() {}
// SYNTHETIC: IMPERIALISM 0x004fded0
// TFrameRadioView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004fdfa0
// TFrameRadioView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TFrameRadioView, TControl)

TFrameRadioView::TFrameRadioView() {}

// FUNCTION: IMPERIALISM 0x004fdfc0
void TFrameRadioView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  if (controlState64 != 0) {
    RECT frame = {1, 1, frameWidth34, frameHeight38};
    SetQuickDrawFillColor(0);
    QDFrameRect(&frame);
    OffsetRect(&frame, -1, -1);
    SetQuickDrawFillColor(0xffffff);
    QDFrameRect(&frame);
  }
}

// FUNCTION: IMPERIALISM 0x004fe060
void TFrameRadioView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
  case 0xa:
    DispatchEvent(0x1f, this, 0);
    return;
  case 0xc:
    if (controlState64 == 0 && GetBoolSlot28() != 0) {
      SetControlStateFlagAndMaybeRefresh(true, false);
    }
    break;
  case 0x1f:
    if (GetBoolSlot28() != 0) {
      SetControlStateFlagAndMaybeRefresh(true, true);
    }
    return;
  case 0x20:
    if (GetBoolSlot28() != 0) {
      SetControlStateFlagAndMaybeRefresh(false, true);
    }
    return;
  default:
    break;
  }
  TView::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004fe190
void TFrameRadioView::SetControlStateFlagAndMaybeRefresh(bool fEnabledState, bool fRefreshNow) {
  if (static_cast<unsigned char>(fEnabledState) != controlState64) {
    controlState64 = static_cast<unsigned char>(fEnabledState);
    if (fRefreshNow) {
      RefreshControl();
      InvokeSlot13C();
    }
  }
}
