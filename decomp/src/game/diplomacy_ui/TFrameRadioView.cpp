#include "game/diplomacy_ui/TFrameRadioView.h"

#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x004fdf80
TFrameRadioView::~TFrameRadioView() {}

IMPLEMENT_DYNCREATE(TFrameRadioView, TControl)

// FUNCTION: IMPERIALISM 0x004fdfc0
void TFrameRadioView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  if (controlState64 != 0) {
    RECT frame = {1, 1, frameWidth, frameHeight};
    SetQuickDrawFillColor(0);
    QDFrameRect(&frame);
    OffsetRect(&frame, -1, -1);
    SetQuickDrawFillColor(0xffffff);
    QDFrameRect(&frame);
  }
}

// FUNCTION: IMPERIALISM 0x004fe060
void TFrameRadioView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
  case 0xa:
    HandleEvent(kControlCommandHiliteOn, this, nullptr);
    return;
  case 0xc:
    if (controlState64 == 0) {
      if (IsEnabled() != 0) {
        HiliteState(1, false);
      }
    }
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  case 0x1f:
    if (IsEnabled() != 0) {
      HiliteState(1, true);
      return;
    }
    break;
  case 0x20:
    if (IsEnabled() != 0) {
      HiliteState(0, true);
      return;
    }
    break;
  default:
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004fe190
void TFrameRadioView::HiliteState(unsigned char fEnabledState, bool fRefreshNow) {
  if (static_cast<unsigned char>(fEnabledState) != controlState64) {
    controlState64 = static_cast<unsigned char>(fEnabledState);
    if (fRefreshNow) {
      RefreshControl();
      ForceRedraw();
    }
  }
}
