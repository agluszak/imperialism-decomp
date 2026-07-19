#include "game/TFrameRadioView.h"

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
}

// FUNCTION: IMPERIALISM 0x004fe060
void TFrameRadioView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  switch (commandId) {
    case 0xa:
      DispatchEvent(0x1f, this, nullptr);
      return;
    case 0xc:
      if (controlState64 == 0) {
        if (GetBoolSlot28() != 0) {
          SetControlStateFlagAndMaybeRefresh(1, 0);
        }
      }
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
    case 0x1f:
      if (GetBoolSlot28() != 0) {
        SetControlStateFlagAndMaybeRefresh(1, 1);
        return;
      }
      break;
    case 0x20:
      if (GetBoolSlot28() != 0) {
        SetControlStateFlagAndMaybeRefresh(0, 1);
        return;
      }
      break;
    default:
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
  }
}

// FUNCTION: IMPERIALISM 0x004fe190
void TFrameRadioView::SetControlStateFlagAndMaybeRefresh(bool fEnabledState, bool fRefreshNow) {
}
