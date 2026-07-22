#include "game/TUpDownPictureButton.h"
#include "game/TWindow.h"
#include "game/TAmtBar.h"
#include "game/TView.h"
#include "game/global_data_tables.h"
#include "game/TSoundPlayer.h"
// SYNTHETIC: IMPERIALISM 0x00571500
// TUpDownPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00571580
// TUpDownPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUpDownPictureButton, TPicture)

// SYNTHETIC: IMPERIALISM 0x005715d0
// TUpDownPictureButton::`scalar deleting destructor'
TUpDownPictureButton::~TUpDownPictureButton() {}

// FUNCTION: IMPERIALISM 0x005715a0
TUpDownPictureButton::TUpDownPictureButton() : TPicture(), timingWord92(7000) {}

// FUNCTION: IMPERIALISM 0x00571620
void TUpDownPictureButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  char mode = enabledState ? 1 : 0;
  if (mode != static_cast<char>(controlState64)) {
    controlState64 = static_cast<unsigned char>(mode);
    short bitmapId =
        mode == 0 ? static_cast<short>(glyphBase84 - 1) : static_cast<short>(glyphBase84 + 1);
    reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00571690
bool TUpDownPictureButton::DrawImmediate() {
  GetWindow()->ForceRedraw();
  return true;
}

// FUNCTION: IMPERIALISM 0x005716b0
void TUpDownPictureButton::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point,
                                                                TToolboxEvent* event,
                                                                CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(timingWord92, 0, 1);
  TControl::BeginMouseCaptureAndStartRepeatTimer(point, event, origin);
}
