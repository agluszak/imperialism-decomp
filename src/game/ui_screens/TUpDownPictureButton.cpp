#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_widgets/TSoundPlayer.h"
// SYNTHETIC: IMPERIALISM 0x00571500
// TUpDownPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00571580
// TUpDownPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUpDownPictureButton, TPicture)

// FUNCTION: IMPERIALISM 0x005715a0
TUpDownPictureButton::TUpDownPictureButton() : TPicture(), timingWord92(7000) {}

// SYNTHETIC: IMPERIALISM 0x005715d0
// TUpDownPictureButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00571600
TUpDownPictureButton::~TUpDownPictureButton() {}

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
void TUpDownPictureButton::DrawImmediate() {
  GetWindow()->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x005716b0
void TUpDownPictureButton::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(timingWord92, 0, 1);
  TControl::DoMouseCommand(point, event, origin);
}
