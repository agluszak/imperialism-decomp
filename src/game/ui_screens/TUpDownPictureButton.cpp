#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_widgets/TSoundPlayer.h"
// SYNTHETIC: IMPERIALISM 0x00571500
// TUpDownPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00571580
// TUpDownPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUpDownPictureButton, TPicture)

// TUpDownPictureButton's ctor is defined inline in the header (marker there): the
// original inlines it into every derived ctor.

// SYNTHETIC: IMPERIALISM 0x005715d0
// TUpDownPictureButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00571600
TUpDownPictureButton::~TUpDownPictureButton() {}

// FUNCTION: IMPERIALISM 0x00571620
void TUpDownPictureButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  if (enabledState != controlState64) {
    controlState64 = enabledState;
    SetPictureResourceIdAndRefresh(enabledState != 0 ? static_cast<short>(glyphBase84 + 1)
                                                     : static_cast<short>(glyphBase84 - 1),
                                   1);
    if (refreshNow) {
      DrawImmediate();
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
