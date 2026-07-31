#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_widgets/TSoundPlayer.h"

// SYNTHETIC: IMPERIALISM 0x00570750
// TPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005707d0
// TPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureButton, TPicture)

// TPictureButton's ctor is defined inline in the header (marker there): the original
// inlines it into every derived ctor.

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00570820
// TPictureButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00570850
TPictureButton::~TPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570870
void TPictureButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  if (static_cast<unsigned char>(enabledState) != this->controlState64) {
    this->controlState64 = enabledState;
    this->Show(enabledState, true);
    if (refreshNow) {
      this->DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005708c0
void TPictureButton::DrawImmediate() {
  CRect rect;
  CRect* redrawRect = this->GetQDExtent(&rect);
  CWnd* nativeWindow = this->nativeWindow50;
  RedrawWindow(nativeWindow->m_hWnd, redrawRect, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
}

// FUNCTION: IMPERIALISM 0x00570900
void TPictureButton::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(timingWord92, 0, 1);
  TControl::DoMouseCommand(point, event, origin);
}
