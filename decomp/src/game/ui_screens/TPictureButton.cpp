#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_widgets/TSoundPlayer.h"

IMPLEMENT_DYNCREATE(TPictureButton, TPicture)

// FUNCTION: IMPERIALISM 0x00570850
TPictureButton::~TPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570870
void TPictureButton::HiliteState(unsigned char enabledState, bool refreshNow) {
  if (enabledState != controlState) {
    controlState = enabledState;
    Show(enabledState, true);
    if (refreshNow) {
      DrawImmediate();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005708c0
void TPictureButton::DrawImmediate() {
  CRect rect;
  CRect* redrawRect = GetQDExtent(&rect);
  CWnd* nativeWindow = this->nativeWindow;
  RedrawWindow(nativeWindow->m_hWnd, redrawRect, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
}

// FUNCTION: IMPERIALISM 0x00570900
void TPictureButton::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(clickSoundId, 0, 1);
  TControl::DoMouseCommand(point, event, origin);
}
