#include "game/TPictureButton.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"
#include "game/TSoundPlayer.h"

// SYNTHETIC: IMPERIALISM 0x00570750
// TPictureButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x005707d0
// TPictureButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureButton, TPicture)

// FUNCTION: IMPERIALISM 0x005707f0
TPictureButton::TPictureButton() : TPicture(), timingWord92(7000) {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x00570820
// TPictureButton::`scalar deleting destructor'

TPictureButton::~TPictureButton() {}

// FUNCTION: IMPERIALISM 0x00570870
void TPictureButton::HiliteState(unsigned char enabledState, unsigned char refreshNow) {
  if (static_cast<unsigned char>(enabledState) != this->controlState64) {
    this->controlState64 = enabledState;
    this->SetEnabled(enabledState, true);
    if (refreshNow) {
      this->IsSelected();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005708c0
bool TPictureButton::IsSelected() {
  CRect rect;
  this->GetQDExtent(&rect);
  return RedrawWindow(reinterpret_cast<HWND>(this->nativeWindow50->m_hWnd), &rect, NULL,
                      RDW_INVALIDATE | RDW_UPDATENOW);
}

// FUNCTION: IMPERIALISM 0x00570900
void TPictureButton::BeginMouseCaptureAndStartRepeatTimer(const CPoint& point, TToolboxEvent* event,
                                                          CPoint origin) {
  g_pSfxPlaybackSystem->PlaySoundEffect(timingWord92, 0, 1);
  TControl::BeginMouseCaptureAndStartRepeatTimer(point, event, origin);
}
