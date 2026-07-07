#include "game/TUpDownPictureButton.h"
#include "game/TAmtBar.h"
#include "game/TView.h"

const unsigned int kAddrSfxPlaybackSystem = 0x006a4510;
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
void TUpDownPictureButton::SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) {
  char mode = enabledState ? 1 : 0;
  if (mode != static_cast<char>(commandTagResourceByte)) {
    commandTagResourceByte = static_cast<unsigned char>(mode);
    short bitmapId =
        mode == 0 ? static_cast<short>(glyphBase84 - 1) : static_cast<short>(glyphBase84 + 1);
    reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00571690
bool TUpDownPictureButton::IsSelected() {
  OwnerPanel()->InvokeSlot13C();
  return true;
}

// FUNCTION: IMPERIALISM 0x005716b0
void TUpDownPictureButton::BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                                int arg4) {
  int sfxSystem = *reinterpret_cast<int*>(kAddrSfxPlaybackSystem);
  reinterpret_cast<void(__cdecl*)(int, int, int)>(
      *reinterpret_cast<void**>(*reinterpret_cast<int*>(sfxSystem) + 0xb8))(timingWord92, 0, 1);
  TView::BeginMouseCaptureAndStartRepeatTimer(point, arg2, arg3, arg4);
}
