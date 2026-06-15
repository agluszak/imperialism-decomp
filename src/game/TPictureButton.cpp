#include "game/TPictureButton.h"
#include "game/CRuntimeClass.h"

extern "C" CRuntimeClass PTR_s_TPictureButton_0065e538;

// FUNCTION: IMPERIALISM 0x005707d0
CRuntimeClass* TPictureButton::GetRuntimeClass() const {
  return &PTR_s_TPictureButton_0065e538;
}

// FUNCTION: IMPERIALISM 0x005707f0
TPictureButton::TPictureButton() : TPictureResourceEntryBase(), timingWord92(7000) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00570820
// TPictureButton::`scalar deleting destructor'

TPictureButton::~TPictureButton() {}

const unsigned int kAddrSfxPlaybackSystem = 0x006A43EC;

// FUNCTION: IMPERIALISM 0x00570870
void TPictureButton::SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) {
  if (static_cast<unsigned char>(enabledState) != this->commandTagResourceByte) {
    this->commandTagResourceByte = enabledState;
    this->SetEnabled(enabledState, true);
    if (refreshNow) {
      this->IsSelected(-1, true);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00570900
void TPictureButton::BeginMouseCaptureAndStartRepeatTimer(Point32* point, int arg2, int arg3,
                                                          int arg4) {
  int sfxSystem = *reinterpret_cast<int*>(kAddrSfxPlaybackSystem);
  reinterpret_cast<void(__cdecl*)(int, int, int)>(
      *reinterpret_cast<void**>(*reinterpret_cast<int*>(sfxSystem) + 0xb8))(timingWord92, 0, 1);
  TControl::BeginMouseCaptureAndStartRepeatTimer(point, arg2, arg3, arg4);
}
