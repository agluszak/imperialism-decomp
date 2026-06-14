#include "game/T2PictToggleButton.h"
#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00662e78
CRuntimeClass g_pClassDescT2PictToggleButton = {0};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00584890
T2PictToggleButton* __cdecl CreateT2PictToggleButtonInstance(void) {
  return new T2PictToggleButton();
}

// FUNCTION: IMPERIALISM 0x00584910
CRuntimeClass* T2PictToggleButton::GetRuntimeClass() {
  return &g_pClassDescT2PictToggleButton;
}

// FUNCTION: IMPERIALISM 0x00584930
T2PictToggleButton::T2PictToggleButton() : TToggleButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00584960
// T2PictToggleButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005849b0
void T2PictToggleButton::IsField3cWithinShortLimit84() {}

// FUNCTION: IMPERIALISM 0x005849d0
void T2PictToggleButton::SyncField0fTowardsField21ByDirectionAndRefresh(char direction) {
  short sVar1;
  void** ppuVar2;

  sVar1 = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x84);
  int field3c = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x3c);

  if (((direction == '\0') && (field3c < (int)sVar1)) ||
      ((direction == '\x01' && ((int)sVar1 < field3c)))) {
    reinterpret_cast<void(__cdecl*)(short, int)>(reinterpret_cast<void***>(this)[0][0x72])(
        (short)field3c, 0);
    *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x3c) = (int)sVar1;
  }
  ppuVar2 = reinterpret_cast<void***>(this)[0];
  reinterpret_cast<void(__cdecl*)()>(ppuVar2[0x3e])();
  reinterpret_cast<void(__cdecl*)(int)>(ppuVar2[0x45])(0);
}

T2PictToggleButton::~T2PictToggleButton() {}
