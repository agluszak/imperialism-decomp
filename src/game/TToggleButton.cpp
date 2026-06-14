#include "game/TToggleButton.h"
#include "game/generated/vcall_facades.h"
#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x0065e598
CRuntimeClass g_pClassDescTToggleButton = {nullptr, 0, 0, nullptr, nullptr};
}

void FreeHeapBufferIfNotNull(undefined4 ptr_value);

// FUNCTION: IMPERIALISM 0x00571050
TToggleButton* __cdecl CreateTToggleButtonInstance(void) {
  return new TToggleButton();
}

// FUNCTION: IMPERIALISM 0x005710d0
CRuntimeClass* TToggleButton::GetRuntimeClass() {
  return &g_pClassDescTToggleButton;
}

// FUNCTION: IMPERIALISM 0x005710f0
TToggleButton::TToggleButton() : TPictureResourceEntryBase() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00571120
// TToggleButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00405f8d
void TToggleButton::TToggleButton_VtblSlot116(int isPressed, int notifyParent) {
  void** ppuVar1 = reinterpret_cast<void***>(this)[0];
  reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(ppuVar1[0x29])(
      this, 0, static_cast<char>(isPressed), static_cast<char>(notifyParent));
  if (static_cast<char>(isPressed) != '\0') {
    void* pField20 = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x20);
    int field1c = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x1c);
    reinterpret_cast<void(__fastcall*)(void*, int, int)>(
        *reinterpret_cast<void**>(reinterpret_cast<char*>(pField20) + 0x1c8))(pField20, 0, field1c);
  }
  reinterpret_cast<void(__cdecl*)()>(ppuVar1[0x3e])();
  reinterpret_cast<void(__cdecl*)(int)>(ppuVar1[0x45])(0);
}
