#include "game/TBoycottButton.h"
#include "game/GameAssert.h"
#include "game/generated/vcall_facades.h"

void FreeHeapBufferIfNotNull(unsigned int ptr_value);


extern "C" {
// GLOBAL: IMPERIALISM 0x662e60
char g_pClassDescTBoycottButton;
}

// FUNCTION: IMPERIALISM 0x005846e0
TBoycottButton* __cdecl CreateTBoycottButtonInstance(void) {
  return new TBoycottButton();
}

// FUNCTION: IMPERIALISM 0x00584760
void* __cdecl GetTBoycottButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTBoycottButton);
}

// FUNCTION: IMPERIALISM 0x00584780
TBoycottButton::TBoycottButton() : TToggleButton() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x005847b0
// TBoycottButton::`scalar deleting destructor'



// FUNCTION: IMPERIALISM 0x00584800
void TBoycottButton::TToggleButton_VtblSlot116(int isPressed, int notifyParent) {
  if (static_cast<char>(isPressed) != '\0') {
    void* result1 = reinterpret_cast<void*(*)()>(reinterpret_cast<void***>(this)[0][0x16])();
    void* result2 = reinterpret_cast<void*(__fastcall*)(void*, int, int)>(
        *reinterpret_cast<void**>(reinterpret_cast<char*>(result1) + 0x94)
    )(result1, 0, 0x636c7573);

    if (result2 == 0) {
      GAME_FAIL_NIL_POINTER();
    }
    reinterpret_cast<void(__fastcall*)(void*, int, int)>(
        *reinterpret_cast<void**>(reinterpret_cast<char*>(result2) + 0x1c8)
    )(result2, 0, 0x20202020);
  }
  TToggleButton::TToggleButton_VtblSlot116(isPressed, notifyParent);
}





