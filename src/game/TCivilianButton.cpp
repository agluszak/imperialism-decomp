#include "game/TCivilianButton.h"
#include "game/generated/vcall_facades.h"

int g_pClassDescTCivilianButton;

// FUNCTION: IMPERIALISM 0x0058b340
void* __cdecl CreateTCivilianButtonInstance(void) {
  return new TCivilianButton();
}

// FUNCTION: IMPERIALISM 0x0058b3c0
void* __cdecl GetTCivilianButtonClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCivilianButton);
}

// FUNCTION: IMPERIALISM 0x0058b3e0
TCivilianButton::TCivilianButton() : TRadioPictureButton() {
  this->hasCommandTagResource = 0xc;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058b410
// TCivilianButton::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x0058B460
void TCivilianButton::SetSelectionAndEnableByMappedValue(int selectedValue) {
  this->hasCommandTagResource = 0xc;
  this->selectedValue9c = (short)selectedValue;
  if (selectedValue != 0) {
    VCall_TRadioPictureButton_SlotA4(this, 1, 0);
    VCall_TRadioPictureButton_SlotA8(this, 1, 0);

    char* globalMapState = reinterpret_cast<char**>(0x00693a10)[0]; // g_pGlobalMapState
    short mappedValue = reinterpret_cast<short(__fastcall*)(int)>(
        *reinterpret_cast<int*>(globalMapState + 0x118))(selectedValue);
    this->mappedSelection98 = mappedValue;
    return;
  }
  VCall_TRadioPictureButton_SlotA4(this, 0, 1);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

TCivilianButton::~TCivilianButton() {}
