#include "game/TRadioText.h"

// SYNTHETIC: IMPERIALISM 0x0043daa0
// TRadioText::`scalar deleting destructor'
TRadioText::~TRadioText() {}
// SYNTHETIC: IMPERIALISM 0x005793f0
// TRadioText::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579470
// TRadioText::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioText, TDropShadowText)

// FUNCTION: IMPERIALISM 0x0043d990
TRadioText::TRadioText() : TDropShadowText() {}

// FUNCTION: IMPERIALISM 0x00579490
void TRadioText::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005794b0
void TRadioText::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00579580
void TRadioText::RefreshAndNotifyOwnerSlot13C() {
  RefreshControl();
  OwnerPanel()->InvokeSlot13C();
}
