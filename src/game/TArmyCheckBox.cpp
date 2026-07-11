#include "game/TArmyCheckBox.h"

// SYNTHETIC: IMPERIALISM 0x004a9400
// TArmyCheckBox::`scalar deleting destructor'
TArmyCheckBox::~TArmyCheckBox() {}
// SYNTHETIC: IMPERIALISM 0x004a9f20
// TArmyCheckBox::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a9fc0
// TArmyCheckBox::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyCheckBox, TControl)

TArmyCheckBox::TArmyCheckBox() {}

// FUNCTION: IMPERIALISM 0x004a9fe0
TArmyCheckBox::TArmyCheckBox(TView* panel, int* offsetLayout, int* sizeLayout, int unused1,
                             int unused2, int field90Value, int field88Value)
    : TControl() {
  (void)unused1;
  (void)unused2;
  InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, sizeLayout, 4, 4, 0);
  field90 = field90Value;
  field88 = field88Value;
}

// FUNCTION: IMPERIALISM 0x004aa030
undefined TArmyCheckBox::VTableSlot73(char param_1) {
  (void)param_1;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa100
void TArmyCheckBox::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x004aa280
void TArmyCheckBox::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x004aa2f0
void TArmyCheckBox::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x004aa310
void TArmyCheckBox::SetControlStateFlagAndMaybeRefresh(bool fEnabledState, bool fRefreshNow) {}

// FUNCTION: IMPERIALISM 0x004aa340
undefined TArmyCheckBox::OrphanLeaf_NoCall_Ins02_004aa340() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa360
undefined TArmyCheckBox::SetArmyUnitLineActiveFlagAndNotify() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa3a0
undefined TArmyCheckBox::OrphanCallChain_C2_I16_004aa3a0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa3e0
undefined TArmyCheckBox::OrphanCallChain_C3_I23_004aa3e0(char param_1, undefined4 param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004aa430
undefined TArmyCheckBox::OrphanCallChain_C1_I05_004aa430() {
  return 0;
}
