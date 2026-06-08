#include "game/TCluster.h"

// FUNCTION: IMPERIALISM 0x00491400
TCluster::TCluster() {
  this->hasCommandTagResource = 5;
  this->field84 = 0x20202020;
}

// SYNTHETIC: IMPERIALISM 0x00491480
// TCluster::`scalar deleting destructor'

#include "decomp_types.h"

undefined4 thunk_DispatchPanelControlEvent(void);

void TCluster::DispatchPanelControlEvent(int eventClass, void* eventPayload, int eventFlags) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      this, 0, eventClass, eventPayload, eventFlags);
}

void TCluster::vmethod_0115() {}
void TCluster::ApplyMoveValue(int value) {}
void TCluster::NotifyControlSelectionChange(void* boundEntry) {}
char TCluster::GetControlFlag() { return 0; }
char TCluster::GetBoolSlot1DC() { return 0; }
void TCluster::DoControlAction() {}
