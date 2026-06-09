#include "decomp_types.h"
#include "game/TCivilianOrderState.h"
#include "game/TSelectedCivilianOrderState.h"

undefined4 thunk_IsCivilianOrderInIdleSelectionState(void);
undefined4 thunk_SetActiveCivilianSelection(void);
undefined4 thunk_QueueImmediateCivilianCommandAndCycleSelection(void);
undefined4 thunk_ShowDisbandCivilianConfirmationDialog(void);

int TCivilianOrderState::IsInIdleSelectionState() {
  return reinterpret_cast<int(__fastcall*)(void*)>(thunk_IsCivilianOrderInIdleSelectionState)(this);
}

void TSelectedCivilianOrderState::SetActiveCivilianSelection(TCivilianOrderState* entryContext,
                                                             int refreshCommandPanel) {
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_SetActiveCivilianSelection)(
      this, 0, entryContext, refreshCommandPanel);
}

void TSelectedCivilianOrderState::QueueImmediateCivilianCommandAndCycleSelection(int commandType) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      thunk_QueueImmediateCivilianCommandAndCycleSelection)(this, 0, commandType);
}

void TSelectedCivilianOrderState::ShowDisbandCivilianConfirmationDialog() {
  reinterpret_cast<void(__fastcall*)(void*)>(thunk_ShowDisbandCivilianConfirmationDialog)(this);
}
