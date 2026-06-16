#include "decomp_types.h"
#include "game/TCivilianOrderState.h"
#include "game/TSelectedCivilianOrderState.h"

undefined4 IsCivilianOrderInIdleSelectionState(void);
undefined4 SetActiveCivilianSelection(void);
undefined4 QueueImmediateCivilianCommandAndCycleSelection(void);
undefined4 ShowDisbandCivilianConfirmationDialog(void);

namespace {

void InvokeSetActiveCivilianSelection(TSelectedCivilianOrderState* self,
                                      TCivilianOrderState* entryContext, int refreshCommandPanel) {
  typedef void (*SetActiveCivilianSelectionDispatch)(TSelectedCivilianOrderState*,
                                                     TCivilianOrderState*, int);
  SetActiveCivilianSelectionDispatch dispatch =
      reinterpret_cast<SetActiveCivilianSelectionDispatch>(SetActiveCivilianSelection);
  dispatch(self, entryContext, refreshCommandPanel);
}

void InvokeQueueImmediateCivilianCommand(TSelectedCivilianOrderState* self, int commandType) {
  typedef void (*QueueCommandDispatch)(TSelectedCivilianOrderState*, int);
  QueueCommandDispatch dispatch =
      reinterpret_cast<QueueCommandDispatch>(QueueImmediateCivilianCommandAndCycleSelection);
  dispatch(self, commandType);
}

void InvokeShowDisbandCivilianConfirmationDialog(TSelectedCivilianOrderState* self) {
  typedef void (*ShowDisbandDispatch)(TSelectedCivilianOrderState*);
  ShowDisbandDispatch dispatch =
      reinterpret_cast<ShowDisbandDispatch>(ShowDisbandCivilianConfirmationDialog);
  dispatch(self);
}

} // namespace

int TCivilianOrderState::IsInIdleSelectionState() {
  typedef int (*IdleSelectionProbe)(TCivilianOrderState*);
  IdleSelectionProbe probe =
      reinterpret_cast<IdleSelectionProbe>(IsCivilianOrderInIdleSelectionState);
  return probe(this);
}

void TSelectedCivilianOrderState::SetActiveCivilianSelection(TCivilianOrderState* entryContext,
                                                             int refreshCommandPanel) {
  InvokeSetActiveCivilianSelection(this, entryContext, refreshCommandPanel);
}

void TSelectedCivilianOrderState::QueueImmediateCivilianCommandAndCycleSelection(int commandType) {
  InvokeQueueImmediateCivilianCommand(this, commandType);
}

void TSelectedCivilianOrderState::ShowDisbandCivilianConfirmationDialog() {
  InvokeShowDisbandCivilianConfirmationDialog(this);
}
