#pragma optimize("y", on)
// TCivToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TCivToolbar.h"
#include "game/TUberCluster.h"
#include "game/TTradeCluster.h"
#include "game/TCivDescription.h"
#include "game/TCivUnit.h"
#include "game/TSelectedCivilianOrderState.h"
#include "game/TGlobalMapState.h"
#include "game/TPanelEventPayload.h"

#include "game/TControl.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/TUiRuntimeContext.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/TSimMgr.h"
#include "game/ui_control_tags.h"
#include "game/TSoundPlayer.h"
#include "game/TGreatPower.h"
#include "game/TMapUberPicture.h"
#include "game/TViewMgr.h"
#include "game/ui_invalidation_guard.h"

#define GAME_ASSERT(cond, line)                                                                    \
  if (!(cond)) {                                                                                   \
    GAME_FAIL_NIL_POINTER();                                                                       \
    reinterpret_cast<void(__cdecl*)(const char*, int)>(                                            \
        TemporarilyClearAndRestoreUiInvalidationFlag)("D:\\Ambit\\Cross\\USmallViews.cpp", line);  \
  }

namespace {

undefined4 ShowCivilianLedgerDialogAndSelectUnit(void);

} // namespace

// 0x004d3a60 (HandleEngineerConstructionAction) lives on TCivMgr — see TCivMgr.cpp.

// FUNCTION: IMPERIALISM 0x0058ea00
TCivToolbar* __cdecl CreateTCivToolbarInstance(void) {
  return new TCivToolbar();
}
IMPLEMENT_DYNCREATE(TCivToolbar, TCluster)

// FUNCTION: IMPERIALISM 0x0058eaa0
TCivToolbar::TCivToolbar() {}

// SYNTHETIC: IMPERIALISM 0x0058ead0
// TCivToolbar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058eb20
void TCivToolbar::RefreshCivilianCommandPanelForSelection(TCivUnit* selectedOrder) {
  this->civilianClassId = selectedOrder ? selectedOrder->orderType : -1;

  TControl* unitControl = this->ResolveControlByTag(0x756e6974);
  if (unitControl == 0) {
    return;
  }

  if (selectedOrder == 0) {
    unitControl->SetEnabled(0, 1);
  } else {
    reinterpret_cast<TCluster*>(unitControl)
        ->SetControlClassAndRefresh(this->civilianClassId + 0x438);
    unitControl->SetEnabled(1, 1);
  }

  TCivDescription* backControl =
      static_cast<TCivDescription*>(static_cast<TView*>(this->ResolveControlByTag(0x6261636b)));
  if (backControl == 0) {
    return;
  }

  if (selectedOrder == 0) {
    backControl->selectedCivilianClass = -1;
    return;
  }

  if (this->civilianClassId != backControl->selectedCivilianClass) {
    backControl->selectedCivilianClass = this->civilianClassId;

    switch (this->civilianClassId) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 5:
    case 7:
    case 8:
      backControl->legendInitialized = 0;
      backControl->UpdateCivilianOrderTargetTileCountsForOwnerNation(selectedOrder);
      break;
    }

    backControl->RefreshControl();
  }
}

/* Refreshes civilian stack controls (stk0..stk5) for the selected tile and syncs command button
   enable state. */

// FUNCTION: IMPERIALISM 0x0058ec50
void TCivToolbar::RefreshCivilianStackButtonsForTile(short tileIndex) {
  int commandEnabled;
  int selectedSlotTag;
  int slotIndex;
  TControl* selectedStackButton;
  TCivUnit* selectedTileEntry;
  TControl* stackButton;
  TSelectedCivilianOrderState* selectedCivilianState;
  int mapState;

  selectedTileEntry = g_pGlobalMapState->GetFirstCivilianOrderOnTile(tileIndex);
  selectedStackButton = 0;
  selectedCivilianState =
      reinterpret_cast<TSelectedCivilianOrderState*>(g_pSelectedCivilianOrderState);

  for (slotIndex = 0; (selectedTileEntry != 0) && (slotIndex < 6); slotIndex = slotIndex + 1) {
    stackButton = this->ResolveControlByTag(0x73746b30 + slotIndex);
    GAME_ASSERT(stackButton != 0, 5585);
    reinterpret_cast<TTradeCluster*>(stackButton)->NotifyControlSelectionChange(selectedTileEntry);
    stackButton->SetEnabled(selectedTileEntry->IsInIdleSelectionState(), 1);
    if ((selectedCivilianState != 0) &&
        (selectedTileEntry == selectedCivilianState->selectedEntry)) {
      selectedStackButton = stackButton;
    }
    selectedTileEntry = static_cast<TCivUnit*>(selectedTileEntry->nextOnTile);
  }
  while (slotIndex < 6) {
    stackButton = this->ResolveControlByTag(0x73746b30 + slotIndex);
    GAME_ASSERT(stackButton != 0, 5585);
    reinterpret_cast<TTradeCluster*>(stackButton)->NotifyControlSelectionChange(0);
    slotIndex = slotIndex + 1;
  }

  selectedSlotTag = 0x6e616461;
  if (selectedStackButton != 0) {
    selectedSlotTag = selectedStackButton->controlTag;
  }
  reinterpret_cast<TCluster*>(this)->SetControlClassAndRefresh(selectedSlotTag);

  commandEnabled = (selectedStackButton != 0) ? 1 : 0;
  stackButton = this->ResolveControlByTag(0x64666e64);
  if (stackButton == 0) {
    return;
  }
  stackButton->SetEnabled(commandEnabled, 1);
  stackButton = this->ResolveControlByTag(0x6c617472);
  if (stackButton == 0) {
    return;
  }
  stackButton->SetEnabled(commandEnabled, 1);
  stackButton = this->ResolveControlByTag(0x646f6e65);
  if (stackButton == 0) {
    return;
  }
  stackButton->SetEnabled(commandEnabled, 1);
}

// FUNCTION: IMPERIALISM 0x0058eed0
void TCivToolbar::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TPanelEventPayload* eventPayload = reinterpret_cast<TPanelEventPayload*>(event);
  int eventFlags = 0;
  (void)sourceHandler;
  // ORIG_CALLCONV: __thiscall

  TSelectedCivilianOrderState* selectedCivilianOrderState = g_pSelectedCivilianOrderState;
  if (commandId == 0xc) {
    if ((kTagStackSlotMin <= static_cast<unsigned int>(eventPayload->controlTag)) &&
        (static_cast<unsigned int>(eventPayload->controlTag) <= kTagStackSlotMax)) {
      selectedCivilianOrderState->SetActiveCivilianSelection(eventPayload->selectedEntryContext, 0);
      this->TCluster::HandleEvent(0xc, reinterpret_cast<TEventHandler*>(eventPayload),
                                  reinterpret_cast<TEvent*>(eventFlags));
      return;
    }
  } else if (commandId == 10) {
    unsigned int controlTag = eventPayload->controlTag;
    if (controlTag < 0x646f6e6f) {
      if (controlTag == kTagDone) {
        selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(4);
        this->TCluster::HandleEvent(10, reinterpret_cast<TEventHandler*>(eventPayload),
                                    reinterpret_cast<TEvent*>(eventFlags));
        return;
      }
      if (controlTag == kTagDefend) {
        selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(2);
        this->TCluster::HandleEvent(10, reinterpret_cast<TEventHandler*>(eventPayload),
                                    reinterpret_cast<TEvent*>(eventFlags));
        return;
      }
    } else {
      if (controlTag == kTagGarrison) {
        unsigned short ctrlState = (unsigned short)GetAsyncKeyState(0x11);
        if ((ctrlState & 0x8000) != 0) {
          ShowCivilianLedgerDialogAndSelectUnit();
          this->TCluster::HandleEvent(10, reinterpret_cast<TEventHandler*>(eventPayload),
                                      reinterpret_cast<TEvent*>(eventFlags));
          return;
        }
        selectedCivilianOrderState->ShowDisbandCivilianConfirmationDialog();
      } else if (controlTag == kTagLater) {
        selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(3);
        this->TCluster::HandleEvent(10, reinterpret_cast<TEventHandler*>(eventPayload),
                                    reinterpret_cast<TEvent*>(eventFlags));
        return;
      }
    }
  }
  this->TCluster::HandleEvent(commandId, reinterpret_cast<TEventHandler*>(eventPayload),
                              reinterpret_cast<TEvent*>(eventFlags));
}

undefined4 CycleMapInteractionSelectionAfterHandledClick(void);

void TCivToolbar::CycleMapInteractionSelectionAfterHandledClick() {
  typedef void (*CycleMapInteractionDispatch)(TCivToolbar*);
  CycleMapInteractionDispatch dispatch = reinterpret_cast<CycleMapInteractionDispatch>(
      ::CycleMapInteractionSelectionAfterHandledClick);
  dispatch(this);
}

TCivToolbar::~TCivToolbar() {}
