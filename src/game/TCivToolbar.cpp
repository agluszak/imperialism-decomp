#pragma optimize("y", on)
// TCivToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/TCivToolbar.h"
#include "game/TControl.h"

struct PanelEventPayload {
  char pad_00[0x1c];
  unsigned int controlTag;
  char pad_20[0x7c];
  void* selectedEntryContext;
};

extern "C" short __stdcall GetAsyncKeyState(int virtual_key_code);

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_SetActiveCivilianSelection(void);
undefined4 thunk_DispatchPanelControlEvent(void);
undefined4 thunk_QueueImmediateCivilianCommandAndCycleSelection(void);
undefined4 thunk_ShowDisbandCivilianConfirmationDialog(void);
undefined4 thunk_UpdateCivilianOrderTargetTileCountsForOwnerNation(void);
undefined4 thunk_ShowCivilianLedgerDialogAndSelectUnit(void);
undefined4 thunk_IsCivilianOrderInIdleSelectionState(void);

namespace {

// GLOBAL: IMPERIALISM 0x667f00
char g_vtblTCivToolbar;
// GLOBAL: IMPERIALISM 0x663100
char g_pClassDescTCivToolbar;

const unsigned int kAddrSelectedCivilianOrderState = 0x006A43DC;
const unsigned int kAddrGlobalMapState = 0x006A43D4;
const unsigned int kTagStackSlotMin = 0x73746B30;
const unsigned int kTagStackSlotMax = 0x73746B35;
const unsigned int kTagDone = 0x646F6E65;
const unsigned int kTagDefend = 0x64666E64;
const unsigned int kTagLater = 0x6C617472;
const unsigned int kTagGarrison = 0x67617272;

struct SelectedCivilianState {
  unsigned char pad_00[0x04];
  void* selectedEntry;

  void SetActiveCivilianSelection(void* entryContext, int refreshCommandPanel) {
    reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_SetActiveCivilianSelection)(
        this, 0, entryContext, refreshCommandPanel);
  }

  void QueueImmediateCivilianCommandAndCycleSelection(int commandType) {
    reinterpret_cast<void(__fastcall*)(void*, int, int)>(
        thunk_QueueImmediateCivilianCommandAndCycleSelection)(this, 0, commandType);
  }

  void ShowDisbandCivilianConfirmationDialog() {
    reinterpret_cast<void(__fastcall*)(void*)>(thunk_ShowDisbandCivilianConfirmationDialog)(
        this);
  }
};

struct CivilianOrderEntry {
  int IsInIdleSelectionState() {
    return reinterpret_cast<int(__fastcall*)(void*)>(thunk_IsCivilianOrderInIdleSelectionState)(
        this);
  }
};

struct CivilianTileEntry {
  unsigned char pad_00_to_13[0x14];
  CivilianTileEntry* pNextOnTile;
};













} // namespace

// FUNCTION: IMPERIALISM 0x0058ea00
TCivToolbar* __cdecl CreateTCivToolbarInstance(void) {
  return new TCivToolbar();
}

// FUNCTION: IMPERIALISM 0x0058ea80
void* __cdecl GetTCivToolbarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCivToolbar);
}

// FUNCTION: IMPERIALISM 0x0058eaa0
TCivToolbar::TCivToolbar() {}

// SYNTHETIC: IMPERIALISM 0x0058ead0
// TCivToolbar::`scalar deleting destructor'

/* Handles civilian command-panel actions from map UI button clicks and stack-slot picks.
   Algorithm:
   1. For stack-slot event class, detect 'stk0'..'stk5' controls and activate selected civilian
   slot.
   2. For command event class, decode 4CC control tag from payload.
   3. Tag 'done': queue immediate command type 4 (No orders this turn).
   4. Tag 'dfnd': queue immediate command type 2 (Sleep).
   5. Tag 'latr': queue immediate command type 3 (Next Unit).
   6. Tag 'garr': if CTRL held, open civilian ledger; otherwise open disband confirmation.
   7. Forward event to panel dispatcher after handling branch.
   Parameters:
   - nEventClass: Event category discriminator.
   - pEventPayload: UI payload block containing control tag and control context.
   - nEventFlags: Additional UI dispatch flags.
   Returns:
   - None. */

/* Refreshes civilian command panel controls for the currently selected civilian entry. */

// FUNCTION: IMPERIALISM 0x0058eb20
void TCivToolbar::RefreshCivilianCommandPanelForSelection(int* selectedCivilianOrderEntry) {
  TControl* backControl;
  short newCivilianClassId;
  TControl* unitControl;

  newCivilianClassId = (short)selectedCivilianOrderEntry[1];
  this->civilianClassId = newCivilianClassId;

  unitControl = this->ResolveControlByTag(0x756e6974);
  if (unitControl == 0) {
    return;
  }
  if (selectedCivilianOrderEntry == 0) {
    unitControl->SetEnabled(0, 1);
  } else {
    unitControl->SetControlClassAndRefresh(civilianClassId + 0x438, 1);
    unitControl->SetEnabled(1, 1);
  }

  backControl = this->ResolveControlByTag(0x6261636b);
  if (backControl == 0) {
    return;
  }
  if (selectedCivilianOrderEntry == 0) {
    *reinterpret_cast<short*>(reinterpret_cast<char*>(backControl) + 0x18) = (short)-1;
    return;
  }
  if (newCivilianClassId != *reinterpret_cast<short*>(reinterpret_cast<char*>(backControl) + 0x18)) {
    *reinterpret_cast<short*>(reinterpret_cast<char*>(backControl) + 0x18) = newCivilianClassId;
    switch (newCivilianClassId) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 5:
    case 7:
    case 8:
      *reinterpret_cast<unsigned char*>(reinterpret_cast<char*>(backControl) + 0x6c) = 0;
      reinterpret_cast<void(__fastcall*)(void*, int, int*)>(
          thunk_UpdateCivilianOrderTargetTileCountsForOwnerNation)(backControl, 0,
                                                                   selectedCivilianOrderEntry);
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
  CivilianTileEntry* selectedTileEntry;
  TControl* stackButton;
  SelectedCivilianState* selectedCivilianState;
  int mapState;

  mapState = *reinterpret_cast<int*>(kAddrGlobalMapState);
  selectedTileEntry = *reinterpret_cast<CivilianTileEntry**>(
      *reinterpret_cast<int*>(mapState + 0xc) + 0x20 + tileIndex * 0x24);
  selectedStackButton = 0;
  selectedCivilianState =
      reinterpret_cast<SelectedCivilianState*>((*reinterpret_cast<SelectedCivilianState**>(kAddrSelectedCivilianOrderState)));

  for (slotIndex = 0; (selectedTileEntry != 0) && (slotIndex < 6); slotIndex = slotIndex + 1) {
    stackButton = this->ResolveControlByTag(0x73746b30 + slotIndex);
    if (stackButton == 0) {
      return;
    }
    stackButton->NotifyControlSelectionChange(selectedTileEntry);
    stackButton->SetEnabled(reinterpret_cast<CivilianOrderEntry*>(selectedTileEntry)->IsInIdleSelectionState(), 1);
    if ((selectedCivilianState != 0) &&
        (selectedTileEntry == selectedCivilianState->selectedEntry)) {
      selectedStackButton = stackButton;
    }
    selectedTileEntry = selectedTileEntry->pNextOnTile;
  }
  while (slotIndex < 6) {
    stackButton = this->ResolveControlByTag(0x73746b30 + slotIndex);
    if (stackButton == 0) {
      return;
    }
    stackButton->NotifyControlSelectionChange(0);
    slotIndex = slotIndex + 1;
  }

  selectedSlotTag = 0x6e616461;
  if (selectedStackButton != 0) {
    selectedSlotTag = reinterpret_cast<int*>(selectedStackButton)[7];
  }
  this->SetControlClassAndRefresh(selectedSlotTag, 0);

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
void TCivToolbar::HandleCivilianMapCommandPanelAction(int eventClass, PanelEventPayload* eventPayload,
                                                      int eventFlags) {
  // ORIG_CALLCONV: __thiscall

  SelectedCivilianState* selectedCivilianOrderState = (*reinterpret_cast<SelectedCivilianState**>(kAddrSelectedCivilianOrderState));
  if (eventClass == 0xc) {
    if ((kTagStackSlotMin <= eventPayload->controlTag) &&
        (eventPayload->controlTag <= kTagStackSlotMax)) {
      selectedCivilianOrderState->SetActiveCivilianSelection(eventPayload->selectedEntryContext, 0);
      this->DispatchPanelControlEvent(0xc, eventPayload, eventFlags);
      return;
    }
  } else if (eventClass == 10) {
    unsigned int controlTag = eventPayload->controlTag;
    if (controlTag < 0x646f6e6f) {
      if (controlTag == kTagDone) {
        selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(4);
        this->DispatchPanelControlEvent(10, eventPayload, eventFlags);
        return;
      }
      if (controlTag == kTagDefend) {
        selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(2);
        this->DispatchPanelControlEvent(10, eventPayload, eventFlags);
        return;
      }
    } else {
      if (controlTag == kTagGarrison) {
        unsigned short ctrlState = (unsigned short)GetAsyncKeyState(0x11);
        if ((ctrlState & 0x8000) != 0) {
          thunk_ShowCivilianLedgerDialogAndSelectUnit();
          this->DispatchPanelControlEvent(10, eventPayload, eventFlags);
          return;
        }
        selectedCivilianOrderState->ShowDisbandCivilianConfirmationDialog();
      } else if (controlTag == kTagLater) {
        selectedCivilianOrderState->QueueImmediateCivilianCommandAndCycleSelection(3);
        this->DispatchPanelControlEvent(10, eventPayload, eventFlags);
        return;
      }
    }
  }
  this->DispatchPanelControlEvent(eventClass, eventPayload, eventFlags);
}
