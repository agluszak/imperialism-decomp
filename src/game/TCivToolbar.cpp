// TCivToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

extern "C" short __stdcall GetAsyncKeyState(int virtual_key_code);

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_SetActiveCivilianSelection(void);
undefined4 thunk_DispatchPanelControlEvent(void);
undefined4 thunk_QueueImmediateCivilianCommandAndCycleSelection(void);
undefined4 thunk_ShowCivilianLedgerDialogAndSelectUnit(void);
undefined4 thunk_ShowDisbandCivilianConfirmationDialog(void);
undefined4 thunk_UpdateCivilianOrderTargetTileCountsForOwnerNation(void);
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

struct CivToolbarState {
  void* vftable;
  char pad_04[0x88];
};

struct PanelEventPayload {
  char pad_00[0x1c];
  unsigned int controlTag;
  char pad_20[0x7c];
  void* selectedEntryContext;
};

struct SelectedCivilianState {
  unsigned char pad_00[0x04];
  void* selectedEntry;
};

struct CivilianTileEntry {
  unsigned char pad_00_to_13[0x14];
  CivilianTileEntry* pNextOnTile;
};

class RuntimeBridge {
public:
  static __inline void ConstructUiResourceEntryType4B0C0(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }
};

static __inline void* QuerySelectedCivilianOrderState() {
  return *reinterpret_cast<void**>(kAddrSelectedCivilianOrderState);
}

static __inline void DispatchPanelControlEvent(CivToolbarState* toolbar, int eventClass,
                                               void* eventPayload, int eventFlags) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, void*, int)>(thunk_DispatchPanelControlEvent)(
      toolbar, 0, eventClass, eventPayload, eventFlags);
}

static __inline void SetActiveCivilianSelection(void* selectedState, void* entryContext,
                                                int refreshCommandPanel) {
  reinterpret_cast<void(__fastcall*)(void*, int, void*, int)>(thunk_SetActiveCivilianSelection)(
      selectedState, 0, entryContext, refreshCommandPanel);
}

static __inline void QueueImmediateCivilianCommandAndCycleSelection(void* selectedState,
                                                                    int commandType) {
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      thunk_QueueImmediateCivilianCommandAndCycleSelection)(selectedState, 0, commandType);
}

static __inline void ShowDisbandCivilianConfirmationDialog(void* selectedState) {
  reinterpret_cast<void(__fastcall*)(void*)>(thunk_ShowDisbandCivilianConfirmationDialog)(
      selectedState);
}

static __inline int* ResolveControlByTag(CivToolbarState* toolbar, unsigned int controlTag) {
  return reinterpret_cast<int*(__fastcall*)(void*, int, unsigned int)>(
      reinterpret_cast<int*>(toolbar->vftable)[0x25])(toolbar, 0, controlTag);
}

static __inline void SetControlEnabledAndRefresh(int* control, int enabledState, int refreshFlag) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(reinterpret_cast<int*>(
      *reinterpret_cast<void**>(control))[0x2a])(control, 0, enabledState, refreshFlag);
}

static __inline void SetControlClassAndRefresh(int* control, int classState, int refreshFlag) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(reinterpret_cast<int*>(
      *reinterpret_cast<void**>(control))[0x72])(control, 0, classState, refreshFlag);
}

static __inline void SetControlBoundEntry(int* control, void* boundEntry) {
  reinterpret_cast<void(__fastcall*)(void*, int, void*)>(
      reinterpret_cast<int*>(*reinterpret_cast<void**>(control))[0x75])(control, 0, boundEntry);
}

static __inline void RefreshControl(int* control) {
  reinterpret_cast<void(__fastcall*)(void*)>(
      reinterpret_cast<int*>(*reinterpret_cast<void**>(control))[0x39])(control);
}

static __inline int IsCivilianOrderInIdleSelectionStateBridge(void* civilianOrderEntry) {
  return reinterpret_cast<int(__fastcall*)(void*)>(thunk_IsCivilianOrderInIdleSelectionState)(
      civilianOrderEntry);
}

} // namespace

// FUNCTION: IMPERIALISM 0x0058ea00
CivToolbarState* __cdecl CreateTCivToolbarInstance(void) {
  CivToolbarState* toolbar = reinterpret_cast<CivToolbarState*>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    RuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
    toolbar->vftable = reinterpret_cast<void*>(&g_vtblTCivToolbar);
  }
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058ea80
void* __cdecl GetTCivToolbarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTCivToolbar);
}

// FUNCTION: IMPERIALISM 0x0058eaa0
CivToolbarState* __fastcall ConstructTCivToolbarBaseState(CivToolbarState* toolbar) {
  RuntimeBridge::ConstructUiResourceEntryType4B0C0(toolbar);
  toolbar->vftable = reinterpret_cast<void*>(&g_vtblTCivToolbar);
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058ead0
CivToolbarState* __fastcall DestructTCivToolbarAndMaybeFree(CivToolbarState* toolbar, int unusedEdx,
                                                            unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)toolbar);
  }
  return toolbar;
}

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
void __fastcall RefreshCivilianCommandPanelForSelection(CivToolbarState* toolbar, int unusedEdx,
                                                        int* selectedCivilianOrderEntry) {
  // ORIG_CALLCONV: __thiscall
  int* backControl;
  short civilianClassId;
  int* unitControl;

  (void)unusedEdx;
  civilianClassId =
      (selectedCivilianOrderEntry == 0) ? (short)-1 : (short)selectedCivilianOrderEntry[1];
  *reinterpret_cast<short*>(reinterpret_cast<char*>(toolbar) + 0x88) = civilianClassId;

  unitControl = ResolveControlByTag(toolbar, 0x756e6974);
  if (unitControl == 0) {
    return;
  }
  if (selectedCivilianOrderEntry == 0) {
    SetControlEnabledAndRefresh(unitControl, 0, 1);
  } else {
    SetControlClassAndRefresh(unitControl, civilianClassId + 0x438, 1);
    SetControlEnabledAndRefresh(unitControl, 1, 1);
  }

  backControl = ResolveControlByTag(toolbar, 0x6261636b);
  if (backControl == 0) {
    return;
  }
  if (selectedCivilianOrderEntry == 0) {
    *reinterpret_cast<short*>(backControl + 0x18) = (short)-1;
    return;
  }
  if (civilianClassId != *reinterpret_cast<short*>(backControl + 0x18)) {
    *reinterpret_cast<short*>(backControl + 0x18) = civilianClassId;
    switch (civilianClassId) {
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
    RefreshControl(backControl);
  }
}

/* Refreshes civilian stack controls (stk0..stk5) for the selected tile and syncs command button
   enable state. */

// FUNCTION: IMPERIALISM 0x0058ec50
void __fastcall RefreshCivilianStackButtonsForTile(CivToolbarState* toolbar, int unusedEdx,
                                                   short tileIndex) {
  // ORIG_CALLCONV: __thiscall
  int commandEnabled;
  int selectedSlotTag;
  int slotIndex;
  int* selectedStackButton;
  CivilianTileEntry* selectedTileEntry;
  int* stackButton;
  SelectedCivilianState* selectedCivilianState;
  int mapState;

  (void)unusedEdx;
  mapState = *reinterpret_cast<int*>(kAddrGlobalMapState);
  selectedTileEntry = *reinterpret_cast<CivilianTileEntry**>(
      *reinterpret_cast<int*>(mapState + 0xc) + 0x20 + tileIndex * 0x24);
  selectedStackButton = 0;
  selectedCivilianState =
      reinterpret_cast<SelectedCivilianState*>(QuerySelectedCivilianOrderState());

  for (slotIndex = 0; (selectedTileEntry != 0) && (slotIndex < 6); slotIndex = slotIndex + 1) {
    stackButton = ResolveControlByTag(toolbar, 0x73746b30 + slotIndex);
    if (stackButton == 0) {
      return;
    }
    SetControlBoundEntry(stackButton, selectedTileEntry);
    SetControlEnabledAndRefresh(stackButton,
                                IsCivilianOrderInIdleSelectionStateBridge(selectedTileEntry), 1);
    if ((selectedCivilianState != 0) &&
        (selectedTileEntry == selectedCivilianState->selectedEntry)) {
      selectedStackButton = stackButton;
    }
    selectedTileEntry = selectedTileEntry->pNextOnTile;
  }
  while (slotIndex < 6) {
    stackButton = ResolveControlByTag(toolbar, 0x73746b30 + slotIndex);
    if (stackButton == 0) {
      return;
    }
    SetControlBoundEntry(stackButton, 0);
    slotIndex = slotIndex + 1;
  }

  selectedSlotTag = 0x6e616461;
  if (selectedStackButton != 0) {
    selectedSlotTag = selectedStackButton[7];
  }
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(
      reinterpret_cast<int*>(toolbar->vftable)[0x72])(toolbar, 0, selectedSlotTag);

  commandEnabled = (selectedStackButton != 0) ? 1 : 0;
  stackButton = ResolveControlByTag(toolbar, 0x64666e64);
  if (stackButton == 0) {
    return;
  }
  SetControlEnabledAndRefresh(stackButton, commandEnabled, 1);
  stackButton = ResolveControlByTag(toolbar, 0x6c617472);
  if (stackButton == 0) {
    return;
  }
  SetControlEnabledAndRefresh(stackButton, commandEnabled, 1);
  stackButton = ResolveControlByTag(toolbar, 0x646f6e65);
  if (stackButton == 0) {
    return;
  }
  SetControlEnabledAndRefresh(stackButton, commandEnabled, 1);
}

// FUNCTION: IMPERIALISM 0x0058eed0
void __fastcall HandleCivilianMapCommandPanelAction(CivToolbarState* toolbar, int unusedEdx,
                                                    int eventClass, PanelEventPayload* eventPayload,
                                                    int eventFlags) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;

  void* selectedCivilianOrderState = QuerySelectedCivilianOrderState();
  if (eventClass == 0xc) {
    if ((kTagStackSlotMin <= eventPayload->controlTag) &&
        (eventPayload->controlTag <= kTagStackSlotMax)) {
      SetActiveCivilianSelection(selectedCivilianOrderState, eventPayload->selectedEntryContext, 0);
      DispatchPanelControlEvent(toolbar, 0xc, eventPayload, eventFlags);
      return;
    }
  } else if (eventClass == 10) {
    unsigned int controlTag = eventPayload->controlTag;
    if (controlTag < 0x646f6e66) {
      if (controlTag == kTagDone) {
        QueueImmediateCivilianCommandAndCycleSelection(selectedCivilianOrderState, 4);
        DispatchPanelControlEvent(toolbar, 10, eventPayload, eventFlags);
        return;
      }
      if (controlTag == kTagDefend) {
        QueueImmediateCivilianCommandAndCycleSelection(selectedCivilianOrderState, 2);
        DispatchPanelControlEvent(toolbar, 10, eventPayload, eventFlags);
        return;
      }
    } else {
      if (controlTag == kTagGarrison) {
        unsigned short ctrlState = (unsigned short)GetAsyncKeyState(0x11);
        if ((ctrlState & 0x8000) != 0) {
          thunk_ShowCivilianLedgerDialogAndSelectUnit();
          DispatchPanelControlEvent(toolbar, 10, eventPayload, eventFlags);
          return;
        }
        ShowDisbandCivilianConfirmationDialog(selectedCivilianOrderState);
      } else if (controlTag == kTagLater) {
        QueueImmediateCivilianCommandAndCycleSelection(selectedCivilianOrderState, 3);
        DispatchPanelControlEvent(toolbar, 10, eventPayload, eventFlags);
        return;
      }
    }
  }
  DispatchPanelControlEvent(toolbar, eventClass, eventPayload, eventFlags);
}
