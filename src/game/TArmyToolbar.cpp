// TArmyToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"

extern "C" short __stdcall GetAsyncKeyState(int virtual_key_code);

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
undefined4 ConstructTUberClusterBaseState(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_OpenSuperArmyRosterPageAndActivateProvinceSelection(void);
undefined4 thunk_CycleMapInteractionSelectionAfterHandledClick(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);

struct TradeMoveStepCluster;

namespace {

// GLOBAL: IMPERIALISM 0x667ad0
char g_vtblTArmyToolbar;
// GLOBAL: IMPERIALISM 0x6630d0
char g_pClassDescTArmyToolbar;

const unsigned int kAddrUiRuntimeContext = 0x006A21BC;
const unsigned int kAddrMapContextActionManager = 0x006A3338;
const unsigned int kTagArmyRatioMin = 0x61727230;
const unsigned int kTagArmyRatioMax = 0x61727239;
const unsigned int kTagArmyModeGarrison = 0x67617272;
const unsigned int kTagArmyModeDefend = 0x64666E64;
const unsigned int kTagArmyModeLater = 0x6C617472;
const unsigned int kTagArmyModeDone = 0x646F6E65;

struct ArmyToolbarState {
  void* vftable;
  char pad_04[0x88];
};

struct ArmyCommandPayload {
  void* vftable;
  char pad_04[0x18];
  unsigned int controlTag;
};

class RuntimeBridge {
public:
  static __inline void ConstructTUberClusterBaseState(TradeMoveStepCluster* self) {
    reinterpret_cast<void(__fastcall*)(TradeMoveStepCluster*)>(::ConstructTUberClusterBaseState)(
        self);
  }
};

static __inline int* QueryUiRuntimeContextPtr() {
  return *reinterpret_cast<int**>(kAddrUiRuntimeContext);
}

static __inline int* QueryMapContextActionManagerPtr() {
  return *reinterpret_cast<int**>(kAddrMapContextActionManager);
}

static __inline void DispatchUiRuntimeSlot48() {
  int* uiRuntime = QueryUiRuntimeContextPtr();
  if (uiRuntime == 0) {
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*)>(uiRuntime[0x12])(uiRuntime);
}

static __inline void DispatchUiRuntimeMapSelection(short mapSelection) {
  int* uiRuntime = QueryUiRuntimeContextPtr();
  if (uiRuntime == 0) {
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(uiRuntime[0x3b])(uiRuntime, 0, mapSelection);
}

static __inline void SetMapContextActionMode(int mode) {
  int* mapContextActionManager = QueryMapContextActionManagerPtr();
  if (mapContextActionManager == 0) {
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*, int, int)>(mapContextActionManager[0x16])(
      mapContextActionManager, 0, mode);
}

static __inline void CycleMapInteractionSelectionAfterHandledClick() {
  int* uiRuntime = QueryUiRuntimeContextPtr();
  if (uiRuntime == 0) {
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*)>(thunk_CycleMapInteractionSelectionAfterHandledClick)(
      reinterpret_cast<void*>(uiRuntime[0x3c]));
}

static __inline void SetArmyPayloadRatioOrModeSelection(ArmyCommandPayload* payload, int value) {
  if (payload == 0) {
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(
      reinterpret_cast<int*>(payload->vftable)[0x71])(payload, 0, value, 1);
}

} // namespace

// FUNCTION: IMPERIALISM 0x0058de40
ArmyToolbarState* __cdecl CreateTArmyToolbarInstance(void) {
  ArmyToolbarState* toolbar =
      reinterpret_cast<ArmyToolbarState*>(AllocateWithFallbackHandler(0x8c));
  if (toolbar != 0) {
    RuntimeBridge::ConstructTUberClusterBaseState(reinterpret_cast<TradeMoveStepCluster*>(toolbar));
    toolbar->vftable = reinterpret_cast<void*>(&g_vtblTArmyToolbar);
  }
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058dec0
void* __cdecl GetTArmyToolbarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTArmyToolbar);
}

// FUNCTION: IMPERIALISM 0x0058dee0
ArmyToolbarState* __fastcall ConstructTArmyToolbarBaseState(ArmyToolbarState* toolbar) {
  RuntimeBridge::ConstructTUberClusterBaseState(reinterpret_cast<TradeMoveStepCluster*>(toolbar));
  toolbar->vftable = reinterpret_cast<void*>(&g_vtblTArmyToolbar);
  return toolbar;
}

// FUNCTION: IMPERIALISM 0x0058df10
ArmyToolbarState* __fastcall DestructTArmyToolbarAndMaybeFree(ArmyToolbarState* toolbar,
                                                              int unusedEdx,
                                                              unsigned char freeSelfFlag) {
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)toolbar);
  }
  return toolbar;
}

/* Handles map-context action command tags for army ratio adjustments and mode transitions
   (defend/later/done/garrison), then cycles active map interaction selection when required. */

// FUNCTION: IMPERIALISM 0x0058e1c0
void __stdcall HandleMapContextActionArmyRatioAndModeCommands(int commandId,
                                                              ArmyCommandPayload* payload) {
  unsigned int controlTag = payload->controlTag;

  if ((kTagArmyRatioMin <= controlTag) && (controlTag <= kTagArmyRatioMax)) {
    int selectedRatioOrMode = 0;
    if (commandId == 100) {
      selectedRatioOrMode = (int)ActivateFirstActiveTacticalUnitByCategoryAtTile();
    } else {
      selectedRatioOrMode = (int)ActivateFirstIdleTacticalUnitByCategoryAtTile();
    }
    SetArmyPayloadRatioOrModeSelection(payload, selectedRatioOrMode);
    DispatchUiRuntimeSlot48();
    return;
  }

  if (controlTag == kTagArmyModeGarrison) {
    unsigned short ctrlState = (unsigned short)GetAsyncKeyState(0x11);
    if ((ctrlState & 0x8000) != 0) {
      thunk_OpenSuperArmyRosterPageAndActivateProvinceSelection();
      return;
    }

    int* mapContextActionManager = QueryMapContextActionManagerPtr();
    if (mapContextActionManager == 0) {
      return;
    }

    short mapSelection =
        *reinterpret_cast<short*>(reinterpret_cast<char*>(mapContextActionManager) + 0x31c);
    if (mapSelection != -1) {
      DispatchUiRuntimeMapSelection(mapSelection);
    }
    return;
  }

  if (controlTag == kTagArmyModeDefend) {
    SetMapContextActionMode(2);
    CycleMapInteractionSelectionAfterHandledClick();
    return;
  }

  if (controlTag == kTagArmyModeLater) {
    SetMapContextActionMode(3);
    CycleMapInteractionSelectionAfterHandledClick();
    return;
  }

  if (controlTag == kTagArmyModeDone) {
    SetMapContextActionMode(4);
    CycleMapInteractionSelectionAfterHandledClick();
  }
}
