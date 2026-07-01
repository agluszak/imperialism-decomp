#include "game/TArmyToolbar.h"

#include <new>

#include "game/TCivToolbar.h"
#include "game/TView.h"
#include "game/mfc.h"
#include "game/ui_control_tags.h"

undefined4 OpenSuperArmyRosterPageAndActivateProvinceSelection(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);

namespace {

const unsigned int kAddrUiRuntimeContext = 0x006A21BC;
const unsigned int kAddrMapContextActionManager = 0x006A3338;

struct ArmyCommandPayload {
  void* vftable;
  char pad_04[0x18];
  unsigned int controlTag;
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

static __inline void InvokeActiveCivToolbarCycleMapInteractionSelection() {
  int* uiRuntime = QueryUiRuntimeContextPtr();
  if (uiRuntime == 0) {
    return;
  }
  reinterpret_cast<TCivToolbar*>(uiRuntime[0x3c])->CycleMapInteractionSelectionAfterHandledClick();
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
TArmyToolbar* __cdecl CreateTArmyToolbarInstance(void) {
  return new TArmyToolbar();
}
// SYNTHETIC: IMPERIALISM 0x0058dec0
// TArmyToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyToolbar, TUnitToolbarCluster)

TArmyToolbar::TArmyToolbar() : TUnitToolbarCluster(), field88(0) {}

// FUNCTION: IMPERIALISM 0x0058dee0
TArmyToolbar* TArmyToolbar::ConstructTArmyToolbarBaseState() {
  ::new (static_cast<void*>(this)) TArmyToolbar();
  return this;
}

// SYNTHETIC: IMPERIALISM 0x0058df10
// TArmyToolbar::`scalar deleting destructor'
TArmyToolbar::~TArmyToolbar() {}

// FUNCTION: IMPERIALISM 0x0058e1c0
void TArmyToolbar::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)sourceHandler;
  ArmyCommandPayload* payload = reinterpret_cast<ArmyCommandPayload*>(event);
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
      OpenSuperArmyRosterPageAndActivateProvinceSelection();
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
    InvokeActiveCivToolbarCycleMapInteractionSelection();
    return;
  }

  if (controlTag == kTagArmyModeLater) {
    SetMapContextActionMode(3);
    InvokeActiveCivToolbarCycleMapInteractionSelection();
    return;
  }

  if (controlTag == kTagArmyModeDone) {
    SetMapContextActionMode(4);
    InvokeActiveCivToolbarCycleMapInteractionSelection();
  }
}
