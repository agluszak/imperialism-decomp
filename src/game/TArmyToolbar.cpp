#include "game/TArmyToolbar.h"

#include <new>

#include "game/TArmyMgr.h"
#include "game/TCivToolbar.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_control_tags.h"

undefined4 OpenSuperArmyRosterPageAndActivateProvinceSelection(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);

namespace {

struct ArmyCommandPayload {
  void* vftable;
  char pad_04[0x18];
  unsigned int controlTag;
};

static __inline void DispatchUiRuntimeSlot48() {
  if (g_pUiRuntimeContext == 0) {
    return;
  }
  g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
}

static __inline void DispatchUiRuntimeMapSelection(short mapSelection) {
  if (g_pUiRuntimeContext == 0) {
    return;
  }
  g_pUiRuntimeContext->HandleTurnEventDialogFactorySlotEC(mapSelection);
}

static __inline void SetMapContextActionMode(int mode) {
  if (g_pMapContextActionManager == 0) {
    return;
  }
  g_pMapContextActionManager->OrphanCallChain_C1_I34_004a4260(mode);
}

static __inline void InvokeActiveCivToolbarCycleMapInteractionSelection() {
  if (g_pUiRuntimeContext == 0) {
    return;
  }
  // mapUberPictureF0 (+0xf0) is a dual-purpose slot: this caller reads it as a TCivToolbar*,
  // while the field's declared type (TMapUberPicture*) reflects other callers -- an explicit
  // type pun, not a modeling error (see the type-modeling guardrail for shared slots).
  reinterpret_cast<TCivToolbar*>(g_pUiRuntimeContext->mapUberPictureF0)
      ->CycleMapInteractionSelectionAfterHandledClick();
}

static __inline void SetArmyPayloadRatioOrModeSelection(ArmyCommandPayload* payload, int value) {
  if (payload == 0) {
    return;
  }
  reinterpret_cast<void(__fastcall*)(void*, int, int, int)>(
      reinterpret_cast<int*>(payload->vftable)[0x71])(payload, 0, value, 1);
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x0058de40
// TArmyToolbar::CreateObject
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

    if (g_pMapContextActionManager == 0) {
      return;
    }

    short mapSelection = g_pMapContextActionManager->pendingMapActionIndex;
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
