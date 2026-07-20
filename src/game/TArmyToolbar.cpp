#include "game/TArmyToolbar.h"

#include <new>

#include "game/TArmyMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TNumberedArrowButton.h"
#include "game/TView.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_control_tags.h"

undefined4 OpenSuperArmyRosterPageAndActivateProvinceSelection(void);

namespace {

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

static __inline void InvokeMapUberPictureCycleMapInteractionSelection() {
  if (g_pUiRuntimeContext == 0) {
    return;
  }
  // CycleMapInteractionSelectionAfterHandledClick is a real TMapUberPicture method (bd 4yz,
  // ground-truth-confirmed via its this+0x96 field read and both real call sites loading
  // mapUberPictureF0 directly) -- no cast needed.
  g_pUiRuntimeContext->mapUberPictureF0->CycleMapInteractionSelectionAfterHandledClick();
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x0058de40
// TArmyToolbar::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058dec0
// TArmyToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyToolbar, TUnitToolbarCluster)

TArmyToolbar::TArmyToolbar() : TUnitToolbarCluster(), selectedTileIndex(0) {}

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
  (void)event;
  unsigned int controlTag = sourceHandler->controlTag;

  if ((kTagArmyRatioMin <= controlTag) && (controlTag <= kTagArmyRatioMax)) {
    short categoryId = static_cast<short>(controlTag) - 0x7230;
    short selectedRatioOrMode = 0;
    if (commandId == 100) {
      selectedRatioOrMode =
          g_pMapContextActionManager->ActivateFirstActiveTacticalUnitByCategoryAtTile(
              categoryId, static_cast<short>(selectedTileIndex));
    } else {
      selectedRatioOrMode =
          g_pMapContextActionManager->ActivateFirstIdleTacticalUnitByCategoryAtTile(
              categoryId, static_cast<short>(selectedTileIndex));
    }
    static_cast<TNumberedArrowButton*>(sourceHandler)->SetValue(selectedRatioOrMode, 1);
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
    InvokeMapUberPictureCycleMapInteractionSelection();
    return;
  }

  if (controlTag == kTagArmyModeLater) {
    SetMapContextActionMode(3);
    InvokeMapUberPictureCycleMapInteractionSelection();
    return;
  }

  if (controlTag == kTagArmyModeDone) {
    SetMapContextActionMode(4);
    InvokeMapUberPictureCycleMapInteractionSelection();
  }
}
