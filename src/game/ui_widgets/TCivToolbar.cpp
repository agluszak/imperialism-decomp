// TCivToolbar wrapper class quad extracted from Ghidra autogen.

#include "decomp_types.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/ui_screens/TUberCluster.h"
#include "game/ui_widgets/TCivilianButton.h"
#include "game/ui_widgets/TCivDescription.h"
#include "game/military/TCivUnit.h"
#include "game/city_ui/TCivMgr.h"
#include "game/map/TMapMgr.h"

#include "game/ui_core/TControl.h"
#include "game/ui_core/TPicture.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TViewMgr.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/ui_widgets_globals.h"

// 0x004d3a60 (HandleEngineerConstructionAction) lives on TCivMgr — see TCivMgr.cpp.

// SYNTHETIC: IMPERIALISM 0x0058ea00
// TCivToolbar::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058ea80
// TCivToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivToolbar, TCluster)

// FUNCTION: IMPERIALISM 0x0058eaa0
TCivToolbar::TCivToolbar() {}

// SYNTHETIC: IMPERIALISM 0x0058ead0
// TCivToolbar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058eb00
TCivToolbar::~TCivToolbar() {}

// FUNCTION: IMPERIALISM 0x0058eb20
void TCivToolbar::RefreshCivilianCommandPanelForSelection(TCivUnit* selectedOrder) {
  this->civilianClassId = selectedOrder ? selectedOrder->orderType : -1;

  TControl* unitControl = static_cast<TControl*>(this->ResolveControlByTag(kControlTagUnit));
  if (unitControl == 0) {
    return;
  }

  if (selectedOrder == 0) {
    unitControl->Show(0, 1);
  } else {
    static_cast<TPicture*>(unitControl)
        ->SetPictureResourceIdAndRefresh(static_cast<short>(this->civilianClassId + 0x438), 1);
    unitControl->Show(1, 1);
  }

  TCivDescription* backControl = static_cast<TCivDescription*>(
      static_cast<TView*>(this->ResolveControlByTag(kControlTagBack)));
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
      backControl->targetTileCountsBySlot[4] = 0;
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
  TCivMgr* selectedCivilianState;

  selectedTileEntry = g_pGlobalMapState->GetFirstCivilianOrderOnTile(tileIndex);
  selectedStackButton = 0;
  selectedCivilianState = g_pSelectedCivilianOrderState;

  for (slotIndex = 0; (selectedTileEntry != 0) && (slotIndex < 6); slotIndex = slotIndex + 1) {
    stackButton =
        static_cast<TControl*>(this->ResolveControlByTag(kControlTagStackSlotFirst + slotIndex));
    if (stackButton == 0) {
      FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x15d1);
    }
    static_cast<TCivilianButton*>(stackButton)
        ->SetSelectedCivilianOrderAndEnableButton(selectedTileEntry);
    stackButton->ViewEnable(selectedTileEntry->IsInIdleSelectionState(), 1);
    if ((selectedCivilianState != 0) &&
        (selectedTileEntry == selectedCivilianState->selectedEntry)) {
      selectedStackButton = stackButton;
    }
    selectedTileEntry = static_cast<TCivUnit*>(selectedTileEntry->nextAtLocation14);
  }
  while (slotIndex < 6) {
    stackButton =
        static_cast<TControl*>(this->ResolveControlByTag(kControlTagStackSlotFirst + slotIndex));
    if (stackButton == 0) {
      FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x15df);
    }
    static_cast<TCivilianButton*>(stackButton)->SetSelectedCivilianOrderAndEnableButton(0);
    slotIndex = slotIndex + 1;
  }

  selectedSlotTag = kControlTagNada;
  if (selectedStackButton != 0) {
    selectedSlotTag = selectedStackButton->controlTag;
  }
  this->SetSelectedChildTagAndRefresh(selectedSlotTag);

  commandEnabled = (selectedStackButton != 0) ? 1 : 0;
  stackButton = static_cast<TControl*>(this->ResolveControlByTag(kControlTagDfnd));
  if (stackButton == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x15eb);
  }
  stackButton->ViewEnable(commandEnabled, 1);
  stackButton = static_cast<TControl*>(this->ResolveControlByTag(kControlTagLatr));
  if (stackButton == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x15ed);
  }
  stackButton->ViewEnable(commandEnabled, 1);
  stackButton = static_cast<TControl*>(this->ResolveControlByTag(kControlTagDone));
  if (stackButton == 0) {
    FailNilPointerWithAssert(s_SourcePathUSmallViews_006992F0, 0x15ef);
  }
  stackButton->ViewEnable(commandEnabled, 1);
}

// FUNCTION: IMPERIALISM 0x0058eed0
void TCivToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  // ORIG_CALLCONV: __thiscall

  TCivMgr* selectedCivilianOrderState = g_pSelectedCivilianOrderState;
  if (commandId == 0xc) {
    unsigned int controlTag = static_cast<unsigned int>(sourceHandler->controlTag);
    if ((kControlTagStackSlotFirst <= controlTag) && (controlTag <= kControlTagStackSlotLast)) {
      TCivilianButton* stackButton = static_cast<TCivilianButton*>(sourceHandler);
      TCivUnit* boundStackEntry = stackButton->selectedCivilianOrder9c;
      selectedCivilianOrderState->SetActiveCivilianSelection(boundStackEntry, 0);
      this->TCluster::DoEvent(0xc, sourceHandler, event);
      return;
    }
  } else if (commandId == 10) {
    unsigned int controlTag = sourceHandler->controlTag;
    if (controlTag < kControlTagDono) {
      if (controlTag == kControlTagDone) {
        selectedCivilianOrderState->OrderAndCycle(static_cast<UnitOrder>(4));
        this->TCluster::DoEvent(10, sourceHandler, event);
        return;
      }
      if (controlTag == kControlTagDfnd) {
        selectedCivilianOrderState->OrderAndCycle(static_cast<UnitOrder>(2));
        this->TCluster::DoEvent(10, sourceHandler, event);
        return;
      }
    } else {
      if (controlTag == kControlTagGarr) {
        unsigned short ctrlState = (unsigned short)GetAsyncKeyState(0x11);
        if ((ctrlState & 0x8000) != 0) {
          g_pViewMgr->ShowCivilianLedgerDialogAndSelectUnit();
          this->TCluster::DoEvent(10, sourceHandler, event);
          return;
        }
        selectedCivilianOrderState->ShowDisbandCivilianConfirmationDialog();
      } else if (controlTag == kControlTagLatr) {
        selectedCivilianOrderState->OrderAndCycle(static_cast<UnitOrder>(3));
        this->TCluster::DoEvent(10, sourceHandler, event);
        return;
      }
    }
  }
  this->TCluster::DoEvent(commandId, sourceHandler, event);
}
