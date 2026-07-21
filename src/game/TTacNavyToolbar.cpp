#include "game/TTacNavyToolbar.h"

#include "game/TAmbitApplication.h"
#include "game/THelpMgr.h"
#include "game/TTacticalBattle.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"

// FUNCTION: IMPERIALISM 0x005ad0d0
undefined TTacNavyToolbar::UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit) {
  (void)unit;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005ad0f0
undefined TTacNavyToolbar::TacticalToolbarSlot74(int param_1) {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005ad110
// TTacNavyToolbar::`scalar deleting destructor'
TTacNavyToolbar::~TTacNavyToolbar() {}
// SYNTHETIC: IMPERIALISM 0x005ad030
// TTacNavyToolbar::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad160
// TTacNavyToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacNavyToolbar, TTacticalToolbar)

TTacNavyToolbar::TTacNavyToolbar() {}

// FUNCTION: IMPERIALISM 0x005ad180
void TTacNavyToolbar::DoPostCreate(int arg) {
  TTacticalToolbar::DoPostCreate(arg);
  SetSelectedChildTagAndRefresh(0x68756c6c); // 'hull'
}

// FUNCTION: IMPERIALISM 0x005ad1b0
void TTacNavyToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagCrew:
      battle88->SetCurrentSideNavyShipDisplayMode(1);
      break;
    case kControlTagHull:
      battle88->SetCurrentSideNavyShipDisplayMode(0);
      break;
    case kControlTagSail:
      battle88->SetCurrentSideNavyShipDisplayMode(2);
      break;
    default:
      break;
    }
  }
  if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kTagDone:
    case kControlTagAuto:
    case kControlTagRetr:
    case kControlTagTarg:
      battle88->HandleTacticalBattleCommandTag(tag);
      break;
    case kControlTagHelp:
      g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
      break;
    default:
      break;
    }
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
  g_pGlobalUiRootController->SetTarget(ownerContext);
}
