#include "game/tactical_ui/TTacNavyToolbar.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/gfx/TAmbitApplication.h"
#include "game/ui_core/THelpMgr.h"
#include "game/tactical/TNavyBattle.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005ad0d0
void TTacNavyToolbar::UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit) {
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x005ad0f0
void TTacNavyToolbar::UpdateTacticalOtherSideUnitControl(TArmyTacUnit* unit) {
  (void)unit;
}

// SYNTHETIC: IMPERIALISM 0x005ad110
// TTacNavyToolbar::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005ad140
TTacNavyToolbar::~TTacNavyToolbar() {}
// SYNTHETIC: IMPERIALISM 0x005ad030
// TTacNavyToolbar::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ad160
// TTacNavyToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacNavyToolbar, TTacticalToolbar)

// FUNCTION: IMPERIALISM 0x005ad180
void TTacNavyToolbar::DoPostCreate(int arg) {
  TTacticalToolbar::DoPostCreate(arg);
  SetSelectedChildTagAndRefresh(kControlTagHull); // 'hull'
}

// FUNCTION: IMPERIALISM 0x005ad1b0
void TTacNavyToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagCrew:
      static_cast<TNavyBattle*>(battle88)->SetTargeting(kNavyTargetingCrew);
      break;
    case kControlTagHull:
      static_cast<TNavyBattle*>(battle88)->SetTargeting(kNavyTargetingHull);
      break;
    case kControlTagSail:
      static_cast<TNavyBattle*>(battle88)->SetTargeting(kNavyTargetingSail);
      break;
    default:
      break;
    }
  }
  if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagDone:
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
