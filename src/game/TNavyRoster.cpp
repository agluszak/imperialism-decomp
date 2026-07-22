#include "game/TNavyRoster.h"

#include "game/TMapDialog.h"
#include "game/TDisplayMgr.h"
#include "game/TMapOrderChildLinkNode.h"
#include "game/TMapUberPicture.h"
#include "game/TShip.h"
#include "game/TShipLine.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x00564c30
// TNavyRoster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00564d00
// TNavyRoster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyRoster, TMilitaryPageView)

// FUNCTION: IMPERIALISM 0x00564d20
TNavyRoster::TNavyRoster() {
  primaryUnitAtlas84 = 0;
  taskForce88 = 0;
  unresolvedZero8C = 0;
  classControls90[0] = 0;
  classControls90[1] = 0;
  classControls90[2] = 0;
  classControls90[3] = 0;
}

// SYNTHETIC: IMPERIALISM 0x00564d70
// TNavyRoster::`scalar deleting destructor'
TNavyRoster::~TNavyRoster() {}

// FUNCTION: IMPERIALISM 0x00564dc0
void TNavyRoster::StuffValues(TTaskForce* taskForce) {
  PrepareUnitCache(0xdba, 0x500, 0x2d);
  taskForce88 = taskForce;

  unsigned int classTag = 0x636c7330; // 'cls0'
  for (int i = 0; i < 4; ++i, ++classTag) {
    TView* classControl = g_pDisplayMgr->activeDialog->ResolveControlByTag(classTag);
    if (classControl == 0) {
      MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUOceanViews_00698650, 0x114);
    }
    classControls90[i] = classControl;
  }

  for (TMapOrderChildLinkNode* link = taskForce->shipList; link != 0; link = link->next) {
    TShipLine* line = new TShipLine();
    int lineBounds[2] = {0xec, 0x31};
    line->SetLineDataRowAndBounds(0, 0, lineBounds);
    line->shipNode10 = static_cast<TShip*>(link->payload);
    line->childLink14 = link;
    line->taskForce18 = taskForce;
    AddOrderedEntry(line);
  }

  AfterStuffValues();
}

// FUNCTION: IMPERIALISM 0x00564fe0
void TNavyRoster::Close() {
  TView::Close();

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapUberPicture->subview2A8;
  mapDialog->suppressMarkerOverlay34C = false;
  mapDialog->ResetAllTileMarkersToSentinel();
  mapUberPicture->navyRosterA0 = 0;
}
