#include "game/TNavyRoster.h"

#include "game/TMapDialog.h"
#include "game/TMapUberPicture.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
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
void TNavyRoster::StuffValues(TTaskForce* taskForce) {}

// FUNCTION: IMPERIALISM 0x00564fe0
void TNavyRoster::Close() {
  TView::Close();

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  TMapDialog* mapDialog = mapUberPicture->subview2A8;
  mapDialog->suppressMarkerOverlay34C = false;
  mapDialog->ResetAllTileMarkersToSentinel();
  mapUberPicture->unresolvedZeroA0 = 0;
}
