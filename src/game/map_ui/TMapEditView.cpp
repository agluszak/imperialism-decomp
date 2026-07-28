#include "game/map_ui/TMapEditView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"

#include "game/core/CString.h"
#include "game/assets/TAssetMgr.h"
#include "game/ui_core/TCluster.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TEditText.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TUiEvent.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

namespace {

const int kMapTileCount = 0x1950;
const int kCityRecordCount = 0x180;

TNumberText* ResolveProvinceNumberControl(TView* owner) {
  TNumberText* control = static_cast<TNumberText*>(owner->ResolveControlByTag(kControlTagPrnu));
  control->AssertValid();
  return control;
}

void ClearTileAdjacencyRenderCache(TTerrainStateRecordView& tile) {
  tile.adjacencyMaskA0a = 0;
  tile.adjacencyMaskB0b = 0;
  tile.riverSpriteCode |= kRiverSpriteCodeNeedsResolution;
  tile.spriteVariantIndex01 = 0;
}

void ClearTileBorderMasks(TTerrainStateRecordView& tile) {
  tile.ownerBorderMask07 = 0;
  tile.cityBorderMask08 = 0;
  tile.waterAdjacencyMask09 = 0;
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x0051cbf0
// TMapEditView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0051cc20
TMapEditView::~TMapEditView() {}
// SYNTHETIC: IMPERIALISM 0x0051cab0
// TMapEditView::CreateObject

// SYNTHETIC: IMPERIALISM 0x0051cc40
// TMapEditView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapEditView, TMapDialog)
// FUNCTION: IMPERIALISM 0x0051cc60
void TMapEditView::DoPostCreate(int arg) {
  TWorldView::DoPostCreate(arg);

  previewSquareRadius = 0x40;
  projectionScale = 1;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->MakeNewGWorld(quickDrawSurface350, 8, surfaceBounds);
  ResetAllTileMarkersToSentinel();

  g_pCitySiteCachedPrimaryRenderSurfaceContext = g_pPrimaryRenderSurfaceContext;
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagDialog);

  TMapUberPicture* mapOwner = static_cast<TMapUberPicture*>(ownerContext);
  mapOwner->SetMapInteractionMode(5);
  g_pGlobalMapState->field24 = 1;
  g_pViewMgr->RenderTurnEventPalettePreviewSurfaceAndProgress();
  mapOwner->DisplayMiniMap();

  const short defaultResourceByProfile[15] = {-1, -1, 0,  20, 5,  17, 18, 1,
                                              -1, -1, -1, -1, -1, 2,  -1};
  for (int tileIndex = 0; tileIndex < kMapTileCount; ++tileIndex) {
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile.GetTerrainKind() != kStrategicTerrainWater) {
      tile.resourceTypeByEdge[0] = defaultResourceByProfile[tile.gateFlag];
      tile.resourceTypeByEdge[1] = -1;
    }
  }

  ResolveProvinceNumberControl(ownerContext)->maximumValue = 0x17f;
}

// FUNCTION: IMPERIALISM 0x0051ce60
void TMapEditView::HandleMapClickByInteractionMode(short tileIndex, int inputFlags) {
  (void)inputFlags;
  ownerContext->ResolveControlByTag(kControlTagEcon)->AssertValid();

  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  if (tile.GetTerrainKind() == kStrategicTerrainWater && editorActionMode368 != 5) {
    return;
  }

  switch (editorActionMode368) {
  case 0:
    DefaultResources(tileIndex);
    break;
  case 1:
    PlaceProvince(tileIndex);
    break;
  case 2:
    PlaceResource(tileIndex);
    break;
  case 3:
    g_pSfxPlaybackSystem->PlaySoundEffect(4000);
    tile.adjacencyBits06 = static_cast<signed char>(editorActionValue36c);
    InvalidateTile(tileIndex);
    break;
  case 4:
    PlaceCountySeat(tileIndex);
    break;
  case 5:
    PlaceRiver(tileIndex);
    break;
  }
}

// FUNCTION: IMPERIALISM 0x0051cfa0
void TMapEditView::InvokeDialogHooks1D8ThenE4(int tileIndex, int dispatchContext) {
  if (editorActionMode368 != 1) {
    TWorldView::InvokeDialogHooks1D8ThenE4(tileIndex, dispatchContext);
    return;
  }

  short provinceId =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].cityRecordIndex;
  if (provinceId == -1) {
    return;
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(0x13f2);
  TNumberText* provinceNumber = ResolveProvinceNumberControl(ownerContext);
  provinceNumber->SetControlValue(provinceId, 1);
  editorActionValue36c = provinceId;
}

// FUNCTION: IMPERIALISM 0x0051d060
void TMapEditView::DispatchOverlayEvent78FromStridedRecord(int tileIndex, int dispatchContext) {
  (void)dispatchContext;
  short provinceId =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].cityRecordIndex;
  int nationTag =
      ResolveProvinceNumberControl(ownerContext)->UpdateControlCachedIntFromWindowText();
  if (nationTag < 0 || nationTag > 0x17) {
    PlayDefaultMessageBeep();
    return;
  }

  int index;
  for (index = 0; index < kMapTileCount; ++index) {
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[index];
    if (tile.cityRecordIndex == provinceId) {
      tile.formerOwnerNationTag03 = static_cast<signed char>(nationTag);
      tile.ownerNationTag04 = static_cast<signed char>(nationTag);
    }
  }

  for (index = 0; index < kMapTileCount; ++index) {
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[index];
    if (tile.cityRecordIndex != provinceId) {
      continue;
    }

    tile.ownerBorderMask07 = 0;
    g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(static_cast<short>(index), 2);
    InvalidateTile(static_cast<short>(index));
    for (int direction = 0; direction < 6; ++direction) {
      short neighbor =
          TMapMgr::GetNeighborTileID(static_cast<short>(index), static_cast<short>(direction));
      g_pGlobalMapState->terrainStateTable[neighbor].ownerBorderMask07 = 0;
      g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(neighbor, 2);
      InvalidateTile(neighbor);
    }
  }
  g_pViewMgr->RenderTurnEventPalettePreviewSurfaceAndProgress();
}

// FUNCTION: IMPERIALISM 0x0051d210
void TMapEditView::HandleMapTileClickSetOrderContextAndHandleEvent79(int arg1, int arg2) {
  (void)arg1;
  (void)arg2;

  int index;
  for (index = 0; index < kMapTileCount; ++index) {
    g_pGlobalMapState->terrainStateTable[index].tileActionState16 = kMapTileActionStateNone;
  }

  for (index = 0; index < kCityRecordCount; ++index) {
    Province& city = g_pGlobalMapState->cityScoreTable[index];
    city.adjacentRegionCount08 = 0;
    city.stationedUnitChain98 = 0;
    city.linkedRegionCount = 0;
    int entry;
    for (entry = 0; entry < 0x20; ++entry) {
      city.linkedTileIndices42[entry] = -1;
    }
    for (entry = 0; entry < 0x0c; ++entry) {
      city.adjacentRegionIds0A[entry] = -1;
      city.adjacentRegionAnchorTiles22[entry] = -1;
    }
  }

  for (index = 0; index < kMapTileCount; ++index) {
    TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[index];
    if (tile.GetTerrainKind() != kStrategicTerrainWater || tile.ownerNationTag04 >= 0x17) {
      continue;
    }

    short neighbors[6];
    TMapMgr::GetNeighborTileIDArray(static_cast<short>(index), neighbors,
                                    g_pGlobalMapState->hexNeighborWrapHorizontally);
    for (int direction = 0; direction < 6; ++direction) {
      TTerrainStateRecordView& neighbor =
          g_pGlobalMapState->terrainStateTable[neighbors[direction]];
      if (neighbor.GetTerrainKind() == kStrategicTerrainWater &&
          neighbor.ownerNationTag04 >= 0x17) {
        tile.ownerNationTag04 = neighbor.ownerNationTag04;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d380
void TMapEditView::PlaceTerrain(short tileIndex) {
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  tile.SetTerrainKind(static_cast<StrategicTerrainKind>(editorActionValue36c));
  ClearTileAdjacencyRenderCache(tile);
  g_pGlobalMapState->AssignPictToTile(tileIndex);
  InvalidateTile(tileIndex);

  for (short direction = 0; direction < 6; ++direction) {
    short neighborIndex = TMapMgr::GetNeighborTileID(tileIndex, direction);
    if (neighborIndex != -1) {
      TTerrainStateRecordView& neighbor = g_pGlobalMapState->terrainStateTable[neighborIndex];
      neighbor.adjacencyMaskA0a = 0;
      neighbor.adjacencyMaskB0b = 0;
      neighbor.riverSpriteCode |= kRiverSpriteCodeNeedsResolution;
      // The retail body clears the selected tile's byte here again, not the neighbor's.
      tile.spriteVariantIndex01 = 0;
      g_pGlobalMapState->AssignPictToTile(neighborIndex);
      InvalidateTile(neighborIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d4f0
void TMapEditView::DefaultResources(short tileIndex) {
  const short terrainByProfile[15] = {5, 0, 0, 0, 0, 7, 7, 2, 2, 3, 4, 6, 6, 1, 0};
  const short resourceByProfile[15] = {-1, -1, 0, 20, 5, 17, 18, 1, -1, -1, -1, -1, -1, 2, -1};
  if (editorActionValue36c == 0) {
    return;
  }

  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  if (tile.gateFlag == 0) {
    return;
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  tile.gateFlag = static_cast<signed char>(editorActionValue36c);
  tile.SetTerrainKind(static_cast<StrategicTerrainKind>(terrainByProfile[editorActionValue36c]));
  ClearTileAdjacencyRenderCache(tile);
  tile.resourceTypeByEdge[0] = static_cast<signed char>(resourceByProfile[tile.gateFlag]);
  tile.resourceTypeByEdge[1] = -1;
  g_pGlobalMapState->AssignPictToTile(tileIndex);
  InvalidateTile(tileIndex);

  for (short direction = 0; direction < 6; ++direction) {
    short neighborIndex = TMapMgr::GetNeighborTileID(tileIndex, direction);
    if (neighborIndex != -1) {
      TTerrainStateRecordView& neighbor = g_pGlobalMapState->terrainStateTable[neighborIndex];
      ClearTileAdjacencyRenderCache(neighbor);
      g_pGlobalMapState->AssignPictToTile(neighborIndex);
      InvalidateTile(neighborIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d7e0
void TMapEditView::PlaceProvince(short tileIndex) {
  if (!BecomeTarget()) {
    return;
  }

  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  tile.cityRecordIndex = static_cast<short>(
      ResolveProvinceNumberControl(ownerContext)->UpdateControlCachedIntFromWindowText());
  ClearTileBorderMasks(tile);
  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(tileIndex, 0);
  InvalidateTile(tileIndex);
  InvalidateTile(tileIndex);

  for (short direction = 0; direction < 6; ++direction) {
    short neighborIndex = TMapMgr::GetNeighborTileID(tileIndex, direction);
    if (neighborIndex != -1) {
      TTerrainStateRecordView& neighbor = g_pGlobalMapState->terrainStateTable[neighborIndex];
      ClearTileBorderMasks(neighbor);
      g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(neighborIndex, 0);
      InvalidateTile(neighborIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d970
void TMapEditView::PlaceResource(short tileIndex) {
  const short resourceBySelection[3] = {22, 21, 6};
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  int slot = 0;
  if (tile.resourceTypeByEdge[0] != -1) {
    slot = 1;
    if (tile.resourceTypeByEdge[1] != -1) {
      PlayDefaultMessageBeep();
      return;
    }
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  tile.resourceTypeByEdge[slot] =
      static_cast<signed char>(resourceBySelection[editorActionValue36c]);
  InvalidateTile(tileIndex);
}

// FUNCTION: IMPERIALISM 0x0051db30
void TMapEditView::PlaceRail(short tileIndex) {
  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  g_pGlobalMapState->terrainStateTable[tileIndex].adjacencyBits06 =
      static_cast<signed char>(editorActionValue36c);
  InvalidateTile(tileIndex);
}

// FUNCTION: IMPERIALISM 0x0051dba0
void TMapEditView::PlaceRiver(short tileIndex) {
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  short variant =
      ResolveRiverSpriteVariantForConnectionMask(static_cast<unsigned char>(editorActionValue36c),
                                                 tile.GetTerrainKind() == kStrategicTerrainWater);
  if (variant == -1) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5a);
    return;
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  tile.riverSpriteCode =
      static_cast<RiverSpriteCodeStorage>(variant | kRiverSpriteCodeNeedsResolution);
  tile.adjacencyMaskA0a = 0;
  tile.adjacencyMaskB0b = 0;
  g_pGlobalMapState->AssignPictToTile(tileIndex);
  InvalidateTile(tileIndex);
}

// FUNCTION: IMPERIALISM 0x0051dc90
void TMapEditView::PlaceCountySeat(short tileIndex) {
  CString cityName("Chumpto");
  TTerrainStateRecordView& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  short provinceId = tile.cityRecordIndex;
  short previousCountySeat = g_pGlobalMapState->cityScoreTable[provinceId].cityTileIndex04;
  g_pGlobalMapState->SetRegionTileSubtypeAndRefreshNeighborFlags(provinceId, tileIndex);

  TWindow* dialog = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventProvinceEditor));
  TEditText* nameControl = static_cast<TEditText*>(dialog->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&cityName, 0);
  dialog->PoseModally();
  nameControl->GetCurrentText(&cityName);
  g_pGlobalMapState->cityScoreTable[provinceId].cityNameA4 = cityName;

  TCluster* typeControl = static_cast<TCluster*>(dialog->ResolveControlByTag(kControlTagType));
  typeControl->AssertValid();
  if (typeControl->GetSelectedChildTag() == static_cast<int>(kControlTagCity)) {
    tile.activeFlags1c |= 1;
  }
  dialog->Close();
  dialog->Free();

  if (previousCountySeat != -1) {
    InvalidateTile(previousCountySeat);
  }
  InvalidateTile(tileIndex);
  short neighbor = TMapMgr::GetNeighborTileID(tileIndex, 2);
  if (neighbor != -1) {
    InvalidateTile(neighbor);
  }
}

// FUNCTION: IMPERIALISM 0x0051deb0
void TMapEditView::DoKeyEvent(TToolboxEvent* event) {
  int delta;
  switch (event->commandCode) {
  case 0x2c:
  case 0x3c:
    delta = -1;
    break;
  case 0x2e:
  case 0x3e:
    delta = 1;
    break;
  default:
    return;
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(7000);
  TNumberText* provinceNumber = ResolveProvinceNumberControl(ownerContext);
  provinceNumber->SetControlValue(provinceNumber->UpdateControlCachedIntFromWindowText() + delta,
                                  1);
}
