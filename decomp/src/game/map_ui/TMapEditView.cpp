#include "game/map_domain_types.h"
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

namespace {} // namespace

// FUNCTION: IMPERIALISM 0x0051cc20
TMapEditView::~TMapEditView() {}

IMPLEMENT_DYNCREATE(TMapEditView, TMapDialog)
// FUNCTION: IMPERIALISM 0x0051cc60
void TMapEditView::DoPostCreate(int arg) {
  TWorldView::DoPostCreate(arg);

  previewSquareRadius = 0x40;
  projectionScale = 1;

  RECT surfaceBounds = {0, 0, 0x1680, 0x40};
  g_pDisplayMgr->MakeNewGWorld(quickDrawSurface, 8, surfaceBounds);
  FlushCache();

  g_pCitySiteCachedPrimaryRenderSurfaceContext = g_pPrimaryRenderSurfaceContext;
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagMain);
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), kControlTagDialog);

  TMapUberPicture* mapOwner = static_cast<TMapUberPicture*>(ownerContext);
  mapOwner->SetMapInteractionMode(5);
  g_pGlobalMapState->field24 = true;
  g_pViewMgr->GenerateMiniMap();
  mapOwner->DisplayMiniMap();

  const short defaultResourceByProfile[15] = {-1, -1, 0,  20, 5,  17, 18, 1,
                                              -1, -1, -1, -1, -1, 2,  -1};
  for (int tileIndex = 0; tileIndex < kStrategicTileCount; ++tileIndex) {
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
    if (tile.GetTerrainKind() != kStrategicTerrainWater) {
      tile.resourceTypeByEdge[0] = defaultResourceByProfile[tile.gateFlag];
      tile.resourceTypeByEdge[1] = -1;
    }
  }

  TNumberText* provinceNumber =
      static_cast<TNumberText*>(ownerContext->FindSubView(kControlTagPrnu));
  provinceNumber->AssertValid();
  provinceNumber->maximumValue = 0x17f;
}

// FUNCTION: IMPERIALISM 0x0051ce60
void TMapEditView::NormalClick(short tileIndex, int inputFlags) {
  ownerContext->FindSubView(kControlTagEcon)->AssertValid();

  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  if (tile.GetTerrainKind() == kStrategicTerrainWater && editorActionMode != 5) {
    return;
  }

  switch (editorActionMode) {
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
    tile.adjacencyBits = static_cast<signed char>(editorActionValue);
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
void TMapEditView::ControlClick(int tileIndex, int dispatchContext) {
  if (editorActionMode != 1) {
    TWorldView::ControlClick(tileIndex, dispatchContext);
    return;
  }

  short provinceId =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].cityRecordIndex;
  if (provinceId == -1) {
    return;
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(0x13f2);
  TNumberText* provinceNumber =
      static_cast<TNumberText*>(ownerContext->FindSubView(kControlTagPrnu));
  provinceNumber->AssertValid();
  provinceNumber->SetControlValue(provinceId, 1);
  editorActionValue = provinceId;
}

// FUNCTION: IMPERIALISM 0x0051d060
void TMapEditView::ShiftClick(int tileIndex, int dispatchContext) {
  short provinceId =
      g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].cityRecordIndex;
  TNumberText* provinceNumber =
      static_cast<TNumberText*>(ownerContext->FindSubView(kControlTagPrnu));
  provinceNumber->AssertValid();
  int nationTag = provinceNumber->UpdateControlCachedIntFromWindowText();
  if (nationTag < 0 || nationTag > 0x17) {
    PlayDefaultMessageBeep();
    return;
  }

  int index;
  for (index = 0; index < kStrategicTileCount; ++index) {
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[index];
    if (tile.cityRecordIndex == provinceId) {
      tile.formerOwnerNationTag = static_cast<signed char>(nationTag);
      tile.ownerNationTag = static_cast<signed char>(nationTag);
    }
  }

  for (index = 0; index < kStrategicTileCount; ++index) {
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[index];
    if (tile.cityRecordIndex != provinceId) {
      continue;
    }

    tile.ownerBorderMask = 0;
    g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(static_cast<short>(index), 2);
    InvalidateTile(static_cast<short>(index));
    for (int direction = 0; direction < 6; ++direction) {
      short neighbor =
          TMapMgr::GetNeighborTileID(static_cast<short>(index), static_cast<short>(direction));
      g_pGlobalMapState->terrainStateTable[neighbor].ownerBorderMask = 0;
      g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(neighbor, 2);
      InvalidateTile(neighbor);
    }
  }
  g_pViewMgr->GenerateMiniMap();
}

// FUNCTION: IMPERIALISM 0x0051d210
void TMapEditView::HandleMapTileClickSetOrderContextAndHandleEvent79(int tileIndexArg,
                                                                     int inputFlags) {

  int index;
  for (index = 0; index < kStrategicTileCount; ++index) {
    g_pGlobalMapState->terrainStateTable[index].tileActionState = kMapTileActionStateNone;
  }

  for (index = 0; index < kProvinceCount; ++index) {
    Province& city = g_pGlobalMapState->cityScoreTable[index];
    city.adjacentRegionCount = 0;
    city.stationedUnitChain = 0;
    city.linkedRegionCount = 0;
    int entry;
    for (entry = 0; entry < 0x20; ++entry) {
      city.linkedTileIndices[entry] = -1;
    }
    for (entry = 0; entry < 0x0c; ++entry) {
      city.adjacentRegionIds[entry] = -1;
      city.adjacentRegionAnchorTiles[entry] = -1;
    }
  }

  for (index = 0; index < kStrategicTileCount; ++index) {
    TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[index];
    if (tile.GetTerrainKind() != kStrategicTerrainWater || tile.ownerNationTag >= 0x17) {
      continue;
    }

    short neighbors[6];
    TMapMgr::GetNeighborTileIDArray(static_cast<short>(index), neighbors,
                                    g_pGlobalMapState->hexNeighborWrapHorizontally);
    for (int direction = 0; direction < 6; ++direction) {
      TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighbors[direction]];
      if (neighbor.GetTerrainKind() == kStrategicTerrainWater && neighbor.ownerNationTag >= 0x17) {
        tile.ownerNationTag = neighbor.ownerNationTag;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d380
void TMapEditView::PlaceTerrain(short tileIndex) {
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  tile.SetTerrainKind(static_cast<StrategicTerrainKind>(editorActionValue));
  tile.adjacencyMaskA0a = 0;
  tile.adjacencyMaskB0b = 0;
  tile.riverSpriteCode |= kRiverSpriteCodeNeedsResolution;
  tile.spriteVariantIndex = 0;
  g_pGlobalMapState->AssignPictToTile(tileIndex);
  InvalidateTile(tileIndex);

  for (short direction = 0; direction < 6; ++direction) {
    short neighborIndex = TMapMgr::GetNeighborTileID(tileIndex, direction);
    if (neighborIndex != -1) {
      TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighborIndex];
      neighbor.adjacencyMaskA0a = 0;
      neighbor.adjacencyMaskB0b = 0;
      neighbor.riverSpriteCode |= kRiverSpriteCodeNeedsResolution;
      // The retail body clears the selected tile's byte here again, not the neighbor's.
      tile.spriteVariantIndex = 0;
      g_pGlobalMapState->AssignPictToTile(neighborIndex);
      InvalidateTile(neighborIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d4f0
void TMapEditView::DefaultResources(short tileIndex) {
  const short terrainByProfile[15] = {5, 0, 0, 0, 0, 7, 7, 2, 2, 3, 4, 6, 6, 1, 0};
  const short resourceByProfile[15] = {-1, -1, 0, 20, 5, 17, 18, 1, -1, -1, -1, -1, -1, 2, -1};
  if (editorActionValue == 0) {
    return;
  }

  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  if (tile.gateFlag == 0) {
    return;
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  tile.gateFlag = static_cast<signed char>(editorActionValue);
  tile.SetTerrainKind(static_cast<StrategicTerrainKind>(terrainByProfile[editorActionValue]));
  tile.adjacencyMaskA0a = 0;
  tile.adjacencyMaskB0b = 0;
  tile.riverSpriteCode |= kRiverSpriteCodeNeedsResolution;
  tile.spriteVariantIndex = 0;
  tile.resourceTypeByEdge[0] = static_cast<signed char>(resourceByProfile[tile.gateFlag]);
  tile.resourceTypeByEdge[1] = -1;
  g_pGlobalMapState->AssignPictToTile(tileIndex);
  InvalidateTile(tileIndex);

  for (short direction = 0; direction < 6; ++direction) {
    short neighborIndex = TMapMgr::GetNeighborTileID(tileIndex, direction);
    if (neighborIndex != -1) {
      TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighborIndex];
      neighbor.adjacencyMaskA0a = 0;
      neighbor.adjacencyMaskB0b = 0;
      neighbor.riverSpriteCode |= kRiverSpriteCodeNeedsResolution;
      neighbor.spriteVariantIndex = 0;
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

  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  TNumberText* provinceNumber =
      static_cast<TNumberText*>(ownerContext->FindSubView(kControlTagPrnu));
  provinceNumber->AssertValid();
  tile.cityRecordIndex = static_cast<short>(provinceNumber->UpdateControlCachedIntFromWindowText());
  tile.ownerBorderMask = 0;
  tile.cityBorderMask = 0;
  tile.waterAdjacencyMask = 0;
  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(tileIndex, 0);
  InvalidateTile(tileIndex);
  InvalidateTile(tileIndex);

  for (short direction = 0; direction < 6; ++direction) {
    short neighborIndex = TMapMgr::GetNeighborTileID(tileIndex, direction);
    if (neighborIndex != -1) {
      TTerrainStateRecord& neighbor = g_pGlobalMapState->terrainStateTable[neighborIndex];
      neighbor.ownerBorderMask = 0;
      neighbor.cityBorderMask = 0;
      neighbor.waterAdjacencyMask = 0;
      g_pGlobalMapState->UpdateTileNeighborBorderInfluenceCounters(neighborIndex, 0);
      InvalidateTile(neighborIndex);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0051d970
void TMapEditView::PlaceResource(short tileIndex) {
  const short resourceBySelection[3] = {22, 21, 6};
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  int slot = 0;
  if (tile.resourceTypeByEdge[0] != -1) {
    slot = 1;
    if (tile.resourceTypeByEdge[1] != -1) {
      PlayDefaultMessageBeep();
      return;
    }
  }

  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  tile.resourceTypeByEdge[slot] = static_cast<signed char>(resourceBySelection[editorActionValue]);
  InvalidateTile(tileIndex);
}

// FUNCTION: IMPERIALISM 0x0051db30
void TMapEditView::PlaceRail(short tileIndex) {
  g_pSfxPlaybackSystem->PlaySoundEffect(4000);
  g_pGlobalMapState->terrainStateTable[tileIndex].adjacencyBits =
      static_cast<signed char>(editorActionValue);
  InvalidateTile(tileIndex);
}

// FUNCTION: IMPERIALISM 0x0051dba0
void TMapEditView::PlaceRiver(short tileIndex) {
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  short variant =
      ResolveRiverSpriteVariantForConnectionMask(static_cast<unsigned char>(editorActionValue),
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
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  short provinceId = tile.cityRecordIndex;
  short previousCountySeat = g_pGlobalMapState->cityScoreTable[provinceId].cityTileIndex;
  g_pGlobalMapState->SetRegionTileSubtypeAndRefreshNeighborFlags(provinceId, tileIndex);

  TWindow* dialog =
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventProvinceEditor);
  TEditText* nameControl = static_cast<TEditText*>(dialog->FindSubView(kControlTagName));
  nameControl->AssertValid();
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&cityName, 0);
  dialog->PoseModally();
  nameControl->GetCurrentText(&cityName);
  g_pGlobalMapState->cityScoreTable[provinceId].cityName = cityName;

  TCluster* typeControl = static_cast<TCluster*>(dialog->FindSubView(kControlTagType));
  typeControl->AssertValid();
  if (typeControl->GetCurrentChoice() == static_cast<int>(kControlTagCity)) {
    tile.activeFlags |= 1;
  }
  dialog->Close();
  dialog->Free();

  if (previousCountySeat != -1) {
    InvalidateTile(previousCountySeat);
  }
  InvalidateTile(tileIndex);
  if (TMapMgr::GetNeighborTileID(tileIndex, 2) != -1) {
    InvalidateTile(TMapMgr::GetNeighborTileID(tileIndex, 2));
  }
}

// FUNCTION: IMPERIALISM 0x0051deb0
void TMapEditView::DoKeyEvent(TToolboxEvent* event) {
  switch (event->commandCode) {
  case 0x2c:
  case 0x3c: {
    g_pSfxPlaybackSystem->PlaySoundEffect(7000);
    TNumberText* provinceNumber =
        static_cast<TNumberText*>(ownerContext->FindSubView(kControlTagPrnu));
    provinceNumber->AssertValid();
    provinceNumber->SetControlValue(provinceNumber->UpdateControlCachedIntFromWindowText() - 1, 1);
    return;
  }
  case 0x2e:
  case 0x3e: {
    g_pSfxPlaybackSystem->PlaySoundEffect(7000);
    TNumberText* provinceNumber =
        static_cast<TNumberText*>(ownerContext->FindSubView(kControlTagPrnu));
    provinceNumber->AssertValid();
    provinceNumber->SetControlValue(provinceNumber->UpdateControlCachedIntFromWindowText() + 1, 1);
    return;
  }
  default:
    return;
  }
}
