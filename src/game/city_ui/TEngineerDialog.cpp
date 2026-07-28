#include "game/city_ui/TEngineerDialog.h"

#include "decomp_types.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/ui_screens/TIconBar.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x004d04b0
// TEngineerDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d0540
// TEngineerDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEngineerDialog, TView)

// FUNCTION: IMPERIALISM 0x004d0560
TEngineerDialog::TEngineerDialog() {
  this->headerSurface60 = 0;
  this->footerSurface64 = 0;
  this->bodyTileSurface68 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004d0590
// TEngineerDialog::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x004d05c0
TEngineerDialog::~TEngineerDialog() {}

// FUNCTION: IMPERIALISM 0x004d05e0
void TEngineerDialog::Free() {
  if (this->headerSurface60 != 0) {
    g_pDisplayMgr->RemoveGWorld(headerSurface60);
  }
  if (this->footerSurface64 != 0) {
    g_pDisplayMgr->RemoveGWorld(footerSurface64);
  }
  if (this->bodyTileSurface68 != 0) {
    g_pDisplayMgr->RemoveGWorld(bodyTileSurface68);
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x004d0650
void TEngineerDialog::Draw(RECT* rectBuffer) {
  if (this->headerSurface60 == 0) {
    return;
  }

  RECT headerRect;
  RECT bodyTileRect;
  RECT dstRect;
  short bodyY;

  headerRect.left = 0;
  headerRect.top = 0;
  headerRect.right = 0x148;
  headerRect.bottom = 0x38;
  bodyTileRect.left = 0;
  bodyTileRect.top = 0;
  bodyTileRect.right = 0x148;
  bodyTileRect.bottom = 0x0e;
  dstRect.left = 0;
  dstRect.right = 0x148;

  BlitQuickDrawSurfaces(this->headerSurface60->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &headerRect,
                        &headerRect, 0);

  bodyY = 0x38;
  int bodyRowCount = (static_cast<short>(this->frameHeight38) - 0x46) / 0x0e;
  if (bodyRowCount > 0) {
    do {
      dstRect.top = bodyY;
      dstRect.bottom = bodyY + 0x0e;
      BlitQuickDrawSurfaces(this->bodyTileSurface68->GetBlitSurface(),
                            g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bodyTileRect,
                            &dstRect, 0);
      bodyY = static_cast<short>(bodyY + 0x0e);
      bodyRowCount = bodyRowCount - 1;
    } while (bodyRowCount != 0);
  }

  dstRect.top = bodyY;
  dstRect.bottom = bodyY + 0x0e;
  BlitQuickDrawSurfaces(this->footerSurface64->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bodyTileRect, &dstRect,
                        0);

  (void)rectBuffer;
}

// FUNCTION: IMPERIALISM 0x004d0810
void TEngineerDialog::BuildCityViewProductionControls(short nBuildingSlotId) {
  TMapMgr* mapState = g_pGlobalMapState;
  unsigned char homeFlags =
      static_cast<unsigned char>(mapState->terrainStateTable[nBuildingSlotId].activeFlags1c);
  unsigned char fortAllowed = static_cast<unsigned char>(((homeFlags >> 4) & 1) == 0);
  unsigned char railAllowed = static_cast<unsigned char>(((homeFlags >> 2) & 1) == 0);
  unsigned char productionAllowed = 1;

  // Release + reload the three offscreen dialog strip surfaces.
  if (this->headerSurface60 != 0) {
    g_pDisplayMgr->RemoveGWorld(this->headerSurface60);
  }
  if (this->footerSurface64 != 0) {
    g_pDisplayMgr->RemoveGWorld(this->footerSurface64);
  }
  if (this->bodyTileSurface68 != 0) {
    g_pDisplayMgr->RemoveGWorld(this->bodyTileSurface68);
  }
  this->headerSurface60 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x1c30);
  if (this->headerSurface60 == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0xcef);
  }
  this->footerSurface64 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x1c31);
  if (this->footerSurface64 == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0xcf0);
  }
  this->bodyTileSurface68 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x1c32);
  if (this->bodyTileSurface68 == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UCityViews.cpp", 0xcf1);
  }

  // Panel title.
  TextStyle titleStyle;
  BuildUiTextStyleDescriptor(&titleStyle, 0, 0xa, 0x2b6a);
  TStaticText* title =
      static_cast<TStaticText*>(this->ResolveControlByTag(IMPERIALISM_FOURCC('l', 't', 'i', 't')));
  title->AssertValid();
  ConfigureUiControlStyleValueAndCaptionFromStringResource(title, 0, 0xe, 0x2b6a, 1, 0x1c20, 6);

  // Active nation, its city influence map, and the anchor tile's six hex neighbours.
  short activeNation = g_pSimMgr->GetActiveNationId();
  char* influenceMap = g_apNationStates[activeNation]->BuildCityInfluenceLevelMap();
  StrategicTileIndex neighborTiles[6];
  TMapMgr::GetNeighborTileIDArray(nBuildingSlotId, neighborTiles,
                                  mapState->hexNeighborWrapHorizontally);

  // A neighbour carrying transport flag 0x14 disables local production.
  if (fortAllowed != 0 && railAllowed != 0) {
    for (int n = 0; n < 6; n++) {
      short nbr = neighborTiles[n];
      if (nbr != -1 && (mapState->terrainStateTable[nbr].activeFlags1c & 0x14) != 0) {
        productionAllowed = 0;
      }
    }
  }

  short fortAccum[23] = {0};
  short portAccum[23] = {0};

  // Fort aggregation: over the anchor tile and every valid, active-nation-owned neighbour
  // inside the influence map, sum per-edge capability requirement levels and fold in the
  // owning province's resource-development counts.
  if (fortAllowed != 0 && productionAllowed != 0) {
    for (int i = 0; i < 7; i++) {
      short tile = (i == 6) ? nBuildingSlotId : neighborTiles[i];
      if (tile == -1) {
        continue;
      }
      if (influenceMap[tile] != 0) {
        continue;
      }
      TTerrainStateRecordView* t = &mapState->terrainStateTable[tile];
      if (t->gateFlag == 0) {
        continue;
      }
      if (t->ownerNationTag04 != g_pSimMgr->GetActiveNationId()) {
        continue;
      }
      for (int edge = 0; edge < 2; edge++) {
        short rt = t->resourceTypeByEdge[edge];
        if (rt == -1) {
          continue;
        }
        fortAccum[4 + rt] = static_cast<short>(
            fortAccum[4 + rt] + mapState->FindResourceCapabilityRequirementLevel(tile, edge));
      }
      Province* p = &mapState->cityScoreTable[t->cityRecordIndex];
      if (p->cityTileIndex04 == tile) {
        for (int j = 0; j < 10; j++) {
          fortAccum[7 + j] =
              static_cast<short>(fortAccum[7 + j] + p->resourceDevelopmentCounts82[j]);
        }
      }
    }
  }

  // Rail census: count active-nation river/rail-capable tiles into portAccum[19].
  if (railAllowed != 0 && productionAllowed != 0) {
    for (int i = 0; i < 7; i++) {
      short tile = (i == 6) ? nBuildingSlotId : neighborTiles[i];
      if (tile == -1) {
        continue;
      }
      if (influenceMap[tile] != 0) {
        continue;
      }
      TTerrainStateRecordView* t = &mapState->terrainStateTable[tile];
      if (t->ownerNationTag04 == g_pSimMgr->GetActiveNationId() && t->riverSpriteCode != 0) {
        portAccum[19] = static_cast<short>(portAccum[19] + 1);
      } else if (t->gateFlag == 0) {
        portAccum[19] = static_cast<short>(portAccum[19] + 1);
      }
    }
  }

  short layoutY = 0x52;

  // Fort up/down button: only when the anchor province can still raise its fort level.
  short homeProvIndex = mapState->terrainStateTable[nBuildingSlotId].cityRecordIndex;
  Province* homeProv = &mapState->cityScoreTable[homeProvIndex];
  short fortCap = g_pTechMgr->GetNationFortLevelCap(g_pSimMgr->GetActiveNationId());
  if (homeProv->fortLevel03 < fortCap && homeProv->cityTileIndex04 == nBuildingSlotId) {
    TUpDownPictureButton* fortBtn = new TUpDownPictureButton();
    int fortOff[2] = {0x11, 0x29};
    int fortSize[2] = {0x26, 0xec};
    fortBtn->IPicture(this, fortOff, fortSize, 5, 5, 0x1c2a);
    fortBtn->controlTag = IMPERIALISM_FOURCC('f', 'o', 'r', 't');
    fortBtn->SetState(1, 0);
    fortBtn->eventNumber60 = 0x22;

    TDeluxeText* fortLabel = new TDeluxeText();
    int fortLabelOff[2] = {0x54, 0x28};
    int fortLabelSize[2] = {0, 0};
    RECT fortLabelInset = {0, 0, 0, 0};
    TextStyle fortLabelStyle;
    fortLabel->IDeluxeText(this, fortLabelOff, fortLabelSize, &fortLabelInset, &fortLabelStyle, -2);
    fortLabel->BuildCityViewProductionControls_Impl(0x1c20, static_cast<short>(layoutY + 3));
    fortLabel->CenterVertically(0);
  }

  // Rail up/down button plus the accumulated fort-production TIconBar rows.
  if (fortAllowed != 0 && productionAllowed != 0) {
    layoutY = static_cast<short>(layoutY + 0x2a);
    TUpDownPictureButton* railBtn = new TUpDownPictureButton();
    int railOff[2] = {0x11, layoutY + 1};
    int railSize[2] = {0, 0};
    railBtn->IPicture(this, railOff, railSize, 5, 5, 0x1c2c);
    railBtn->controlTag = IMPERIALISM_FOURCC('r', 'a', 'i', 'l');
    railBtn->SetState(1, 0);
    railBtn->eventNumber60 = 0x22;

    TDeluxeText* railLabel = new TDeluxeText();
    int railLabelOff[2] = {0x54, layoutY};
    int railLabelSize[2] = {0, 0};
    RECT railLabelInset = {0, 0, 0, 0};
    TextStyle railLabelStyle;
    railLabel->IDeluxeText(this, railLabelOff, railLabelSize, &railLabelInset, &railLabelStyle, -2);
    railLabel->BuildCityViewProductionControls_Impl(0x1c20, layoutY);
    railLabel->CenterVertically(0);

    for (int i = 0; i < 23; i++) {
      if (fortAccum[i] == 0) {
        continue;
      }
      TIconBar* iconRow = new TIconBar();
      int iconPos[2] = {this->frameWidth34 - 0x60, layoutY};
      int iconSize[2] = {0x18, 0};
      iconRow->IIconBar(this, iconPos, iconSize, 5, 5, static_cast<short>(i + 0x2bc), fortAccum[i]);
      layoutY = static_cast<short>(layoutY + 0x1c);
    }
  }

  // Port up/down button plus the accumulated port-availability TIconBar rows.
  if (railAllowed != 0 && g_pGlobalMapState->CanBuildPortAtTile(nBuildingSlotId) != 0 &&
      productionAllowed != 0) {
    layoutY = static_cast<short>(layoutY + 0x2a);
    TUpDownPictureButton* portBtn = new TUpDownPictureButton();
    int portOff[2] = {0x11, layoutY + 1};
    int portSize[2] = {0, 0};
    portBtn->IPicture(this, portOff, portSize, 5, 5, 0x1c2e);
    portBtn->controlTag = IMPERIALISM_FOURCC('p', 'o', 'r', 't');
    portBtn->SetState(1, 0);
    portBtn->eventNumber60 = 0x22;

    TDeluxeText* portLabel = new TDeluxeText();
    int portLabelOff[2] = {0x54, layoutY};
    int portLabelSize[2] = {0, 0};
    RECT portLabelInset = {0, 0, 0, 0};
    TextStyle portLabelStyle;
    portLabel->IDeluxeText(this, portLabelOff, portLabelSize, &portLabelInset, &portLabelStyle, -2);
    portLabel->BuildCityViewProductionControls_Impl(0x1c20, layoutY);
    portLabel->CenterVertically(0);

    for (int i = 0; i < 23; i++) {
      if (portAccum[i] == 0) {
        continue;
      }
      TIconBar* iconRow = new TIconBar();
      int iconPos[2] = {this->frameWidth34 - 0x60, layoutY};
      int iconSize[2] = {0x18, 0};
      iconRow->IIconBar(this, iconPos, iconSize, 5, 5, static_cast<short>(i + 0x2bc), portAccum[i]);
      layoutY = static_cast<short>(layoutY + 0x1c);
    }
  }

  // Cancel button.
  layoutY = static_cast<short>(layoutY + 0x1e);
  TUpDownPictureButton* cancelBtn = new TUpDownPictureButton();
  int cancelOff[2] = {0x3d, 0x18};
  int cancelSize[2] = {0x11, layoutY - 2};
  cancelBtn->IPicture(this, cancelOff, cancelSize, 5, 5, 0x24c4);
  cancelBtn->controlTag = IMPERIALISM_FOURCC('c', 'n', 'c', 'l');
  cancelBtn->eventNumber60 = 0x22;
  cancelBtn->SetState(1, 0);
}
