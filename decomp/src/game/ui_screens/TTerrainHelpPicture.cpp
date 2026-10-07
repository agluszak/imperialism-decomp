#include "game/ui_screens/TTerrainHelpPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_screens.h"
#include "game/ui_core/TWindow.h"

#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_screens/TLonelyTileView.h"
#include "game/map/TMapMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/map/TZone.h"
#include "game/ui_core/TControl.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/civilian_domain_types.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

#include <string.h>

// FUNCTION: IMPERIALISM 0x0043d770
TTerrainHelpPicture::TTerrainHelpPicture() {}

// FUNCTION: IMPERIALISM 0x0043d7d0
TTerrainHelpPicture::~TTerrainHelpPicture() {}

IMPLEMENT_DYNCREATE(TTerrainHelpPicture, TPicture)

// FUNCTION: IMPERIALISM 0x00504e90
void TTerrainHelpPicture::BuildMapTileActionContextMenu(short nTileIndex) {
  TextStyle itemStyle;
  itemStyle.textColor = 0;
  memset(menuItemIds, 0, sizeof(menuItemIds));
  short count = 0;

  // Build the item-id list from the selected tile's record.
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags & 1) {
    menuItemIds[count++] = 0x11;
  }
  menuItemIds[count++] =
      static_cast<short>(g_pGlobalMapState->terrainStateTable[nTileIndex].gateFlag + 1);
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].riverSpriteCode != kRiverSpriteCodeNone) {
    menuItemIds[count++] = 0x16;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].ownerBorderMask != 0) {
    if (g_pGlobalMapState->terrainStateTable[nTileIndex].GetTerrainKind() !=
        kStrategicTerrainWater) {
      menuItemIds[count++] = 0x13;
    } else {
      menuItemIds[count++] = 0x32;
    }
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].cityBorderMask != 0 &&
      g_pGlobalMapState->terrainStateTable[nTileIndex].cityBorderMask !=
          g_pGlobalMapState->terrainStateTable[nTileIndex].ownerBorderMask) {
    menuItemIds[count++] = 0x12;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags & 0x14) {
    menuItemIds[count++] = 0x14;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags & 0x20) {
    menuItemIds[count++] = 0x1d;
  }

  if (g_pGlobalMapState->GetDevelopmentLevel(nTileIndex, false) != 0 ||
      g_pGlobalMapState->GetDevelopmentLevel(nTileIndex, true) != 0) {
    short itemId = 0x17;
    switch (g_pGlobalMapState->terrainStateTable[nTileIndex].gateFlag) {
    case 2:
    case 5:
    case 6:
      itemId = 0x1a;
      break;
    case 3:
    case 7:
      itemId = 0x1d;
      break;
    case 10:
    case 11:
    case 12:
      itemId = 0x1b;
      break;
    case 13:
      itemId = 0x18;
      break;
    default:
      break;
    }
    menuItemIds[count++] = itemId;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].secondaryOwnerNationTag != -1) {
    menuItemIds[count++] = 0x1c;
  }
  for (CivilianUnitKindStorage civilianUnitKind = 0; civilianUnitKind <= kCivilianUnitDriller;
       ++civilianUnitKind) {
    if (g_pGlobalMapState->IsUnitPresent(nTileIndex, civilianUnitKind)) {
      menuItemIds[count++] = static_cast<short>(civilianUnitKind + 0x21);
    }
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].perTileVisitedFlag > 0) {
    menuItemIds[count++] = 0x2a;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
      kMapTileActionStateBlockadingFleet) {
    menuItemIds[count++] = 0x2b;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
      kMapTileActionStateAnchor) {
    menuItemIds[count++] = 0x2c;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
      kMapTileActionStateMovingFleet) {
    menuItemIds[count++] = 0x2d;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
      kMapTileActionStatePatrollingFleet) {
    menuItemIds[count++] = 0x2e;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
      kMapTileActionStateInvadingFleet) {
    menuItemIds[count++] = 0x2f;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
      kMapTileActionStateDockedFleet) {
    menuItemIds[count++] = 0x30;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
          kMapTileActionStateFleetFrameFirst ||
      g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionState ==
          kMapTileActionStateFleetFrameLast) {
    menuItemIds[count++] = 0x31;
  }

  // Push the list into the 12 'i00a'..'i00l' item panes.
  InitializeUiTextStyleDescriptor(&itemStyle, 4, 0xc, 0x2b6d, 3);
  for (short i = 0; i < 12; i++) {
    TStaticText* itemPane = static_cast<TStaticText*>(FindSubView(kControlTagI00a + i));
    itemPane->InstallTextStyle(itemStyle, 1);
    short itemId = menuItemIds[i];
    if (itemId != 0) {
      itemPane->SetTextWithStrListID(0x2755, itemId, true);
      itemPane->Show(1, 0);
      itemPane->ViewEnable(1, 0);
    } else {
      itemPane->Show(0, 1);
      itemPane->ViewEnable(0, 0);
    }
    itemPane->SetJustification(i > 6 ? -1 : -2, false);
  }

  // Refresh the two lonely-tile preview panes.
  TLonelyTileView* tilePane = static_cast<TLonelyTileView*>(FindSubView(kControlTagTile));
  tilePane->AssertValid();
  tilePane->tileIndex = nTileIndex;
  tilePane->RefreshControl();
  TLonelyTileView* tile2Pane = static_cast<TLonelyTileView*>(FindSubView(kControlTagTil2));
  tile2Pane->AssertValid();
  tile2Pane->tileIndex = nTileIndex;
  tile2Pane->RefreshControl();

  // Style the 'info' pane.
  InitializeUiTextStyleDescriptor(&itemStyle, 0, 0xc, 0x2b67, 3);
  infoTextPane = static_cast<TDeluxeText*>(FindSubView(kControlTagInfo));
  infoTextPane->SetTextStyle(itemStyle, false);

  // Title pane + location text.
  TextStyle titleStyle;
  titleStyle.textColor = 0;
  CString strCityName;
  CString strTemplate;
  CString strOwnerLabel;
  CString strInfoText;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xc, 0x2b67, 1);
  TStaticText* titlePane = static_cast<TStaticText*>(FindSubView(kControlTagTitl));
  titlePane->Show(1, 1);
  titlePane->ViewEnable(0, 1);
  titlePane->SetJustification(1, false);
  titlePane->InstallTextStyle(titleStyle, 0);

  if (g_pGlobalMapState->terrainStateTable[nTileIndex].GetTerrainKind() == kStrategicTerrainWater) {
    TZone* zone = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    zone->AssignZoneDisplayNameToOutputRef(&strInfoText);
  } else {
    short cityIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
    g_pGlobalMapState->AssignCityRecordDisplayName(cityIndex, &strCityName);
    int ownerNation = g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode;
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&strOwnerLabel);
    g_pSimMgr->GetString(0x2755, (ownerNation < kMajorNationCount) ? 0x1d : 0x1e, &strTemplate);
    scanBracketExpressions(g_pSimMgr, &strInfoText, static_cast<LPCSTR>(strTemplate),
                           static_cast<LPCSTR>(strCityName), static_cast<LPCSTR>(strOwnerLabel));
    if (g_pGlobalMapState->cityScoreTable[cityIndex].formerOwnerNationCode != ownerNation) {
      CString strFormerLine;
      {
        strOwnerLabel = g_pSimMgr->GetCountryName(
            g_pGlobalMapState->cityScoreTable[cityIndex].formerOwnerNationCode);
      }
      g_pSimMgr->GetString(0x2755, 0x1f, &strTemplate);
      scanBracketExpressions(g_pSimMgr, &strFormerLine, static_cast<LPCSTR>(strTemplate),
                             static_cast<LPCSTR>(strOwnerLabel));
      strInfoText += "\n" + strFormerLine;
    }
  }
  titlePane->SetTextAndMaybeRefresh(&strInfoText, true);
  HighlightMenuItem(0);
}

// FUNCTION: IMPERIALISM 0x005057a0
void TTerrainHelpPicture::HighlightMenuItem(int selectedIndex) {
  GetWindow();
  TextStyle normalStyle;
  TextStyle highlightStyle;
  TextStyle captionStyle;
  normalStyle.textColor = 0;
  highlightStyle.textColor = 0;
  captionStyle.textColor = 0;
  InitializeUiTextStyleDescriptor(&normalStyle, 4, 0xc, 0x2b6d, 3);
  InitializeUiTextStyleDescriptor(&highlightStyle, 4, 0xc, 0x2b69, 3);
  InitializeUiTextStyleDescriptor(&captionStyle, 0, 0xc, 0x2b67, 1);

  TStaticText* captionPane = static_cast<TStaticText*>(FindSubView(kControlTagItem));
  captionPane->SetTextWithStrListID(0x2755, menuItemIds[selectedIndex], true);
  captionPane->Show(1, 1);
  captionPane->ViewEnable(0, 1);
  captionPane->SetJustification(1, false);
  captionPane->InstallTextStyle(captionStyle, 0);

  for (int i = 0; i < 12; i++) {
    TStaticText* itemPane = static_cast<TStaticText*>(FindSubView(kControlTagI00a + i));
    itemPane->InstallTextStyle((selectedIndex == i) ? highlightStyle : normalStyle, 1);
  }

  CString detailText;
  g_pSimMgr->GetString(0x2756, static_cast<short>(menuItemIds[selectedIndex] - 1), &detailText);
  infoTextPane->SetEntryText(&detailText, true);
  infoTextPane->Show(1, 1);
}

// FUNCTION: IMPERIALISM 0x005059d0
void TTerrainHelpPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::DoEvent(commandId, sourceHandler, event);
  if (commandId == 0xd) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= kControlTagI00a && tag < kControlTagI00m) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
      short index = static_cast<short>(sourceHandler->controlTag) - 0x3061;
      HighlightMenuItem(index);
    }
  }
}
