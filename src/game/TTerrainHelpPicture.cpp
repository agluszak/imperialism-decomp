#include "game/TTerrainHelpPicture.h"

#include "game/TDeluxeText.h"
#include "game/TLonelyTileView.h"
#include "game/TMapMgr.h"
#include "game/TOcean.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TZone.h"
#include "game/TControl.h"
#include "game/TSoundPlayer.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"

#include <string.h>

// SYNTHETIC: IMPERIALISM 0x0043d7a0
// TTerrainHelpPicture::`scalar deleting destructor'
TTerrainHelpPicture::~TTerrainHelpPicture() {}
// SYNTHETIC: IMPERIALISM 0x00504df0
// TTerrainHelpPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00504e70
// TTerrainHelpPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTerrainHelpPicture, TPicture)

TTerrainHelpPicture::TTerrainHelpPicture() {}

// FUNCTION: IMPERIALISM 0x00504e90
void TTerrainHelpPicture::BuildMapTileActionContextMenu(short nTileIndex) {
  TUiTextStyleDescriptor itemStyle;
  itemStyle.textColor = 0;
  memset(menuItemIds94, 0, sizeof(menuItemIds94));
  short count = 0;

  // Build the item-id list from the selected tile's record.
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags1c & 1) {
    menuItemIds94[count++] = 0x11;
  }
  menuItemIds94[count++] =
      static_cast<short>(g_pGlobalMapState->terrainStateTable[nTileIndex].gateFlag + 1);
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].roadFlag != 0) {
    menuItemIds94[count++] = 0x16;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].ownerBorderMask07 != 0) {
    if (g_pGlobalMapState->terrainStateTable[nTileIndex].terrainType00 != 5) {
      menuItemIds94[count++] = 0x13;
    } else {
      menuItemIds94[count++] = 0x32;
    }
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].cityBorderMask08 != 0 &&
      g_pGlobalMapState->terrainStateTable[nTileIndex].cityBorderMask08 !=
          g_pGlobalMapState->terrainStateTable[nTileIndex].ownerBorderMask07) {
    menuItemIds94[count++] = 0x12;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags1c & 0x14) {
    menuItemIds94[count++] = 0x14;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].activeFlags1c & 0x20) {
    menuItemIds94[count++] = 0x1d;
  }

  if (g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(nTileIndex, 0) != 0 ||
      g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(nTileIndex, 1) != 0) {
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
    menuItemIds94[count++] = itemId;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].secondaryOwnerNationTag18 != -1) {
    menuItemIds94[count++] = 0x1c;
  }
  for (short orderType = 0; orderType <= 8; orderType++) {
    if (g_pGlobalMapState->TileHasCivilianOrderOfType(nTileIndex, orderType)) {
      menuItemIds94[count++] = static_cast<short>(orderType + 0x21);
    }
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].perTileVisitedFlag0f > 0) {
    menuItemIds94[count++] = 0x2a;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 2) {
    menuItemIds94[count++] = 0x2b;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 3) {
    menuItemIds94[count++] = 0x2c;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 4) {
    menuItemIds94[count++] = 0x2d;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 5) {
    menuItemIds94[count++] = 0x2e;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 6) {
    menuItemIds94[count++] = 0x2f;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 0xe) {
    menuItemIds94[count++] = 0x30;
  }
  if (g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 0x10 ||
      g_pGlobalMapState->terrainStateTable[nTileIndex].tileActionClass16 == 0x11) {
    menuItemIds94[count++] = 0x31;
  }

  // Push the list into the 12 'i00a'..'i00l' item panes.
  InitializeUiTextStyleDescriptor(&itemStyle, 4, 0xc, 0x2b6d, 3);
  for (short i = 0; i < 12; i++) {
    TStaticText* itemPane =
        static_cast<TStaticText*>(ResolveControlByTag(0x69303061 /* 'i00a' */ + i));
    itemPane->SetTextStyleAndMaybeRefresh(&itemStyle, 1);
    short itemId = menuItemIds94[i];
    if (itemId != 0) {
      itemPane->LoadUiStringAndDispatchViaVslot1C8(0x2755, itemId, 1);
      itemPane->SetEnabled(1, 0);
      itemPane->SetState(1, 0);
    } else {
      itemPane->SetEnabled(0, 1);
      itemPane->SetState(0, 0);
    }
    itemPane->SetTextThemeCodeAndMaybeRefresh(i > 6 ? -1 : -2, 0);
  }

  // Refresh the two lonely-tile preview panes.
  TLonelyTileView* tilePane =
      static_cast<TLonelyTileView*>(ResolveControlByTag(0x74696c65 /* 'tile' */));
  tilePane->AssertValid();
  tilePane->tileIndex60 = nTileIndex;
  tilePane->RefreshControl();
  TLonelyTileView* tile2Pane =
      static_cast<TLonelyTileView*>(ResolveControlByTag(0x74696c32 /* 'til2' */));
  tile2Pane->AssertValid();
  tile2Pane->tileIndex60 = nTileIndex;
  tile2Pane->RefreshControl();

  // Style the 'info' pane.
  InitializeUiTextStyleDescriptor(&itemStyle, 0, 0xc, 0x2b67, 3);
  infoTextPane90 = static_cast<TDeluxeText*>(ResolveControlByTag(0x696e666f /* 'info' */));
  infoTextPane90->ApplyTextStyleDescriptorAndMaybeRefresh(&itemStyle, 0);

  // Title pane + location text.
  TUiTextStyleDescriptor titleStyle;
  titleStyle.textColor = 0;
  CString strCityName;
  CString strTemplate;
  CString strOwnerLabel;
  CString strInfoText;
  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xc, 0x2b67, 1);
  TStaticText* titlePane = static_cast<TStaticText*>(ResolveControlByTag(0x7469746c /* 'titl' */));
  titlePane->SetEnabled(1, 1);
  titlePane->SetState(0, 1);
  titlePane->SetTextThemeCodeAndMaybeRefresh(1, 0);
  titlePane->SetTextStyleAndMaybeRefresh(&titleStyle, 0);

  if (g_pGlobalMapState->terrainStateTable[nTileIndex].terrainType00 == 5) {
    TZone* zone = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    zone->AssignZoneDisplayNameToOutputRef(&strInfoText);
  } else {
    short cityIndex = g_pGlobalMapState->terrainStateTable[nTileIndex].cityRecordIndex;
    g_pGlobalMapState->AssignCityRecordDisplayName(cityIndex, &strCityName);
    int ownerNation = g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00;
    g_apTerrainTypeDescriptorTable[ownerNation]->FormatOverlayTerrainLabelText(&strOwnerLabel);
    g_pSimMgr->GetString(0x2755, (ownerNation < 7) ? 0x1d : 0x1e, &strTemplate);
    scanBracketExpressions(g_pSimMgr, &strInfoText, static_cast<LPCSTR>(strTemplate),
                           static_cast<LPCSTR>(strCityName), static_cast<LPCSTR>(strOwnerLabel));
    if (g_pGlobalMapState->cityScoreTable[cityIndex].formerOwnerNationCode01 != ownerNation) {
      CString strFormerLine;
      {
        strOwnerLabel = g_pSimMgr->LoadNormalizedCredentialName(
            g_pGlobalMapState->cityScoreTable[cityIndex].formerOwnerNationCode01);
      }
      g_pSimMgr->GetString(0x2755, 0x1f, &strTemplate);
      scanBracketExpressions(g_pSimMgr, &strFormerLine, static_cast<LPCSTR>(strTemplate),
                             static_cast<LPCSTR>(strOwnerLabel));
      strInfoText += "\n" + strFormerLine;
    }
  }
  titlePane->AssignTextSharedRefIfChangedAndMaybeInvalidate(&strInfoText, 1);
  HighlightSelectedMenuItemAndRefreshDetailText(0);
}

// FUNCTION: IMPERIALISM 0x005057a0
void TTerrainHelpPicture::HighlightSelectedMenuItemAndRefreshDetailText(int selectedIndex) {
  OwnerPanel();
  TUiTextStyleDescriptor normalStyle;
  TUiTextStyleDescriptor highlightStyle;
  TUiTextStyleDescriptor captionStyle;
  normalStyle.textColor = 0;
  highlightStyle.textColor = 0;
  captionStyle.textColor = 0;
  InitializeUiTextStyleDescriptor(&normalStyle, 4, 0xc, 0x2b6d, 3);
  InitializeUiTextStyleDescriptor(&highlightStyle, 4, 0xc, 0x2b69, 3);
  InitializeUiTextStyleDescriptor(&captionStyle, 0, 0xc, 0x2b67, 1);

  TStaticText* captionPane =
      static_cast<TStaticText*>(ResolveControlByTag(0x6974656d /* 'item' */));
  captionPane->LoadUiStringAndDispatchViaVslot1C8(0x2755, menuItemIds94[selectedIndex], 1);
  captionPane->SetEnabled(1, 1);
  captionPane->SetState(0, 1);
  captionPane->SetTextThemeCodeAndMaybeRefresh(1, 0);
  captionPane->SetTextStyleAndMaybeRefresh(&captionStyle, 0);

  for (int i = 0; i < 12; i++) {
    TStaticText* itemPane =
        static_cast<TStaticText*>(ResolveControlByTag(0x69303061 /* 'i00a' */ + i));
    itemPane->SetTextStyleAndMaybeRefresh(
        (selectedIndex == i) ? &highlightStyle : &normalStyle, 1);
  }

  CString detailText;
  g_pSimMgr->GetString(0x2756, static_cast<short>(menuItemIds94[selectedIndex] - 1), &detailText);
  infoTextPane90->UpdateTextEntrySharedStringAndMaybeNotify(&detailText, 1);
  infoTextPane90->SetEnabled(1, 1);
}

// FUNCTION: IMPERIALISM 0x005059d0
void TTerrainHelpPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TControl::HandleEvent(commandId, sourceHandler, event);
  if (commandId == 0xd) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag >= kControlTagI00a && tag < kControlTagI00m) {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b58, 0, 1);
      short index = static_cast<short>(sourceHandler->controlTag) - 0x3061;
      HighlightSelectedMenuItemAndRefreshDetailText(index);
    }
  }
}
