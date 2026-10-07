#include "game/ui_widgets/TCivReport.h"
#include "game/mfc.h"

#include "game/globals/map_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/CString.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TCivReport, TPicture)

// FUNCTION: IMPERIALISM 0x00590c30
TCivReport::TCivReport() {}

// FUNCTION: IMPERIALISM 0x00590c90
TCivReport::~TCivReport() {}

// FUNCTION: IMPERIALISM 0x00590cb0
void TCivReport::StuffValues(TCivUnit* civilianOrderEntry) {
  CString reportText;
  CString templateText;
  CString expandedText;
  CString valueText;
  CString secondaryValue;
  CString cityName;

  int resourceCount;
  bool appendTurnCount = true;
  g_pSimMgr->GetString(0x2724, 0, &templateText);
  g_pSimMgr->GetString(0x2718, civilianOrderEntry->orderType, &valueText);
  short tileIndex = civilianOrderEntry->tileIndex;
  g_pGlobalMapState->AssignCityRecordDisplayName(
      g_pGlobalMapState->terrainStateTable[tileIndex].cityRecordIndex, &cityName);
  scanBracketExpressions(g_pSimMgr, &reportText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(valueText), static_cast<LPCSTR>(cityName));
  reportText += '\n';

  switch (civilianOrderEntry->unitOrder) {
  case kUnitOrderLayRail:
    g_pSimMgr->GetString(0x2724, 1, &valueText);
    reportText += valueText + s_szLineBreak;
    break;

  case kUnitOrderBuildDepot:
    g_pSimMgr->GetString(0x2724, 2, &valueText);
    reportText += valueText + s_szLineBreak;
    break;

  case kUnitOrderBuildPort:
    g_pSimMgr->GetString(0x2724, 3, &valueText);
    reportText += valueText + s_szLineBreak;
    break;

  case kUnitOrderProspect:
    g_pSimMgr->GetString(0x2724, 4, &valueText);
    reportText += valueText + s_szLineBreak;
    break;

  case kUnitOrderDevelopResource:
    if (civilianOrderEntry->orderType == kCivilianUnitMiner &&
        g_pGlobalMapState->GetDevelopmentLevel(tileIndex, true) == 0) {
      resourceCount = 0;
      for (short edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
        short resourceType =
            g_pGlobalMapState->terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex];
        if (resourceType != -1 && g_abResourceTypeMiniCivMentionFlag[resourceType] != 0) {
          CString* resourceName;
          if (edgeIndex == 0) {
            resourceName = &valueText;
          } else {
            resourceName = &secondaryValue;
          }
          g_pSimMgr->GetString(0x2711, resourceType, resourceName);
          ++resourceCount;
        }
      }

      if (resourceCount > 1) {
        g_pSimMgr->GetString(0x2724, 6, &templateText);
        scanBracketExpressions(g_pSimMgr, &expandedText, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(valueText), static_cast<LPCSTR>(secondaryValue));
      } else {
        g_pSimMgr->GetString(0x2724, 10, &templateText);
        scanBracketExpressions(g_pSimMgr, &expandedText, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(valueText));
      }
      reportText += expandedText + s_szLineBreak;
      break;
    }

    if (civilianOrderEntry->orderType == kCivilianUnitDeveloper) {
      g_pSimMgr->GetString(0x2724, 5, &templateText);
      g_pSimMgr->GetString(0x2725, civilianOrderEntry->orderType, &valueText);
      scanBracketExpressions(g_pSimMgr, &expandedText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(valueText));
      reportText += expandedText + s_szLineBreak;
    } else {
      g_pSimMgr->GetString(0x2724, 7, &templateText);
      g_pSimMgr->GetString(0x2725, civilianOrderEntry->orderType, &valueText);
      scanBracketExpressions(g_pSimMgr, &expandedText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(valueText));
      reportText += expandedText + s_szLineBreak;
    }
    break;

  case kUnitOrderRedeploy:
    g_pSimMgr->GetString(0x2724, 8, &valueText);
    reportText += valueText;
    appendTurnCount = false;
    break;
  }

  if (appendTurnCount) {
    g_pSimMgr->GetString(0x2724, 9, &templateText);
    valueText.Format(g_szDecimalFormat, civilianOrderEntry->remainingTurns * 3);
    scanBracketExpressions(g_pSimMgr, &expandedText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(valueText));
    reportText += expandedText;
  }

  TDeluxeText* infoControl = static_cast<TDeluxeText*>(FindSubView(kControlTagInfo));
  infoControl->AssertValid();
  infoControl->UpdateTextEntrySharedStringAndMaybeNotify(&reportText, false);
  infoControl->SetTextStyle(0, 12, 0x2b6a);
  infoControl->SetJustification(1, false);
  infoControl->CenterVertically(true);

  for (int titleIndex = 0; titleIndex < 3; ++titleIndex) {
    TextStyle titleStyle;
    titleStyle.textColor = 0;
    if (titleIndex > 0) {
      BuildUiTextStyleDescriptor(&titleStyle, 0, 12, 0x2b6a);
    } else {
      BuildUiTextStyleDescriptor(&titleStyle, 0, 14, 0x2b6a);
    }
    TStaticText* titleControl =
        static_cast<TStaticText*>(FindSubView(IMPERIALISM_FOURCC('t', 't', 'l', '0') + titleIndex));
    titleControl->AssertValid();
    titleControl->SetTextWithStrListID(0x2724, static_cast<short>(titleIndex + 12), true);
    titleControl->InstallTextStyle(titleStyle, 0);
    titleControl->SetJustification(1, false);
  }
}
