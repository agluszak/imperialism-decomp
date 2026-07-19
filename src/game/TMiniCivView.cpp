#include "game/TMiniCivView.h"

#include "game/CString.h"
#include "game/TCivUnit.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/localization_text_helpers.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004ab800
undefined TMiniCivView::OrphanRetStub_004ab800() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004ab820
// TMiniCivView::`scalar deleting destructor'
TMiniCivView::~TMiniCivView() {}
// SYNTHETIC: IMPERIALISM 0x004ab8c0
// TMiniCivView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ab950
// TMiniCivView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniCivView, TControl)

// FUNCTION: IMPERIALISM 0x004ab970
void TMiniCivView::ConstructTMiniCivViewBaseState(TView* panel, int* offsetLayout, int* sizeLayout,
                                                  TCivUnit* civUnit) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
  civUnit84 = civUnit;
  frameStyle60 = 0x22;
  SetControlHoverHelpText(g_pMiniCivSharedText_0064cb18, this);

  CString assembled;
  CString textA;
  CString textB;
  CString templateText;
  CString formatted;
  short tile = civUnit->tileIndex06;
  {
    CString empty(g_pMiniCivSharedText_0064cb18);
    assembled = empty;
  }

  switch (civUnit->field_8) {
  case 5:
    g_pSimMgr->GetString(0x2724, 1, &textA);
    assembled += textA + "\n";
    break;
  case 6:
    g_pSimMgr->GetString(0x2724, 2, &textA);
    assembled += textA + "\n";
    break;
  case 7:
    g_pSimMgr->GetString(0x2724, 3, &textA);
    assembled += textA + "\n";
    break;
  case 8:
    g_pSimMgr->GetString(0x2724, 4, &textA);
    assembled += textA + "\n";
    break;
  case 10:
    if (civUnit->orderType == 0 &&
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tile, 1) == 0) {
      // Undeveloped tile: name the (up to two) improvable edge resources.
      int matchCount = 0;
      short edge;
      for (edge = 0; edge < 2; ++edge) {
        short type = g_pGlobalMapState->terrainStateTable[tile].resourceTypeByEdge[edge];
        if (type != -1 && g_abResourceTypeMiniCivMentionFlag[type] != 0) {
          g_pSimMgr->GetString(0x2711, type, (edge != 0) ? &textB : &textA);
          ++matchCount;
        }
      }
      if (1 < static_cast<short>(matchCount)) {
        g_pSimMgr->GetString(0x2724, 6, &templateText);
        scanBracketExpressions(g_pSimMgr, &formatted, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(textA), static_cast<LPCSTR>(textB));
      } else {
        g_pSimMgr->GetString(0x2724, 0xa, &templateText);
        scanBracketExpressions(g_pSimMgr, &formatted, static_cast<LPCSTR>(templateText),
                               static_cast<LPCSTR>(textA));
      }
      assembled += formatted + "\n";
    } else {
      // Active work order: "<building X>"-style line keyed by the order type.
      if (civUnit->orderType == 7) {
        g_pSimMgr->GetString(0x2724, 5, &templateText);
      } else {
        g_pSimMgr->GetString(0x2724, 7, &templateText);
      }
      g_pSimMgr->GetString(0x2725, civUnit->orderType, &textA);
      scanBracketExpressions(g_pSimMgr, &formatted, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(textA));
      assembled += formatted + "\n";
    }
    break;
  case 1:
    g_pSimMgr->GetString(0x2724, 8, &textA);
    assembled += textA;
    break;
  default:
    break;
  }

  unitText88 = assembled;
}

// FUNCTION: IMPERIALISM 0x004ac000
void TMiniCivView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x004ac320
void TMiniCivView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}
