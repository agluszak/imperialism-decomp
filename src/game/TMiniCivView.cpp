#include "game/TMiniCivView.h"

#include "game/CString.h"
#include "game/TCivUnit.h"
#include "game/TCountry.h"
#include "game/TMapMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004ab800
void TMiniCivView::Hilite() {}

// SYNTHETIC: IMPERIALISM 0x004ab820
// TMiniCivView::`scalar deleting destructor'
TMiniCivView::~TMiniCivView() {}
// SYNTHETIC: IMPERIALISM 0x004ab8c0
// TMiniCivView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ab950
// TMiniCivView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniCivView, TControl)

// FUNCTION: IMPERIALISM 0x004ab970
void TMiniCivView::InitializeForCivilianUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                             TCivUnit* civUnit) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
  civUnit84 = civUnit;
  eventNumber60 = 0x22;
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

  switch (civUnit->unitOrder) {
  case kUnitOrderLayRail:
    g_pSimMgr->GetString(0x2724, 1, &textA);
    assembled += textA + "\n";
    break;
  case kUnitOrderBuildDepot:
    g_pSimMgr->GetString(0x2724, 2, &textA);
    assembled += textA + "\n";
    break;
  case kUnitOrderBuildPort:
    g_pSimMgr->GetString(0x2724, 3, &textA);
    assembled += textA + "\n";
    break;
  case kUnitOrderProspect:
    g_pSimMgr->GetString(0x2724, 4, &textA);
    assembled += textA + "\n";
    break;
  case kUnitOrderDevelopResource:
    if (civUnit->orderType == EncodeCivilianUnitKind(kCivilianUnitMiner) &&
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
      if (civUnit->orderType == EncodeCivilianUnitKind(kCivilianUnitDeveloper)) {
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
  case kUnitOrderRedeploy:
    g_pSimMgr->GetString(0x2724, 8, &textA);
    assembled += textA;
    break;
  default:
    break;
  }

  unitText88 = assembled;
}

// FUNCTION: IMPERIALISM 0x004ac000
void TMiniCivView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter, like the other Draws

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b67, 3);

  // lineText holds the order-type name for the first line, then gets overwritten with
  // the "<city>, <nation>" location line for the second draw below.
  CString lineText;
  CString nationName;
  g_pSimMgr->GetString(0x2718, civUnit84->orderType, &lineText);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x18);
  DrawTextWithCachedQuickDrawStyleState(&lineText);

  CString cityName;
  // Each field is re-read through terrainStateTable[tileIndex06] separately (not cached
  // in a shared reference), matching the original's own re-computation at each site.
  g_apTerrainTypeDescriptorTable[g_pGlobalMapState->terrainStateTable[civUnit84->tileIndex06]
                                     .ownerNationTag04]
      ->FormatOverlayTerrainLabelText(&nationName);
  g_pGlobalMapState->AssignCityRecordDisplayName(
      g_pGlobalMapState->terrainStateTable[civUnit84->tileIndex06].cityRecordIndex, &cityName);
  {
    // Scoped so the assembled-line temp is destroyed right after the assignment,
    // matching the original (which destroys it immediately, not at function end).
    CString cityLine = cityName + g_szListSeparator_00695760 + nationName;
    lineText = cityLine;
  }

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b6a, 3);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x26);
  DrawTextWithCachedQuickDrawStyleState(&lineText);

  SetQuickDrawTextOriginWithContextOffset(0x40, 0x34);
  DrawTextWithCachedQuickDrawStyleState(&unitText88);

  // Civ-unit order-icon column, selected by the current improvement selection state
  // (0-indexed sprite column, each 0x40px wide) from a third icon strip cached on
  // TMacViewMgr at +0x66c (distinct from the +0x694/+0x68c strips used elsewhere).
  short iconColumn = g_pGlobalMapState->ApplyMapImprovementSelectionState(civUnit84);
  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x66c) + 4);
  RECT srcRect = {iconColumn, 0, iconColumn + 0x40, 0x40};
  RECT dstRect = {0, 0, 0x40, 0x40};
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(iconStripSurface,
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);
  SetQuickDrawStrokeColor(0x13);
}

// FUNCTION: IMPERIALISM 0x004ac320
void TMiniCivView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler == this) {
    ownerContext->GetNextHandler();
    // The original also writes civUnit84->tileIndex06 into a short field at the same
    // +0x84 offset on ownerContext's concrete (unrecovered) class -- distinct from this
    // class's own field84 (unitText88, a CString) despite the matching offset. Left
    // unresolved pending that class's recovery rather than guessing its layout (same
    // pattern as TMiniArmyView::DoEvent's own ownerContext->field84 write).
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
