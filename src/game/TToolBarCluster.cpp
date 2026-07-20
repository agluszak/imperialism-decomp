#include "game/TToolBarCluster.h"

#include "game/TApplication.h"
#include "game/TArmyMgr.h"
#include "game/TAssetMgr.h"
#include "game/TGlobalMapState.h"
#include "game/TMapUberPicture.h"
#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TTaskForce.h"
#include "game/TViewMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/map_overlay_geometry.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"

struct TGlobalMapCityScoreRecord;
// 0x00563360 -- __stdcall free resolver (defined in TMapMgr.cpp).
TGlobalMapCityScoreRecord* __stdcall GetProvinceByTileIndex(short nTileIndex);

// Resolves the turn-event dialog node for message context 0x102c (the "capabilities" dialog),
// computes its placement, and refreshes it. Standalone helper (no `this`) -- matches the
// original's own free-function shape. Defined below at its real address (0x5dc560), after
// this class's own methods.
void DispatchUiRuntimeMessage102CAndRefreshActiveView();

// Builds the 16 per-slot hover/hit-test rects consumed by
// TToolBarCluster::HandleCityBuildingHoverSelection from a table of 17 (x,y) anchor points.
// Most slots get a fixed 10x10 box at their anchor; slots 10 and 11 instead span between two
// consecutive anchors (a wider combined-slot region). Placement-constructs each CRect directly
// into the pre-existing global array, matching the original's direct constructor calls.
// FUNCTION: IMPERIALISM 0x004b95c0
void InitializeCityBuildingHoverSelectionRects_004b95c0() {
  short* coords = g_anCityBuildingSlotCoords;
  CRect* rects = g_aCityBuildingHoverSelectionRects;
  new (&rects[0]) CRect(coords[0], coords[1], coords[0] + 10, coords[1] + 10);
  new (&rects[1]) CRect(coords[2], coords[3], coords[2] + 10, coords[3] + 10);
  new (&rects[2]) CRect(coords[4], coords[5], coords[4] + 10, coords[5] + 10);
  new (&rects[3]) CRect(coords[6], coords[7], coords[6] + 10, coords[7] + 10);
  new (&rects[4]) CRect(coords[8], coords[9], coords[8] + 10, coords[9] + 10);
  new (&rects[5]) CRect(coords[10], coords[11], coords[10] + 10, coords[11] + 10);
  new (&rects[6]) CRect(coords[12], coords[13], coords[12] + 10, coords[13] + 10);
  new (&rects[7]) CRect(coords[14], coords[15], coords[14] + 10, coords[15] + 10);
  new (&rects[8]) CRect(coords[16], coords[17], coords[16] + 10, coords[17] + 10);
  new (&rects[9]) CRect(coords[18], coords[19], coords[18] + 10, coords[19] + 10);
  new (&rects[10]) CRect(coords[20], coords[21], coords[22] + 10, coords[23] + 10);
  new (&rects[11]) CRect(coords[24], coords[25], coords[26] + 10, coords[27] + 10);
  new (&rects[12]) CRect(coords[26], coords[27], coords[26] + 10, coords[27] + 10);
  new (&rects[13]) CRect(coords[28], coords[29], coords[28] + 10, coords[29] + 10);
  new (&rects[14]) CRect(coords[30], coords[31], coords[30] + 10, coords[31] + 10);
  new (&rects[15]) CRect(coords[32], coords[33], coords[32] + 10, coords[33] + 10);
}

// Populates the city-building screen's layout data: a 164-int packed table
// (g_anCityBuildingLayoutValues -- per-field semantics not yet recovered) immediately
// followed by 31 action-button rects (g_aCityBuildingActionRects), each
// placement-constructed directly into the pre-existing global array via the real
// CRect(int,int,int,int) constructor, matching the original's direct constructor calls.
// FUNCTION: IMPERIALISM 0x004b98b0
void InitializeCityBuildingLayoutData() {
  g_anCityBuildingLayoutValues[3] = 0x10a;
  g_anCityBuildingLayoutValues[15] = 0x10a;
  g_anCityBuildingLayoutValues[0] = 0x110;
  g_anCityBuildingLayoutValues[1] = 0xfc;
  g_anCityBuildingLayoutValues[2] = 0x11f;
  g_anCityBuildingLayoutValues[12] = 0x110;
  g_anCityBuildingLayoutValues[13] = 0xfc;
  g_anCityBuildingLayoutValues[14] = 0x11f;
  g_anCityBuildingLayoutValues[16] = 0xd3;
  g_anCityBuildingLayoutValues[24] = 0xd3;
  g_anCityBuildingLayoutValues[4] = 0x0;
  g_anCityBuildingLayoutValues[5] = 0x0;
  g_anCityBuildingLayoutValues[6] = 0x0;
  g_anCityBuildingLayoutValues[7] = 0x0;
  g_anCityBuildingLayoutValues[8] = 0x0;
  g_anCityBuildingLayoutValues[9] = 0x0;
  g_anCityBuildingLayoutValues[10] = 0x0;
  g_anCityBuildingLayoutValues[11] = 0x0;
  g_anCityBuildingLayoutValues[17] = 0xd1;
  g_anCityBuildingLayoutValues[18] = 0xe4;
  g_anCityBuildingLayoutValues[19] = 0xe0;
  g_anCityBuildingLayoutValues[20] = 0x0;
  g_anCityBuildingLayoutValues[21] = 0x0;
  g_anCityBuildingLayoutValues[22] = 0x0;
  g_anCityBuildingLayoutValues[23] = 0x0;
  g_anCityBuildingLayoutValues[25] = 0xd4;
  g_anCityBuildingLayoutValues[26] = 0x111;
  g_anCityBuildingLayoutValues[27] = 0x10f;
  g_anCityBuildingLayoutValues[28] = 0x0;
  g_anCityBuildingLayoutValues[29] = 0x0;
  g_anCityBuildingLayoutValues[30] = 0x0;
  g_anCityBuildingLayoutValues[31] = 0x0;
  g_anCityBuildingLayoutValues[32] = 0x0;
  g_anCityBuildingLayoutValues[33] = 0x0;
  g_anCityBuildingLayoutValues[34] = 0x0;
  g_anCityBuildingLayoutValues[35] = 0x0;
  g_anCityBuildingLayoutValues[36] = 0x1b4;
  g_anCityBuildingLayoutValues[37] = 0x15a;
  g_anCityBuildingLayoutValues[38] = 0x1c3;
  g_anCityBuildingLayoutValues[39] = 0x169;
  g_anCityBuildingLayoutValues[40] = 0x0;
  g_anCityBuildingLayoutValues[41] = 0x0;
  g_anCityBuildingLayoutValues[42] = 0x0;
  g_anCityBuildingLayoutValues[43] = 0x0;
  g_anCityBuildingLayoutValues[44] = 0x0;
  g_anCityBuildingLayoutValues[45] = 0x0;
  g_anCityBuildingLayoutValues[46] = 0x0;
  g_anCityBuildingLayoutValues[47] = 0x0;
  g_anCityBuildingLayoutValues[48] = 0x1a9;
  g_anCityBuildingLayoutValues[49] = 0x14c;
  g_anCityBuildingLayoutValues[50] = 0x1c3;
  g_anCityBuildingLayoutValues[51] = 0x169;
  g_anCityBuildingLayoutValues[52] = 0x16b;
  g_anCityBuildingLayoutValues[53] = 0x116;
  g_anCityBuildingLayoutValues[54] = 0x187;
  g_anCityBuildingLayoutValues[55] = 0x131;
  g_anCityBuildingLayoutValues[56] = 0x0;
  g_anCityBuildingLayoutValues[57] = 0x0;
  g_anCityBuildingLayoutValues[58] = 0x0;
  g_anCityBuildingLayoutValues[59] = 0x0;
  g_anCityBuildingLayoutValues[60] = 0x1a9;
  g_anCityBuildingLayoutValues[61] = 0x14c;
  g_anCityBuildingLayoutValues[62] = 0x1c3;
  g_anCityBuildingLayoutValues[63] = 0x169;
  g_anCityBuildingLayoutValues[64] = 0x173;
  g_anCityBuildingLayoutValues[65] = 0x123;
  g_anCityBuildingLayoutValues[66] = 0x199;
  g_anCityBuildingLayoutValues[67] = 0x14b;
  g_anCityBuildingLayoutValues[68] = 0x0;
  g_anCityBuildingLayoutValues[77] = 0xed;
  g_anCityBuildingLayoutValues[89] = 0xed;
  g_anCityBuildingLayoutValues[69] = 0x0;
  g_anCityBuildingLayoutValues[70] = 0x0;
  g_anCityBuildingLayoutValues[71] = 0x0;
  g_anCityBuildingLayoutValues[72] = 0x16c;
  g_anCityBuildingLayoutValues[73] = 0xb7;
  g_anCityBuildingLayoutValues[74] = 0x192;
  g_anCityBuildingLayoutValues[75] = 0xeb;
  g_anCityBuildingLayoutValues[76] = 0x185;
  g_anCityBuildingLayoutValues[78] = 0x1ce;
  g_anCityBuildingLayoutValues[79] = 0x10d;
  g_anCityBuildingLayoutValues[80] = 0x0;
  g_anCityBuildingLayoutValues[81] = 0x0;
  g_anCityBuildingLayoutValues[82] = 0x0;
  g_anCityBuildingLayoutValues[83] = 0x0;
  g_anCityBuildingLayoutValues[84] = 0x155;
  g_anCityBuildingLayoutValues[85] = 0xb6;
  g_anCityBuildingLayoutValues[86] = 0x192;
  g_anCityBuildingLayoutValues[87] = 0xf7;
  g_anCityBuildingLayoutValues[88] = 0x16f;
  g_anCityBuildingLayoutValues[90] = 0x1cd;
  g_anCityBuildingLayoutValues[91] = 0x11b;
  g_anCityBuildingLayoutValues[92] = 0x0;
  g_anCityBuildingLayoutValues[93] = 0x0;
  g_anCityBuildingLayoutValues[94] = 0x0;
  g_anCityBuildingLayoutValues[95] = 0x0;
  g_anCityBuildingLayoutValues[96] = 0x158;
  g_anCityBuildingLayoutValues[97] = 0xa1;
  g_anCityBuildingLayoutValues[98] = 0x166;
  g_anCityBuildingLayoutValues[99] = 0xbc;
  g_anCityBuildingLayoutValues[100] = 0x171;
  g_anCityBuildingLayoutValues[101] = 0x107;
  g_anCityBuildingLayoutValues[102] = 0x179;
  g_anCityBuildingLayoutValues[103] = 0x10f;
  g_anCityBuildingLayoutValues[104] = 0x12e;
  g_anCityBuildingLayoutValues[105] = 0xef;
  g_anCityBuildingLayoutValues[106] = 0x13f;
  g_anCityBuildingLayoutValues[107] = 0xfa;
  g_anCityBuildingLayoutValues[108] = 0x1d8;
  g_anCityBuildingLayoutValues[109] = 0x11a;
  g_anCityBuildingLayoutValues[110] = 0x1f3;
  g_anCityBuildingLayoutValues[111] = 0x14e;
  g_anCityBuildingLayoutValues[112] = 0x1ba;
  g_anCityBuildingLayoutValues[113] = 0x13d;
  g_anCityBuildingLayoutValues[114] = 0x1d0;
  g_anCityBuildingLayoutValues[115] = 0x146;
  g_anCityBuildingLayoutValues[116] = 0x0;
  g_anCityBuildingLayoutValues[117] = 0x0;
  g_anCityBuildingLayoutValues[118] = 0x0;
  g_anCityBuildingLayoutValues[119] = 0x0;
  g_anCityBuildingLayoutValues[120] = 0x1df;
  g_anCityBuildingLayoutValues[121] = 0x124;
  g_anCityBuildingLayoutValues[122] = 0x1f2;
  g_anCityBuildingLayoutValues[123] = 0x14e;
  g_anCityBuildingLayoutValues[124] = 0x1c6;
  g_anCityBuildingLayoutValues[125] = 0xfa;
  g_anCityBuildingLayoutValues[126] = 0x1e3;
  g_anCityBuildingLayoutValues[127] = 0x115;
  g_anCityBuildingLayoutValues[128] = 0x0;
  g_anCityBuildingLayoutValues[129] = 0x0;
  g_anCityBuildingLayoutValues[130] = 0x0;
  g_anCityBuildingLayoutValues[131] = 0x0;
  g_anCityBuildingLayoutValues[132] = 0x1da;
  g_anCityBuildingLayoutValues[133] = 0xd5;
  g_anCityBuildingLayoutValues[134] = 0x21a;
  g_anCityBuildingLayoutValues[135] = 0x113;
  g_anCityBuildingLayoutValues[136] = 0x1bb;
  g_anCityBuildingLayoutValues[137] = 0x121;
  g_anCityBuildingLayoutValues[138] = 0x208;
  g_anCityBuildingLayoutValues[139] = 0x14c;
  g_anCityBuildingLayoutValues[140] = 0x0;
  g_anCityBuildingLayoutValues[141] = 0x0;
  g_anCityBuildingLayoutValues[142] = 0x0;
  g_anCityBuildingLayoutValues[143] = 0x0;
  g_anCityBuildingLayoutValues[144] = 0xb3;
  g_anCityBuildingLayoutValues[145] = 0x144;
  g_anCityBuildingLayoutValues[146] = 0xc3;
  g_anCityBuildingLayoutValues[147] = 0x156;
  g_anCityBuildingLayoutValues[148] = 0xb4;
  g_anCityBuildingLayoutValues[149] = 0x15e;
  g_anCityBuildingLayoutValues[150] = 0xd2;
  g_anCityBuildingLayoutValues[151] = 0x173;
  g_anCityBuildingLayoutValues[152] = 0x0;
  g_anCityBuildingLayoutValues[153] = 0x0;
  g_anCityBuildingLayoutValues[154] = 0x0;
  g_anCityBuildingLayoutValues[155] = 0x0;
  g_anCityBuildingLayoutValues[156] = 0x8d;
  g_anCityBuildingLayoutValues[157] = 0x124;
  g_anCityBuildingLayoutValues[158] = 0xa9;
  g_anCityBuildingLayoutValues[159] = 0x141;
  g_anCityBuildingLayoutValues[160] = 0xc2;
  g_anCityBuildingLayoutValues[161] = 0x157;
  g_anCityBuildingLayoutValues[162] = 0xda;
  g_anCityBuildingLayoutValues[163] = 0x169;
  new (&g_aCityBuildingActionRects[0]) CRect(121, 325, 160, 338);
  new (&g_aCityBuildingActionRects[1]) CRect(185, 345, 224, 381);
  new (&g_aCityBuildingActionRects[2]) CRect(94, 326, 146, 368);
  new (&g_aCityBuildingActionRects[3]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[4]) CRect(284, 374, 299, 388);
  new (&g_aCityBuildingActionRects[5]) CRect(273, 402, 322, 439);
  new (&g_aCityBuildingActionRects[6]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[7]) CRect(303, 328, 327, 351);
  new (&g_aCityBuildingActionRects[8]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[9]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[10]) CRect(273, 327, 294, 348);
  new (&g_aCityBuildingActionRects[11]) CRect(304, 324, 328, 347);
  new (&g_aCityBuildingActionRects[12]) CRect(340, 362, 360, 381);
  new (&g_aCityBuildingActionRects[13]) CRect(441, 152, 463, 170);
  new (&g_aCityBuildingActionRects[14]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[15]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[16]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[17]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[18]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[19]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[20]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[21]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[22]) CRect(464, 130, 488, 153);
  new (&g_aCityBuildingActionRects[23]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[24]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[25]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[26]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[27]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[28]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[29]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingActionRects[30]) CRect(0, 0, 0, 0);
}

// SYNTHETIC: IMPERIALISM 0x00584d80
// TToolBarCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00584e00
// TToolBarCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TToolBarCluster, TCluster)

// FUNCTION: IMPERIALISM 0x00584e20
TToolBarCluster::TToolBarCluster() {}

// SYNTHETIC: IMPERIALISM 0x00584e50
// TToolBarCluster::`scalar deleting destructor'
TToolBarCluster::~TToolBarCluster() {}

// Resolves the turn-event dialog node for message context 0x102c (the "capabilities" dialog),
// computes its placement, and refreshes it. Standalone helper (no `this`) -- matches the

// FUNCTION: IMPERIALISM 0x00584ea0
void TToolBarCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::HandleEvent(commandId, sourceHandler, event);

  bool eligible = g_pApplicationUiRootController->InModalState() == 0;
  if (g_pApplicationUiRootController->screenModeAt24 > 1) {
    eligible = false;
  }
  if (commandId == 10 && eligible) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag > kControlTagFlagCaps) {
      // Original tail-calls into the shared 499-byte HandleCrossUSmallViewsCommandTagDispatch
      // (0x584f27, unowned) for every tag above 'Flag' -- not yet ported.
    } else if (tag == kControlTagFlagCaps) {
      DispatchUiRuntimeMessage102CAndRefreshActiveView();
    } else if (tag == kControlTagDoneCaps) {
      g_pSimMgr->PostMainWindowCommand100ForTurnFlow();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005851c0
void TToolBarCluster::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                          RgnHandle hitArg) {
  (void)point;
  (void)hitArg;
}

// FUNCTION: IMPERIALISM 0x005853f0
undefined TToolBarCluster::RefreshTurnOrderStatusPanelTextsAndControls() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00585ba0
void TToolBarCluster::UpdateControlTagTreaTextFromNationAndMapContext(short nationId) {
  // 'trea' tag: the active nation's treasury balance, only when the slot is eligible
  // for event processing (matches TSimMgr::IsNationSlotEligibleForEventProcessing's
  // major-slot/profile-band gate).
  CString treaText;
  if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationId)) {
    g_pSimMgr->FormatIntegerString(g_apNationStates[nationId]->treasuryValue10, &treaText);
  }
  TView* treaControl = this->ResolveControlByTag(0x74726561); // 'trea'
  if (treaControl != nullptr) {
    static_cast<TStaticText*>(treaControl)
        ->AssignTextSharedRefIfChangedAndMaybeInvalidate(&treaText, 1);
  }

  // 'seas' tag: "<season>, <year>" turn-status text (present on the main map toolbar).
  TView* seasControl = this->ResolveControlByTag(0x73656173); // 'seas'
  if (seasControl != nullptr) {
    CString seasonText;
    g_pSimMgr->FormatSeasonName(&seasonText);
    int year = 1815 + g_pSimMgr->quarterGateTick2c / 4;
    CString yearText;
    yearText.Format("%d", year);
    CString seasText = seasonText + ", " + yearText;
    static_cast<TStaticText*>(seasControl)
        ->AssignTextSharedRefIfChangedAndMaybeInvalidate(&seasText, 1);
    return;
  }

  // 'forc' tag: pending city-action-gate unit cost (present on the tactical/army
  // toolbar variant instead of 'seas'), expanded through the localized "[0]" template.
  TView* forcControl = this->ResolveControlByTag(0x666f7263); // 'forc'
  if (forcControl == nullptr) {
    return;
  }
  CString countText;
  if (g_pMapContextActionManager->pendingMapActionIndex != -1) {
    int cost = g_pMapContextActionManager->ComputeSelectedTileCityActionGateSum();
    countText.Format("%d", cost);
  } else {
    countText = "0";
  }
  CString templateText;
  g_pSimMgr->GetString(0x2732, 0x10, &templateText);
  CString forcText;
  scanBracketExpressions(g_pSimMgr, &forcText, static_cast<LPCSTR>(templateText),
                         static_cast<LPCSTR>(countText));
  static_cast<TStaticText*>(forcControl)
      ->AssignTextSharedRefIfChangedAndMaybeInvalidate(&forcText, 1);
}

// FUNCTION: IMPERIALISM 0x00585ee0
void TToolBarCluster::SehCleanup_ReleaseTwoTempSharedStringRefs(int unusedArg) {
  // Ground truth (RET 0x4) has one stack arg, never read by the body, and no
  // meaningful return value tracked (no AL write before return) -- the whole body
  // is two default-constructed CString locals immediately going out of scope, i.e.
  // an SEH cleanup shell with no real logic.
  (void)unusedArg;
  CString unused1;
  CString unused2;
}
// FUNCTION: IMPERIALISM 0x005dc560
void DispatchUiRuntimeMessage102CAndRefreshActiveView() {
  TView* node = g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x102c);
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0xf6c);
  }
  POINT placement;
  g_pUiRuntimeContext->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
  // TODO: dispatches through node's own vtable slot 0x1ac (word slot 0x6b) with no args --
  // that byte offset coincides with TControl::NoOpUiViewSlotHandler(int, int) elsewhere, but
  // that method takes 2 args while this callsite passes none, so node is NOT a TControl at
  // this slot (same "shared offset, different class" trap as elsewhere this session). node's
  // concrete class beyond TView (whose own declared extent tops out at slot 0x67, just short
  // of this slot) is unresolved, so this call is left unmodeled.
  node->CallVoidSlotA0();
  node->Free();
}
