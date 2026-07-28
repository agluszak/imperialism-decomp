#include "game/ui_widgets/TToolBarCluster.h"
#include "game/ui_tags_common.h"
#include "game/resource_manifest_tags.h"
#include "game/ui_tags_widgets.h"

#include "game/ui_core/TApplication.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/military/TArmyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/assets/TAssetMgr.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/THelpMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TDropShadowNumberText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TStaticText.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/raw_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/map_overlay_geometry.h"
#include "game/military/mapped_flavor_text.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

struct Province;
// 0x00563360 -- __stdcall free resolver (defined in TMapMgr.cpp).
Province* __stdcall GetProvinceByTileIndex(short nTileIndex);

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

// Populates the city-building screen's 72-rect layout table
// (g_aCityBuildingLayoutRects): elements 0..40 by per-field stores, elements 41..71
// (the action-button rects at 0x6a2778) placement-constructed into the pre-existing
// global array via the real CRect(int,int,int,int) constructor, matching the
// original's direct constructor calls.
// FUNCTION: IMPERIALISM 0x004b98b0
void InitializeCityBuildingLayoutData() {
  g_aCityBuildingLayoutRects[0].bottom = 0x10a;
  g_aCityBuildingLayoutRects[3].bottom = 0x10a;
  g_aCityBuildingLayoutRects[0].left = 0x110;
  g_aCityBuildingLayoutRects[0].top = 0xfc;
  g_aCityBuildingLayoutRects[0].right = 0x11f;
  g_aCityBuildingLayoutRects[3].left = 0x110;
  g_aCityBuildingLayoutRects[3].top = 0xfc;
  g_aCityBuildingLayoutRects[3].right = 0x11f;
  g_aCityBuildingLayoutRects[4].left = 0xd3;
  g_aCityBuildingLayoutRects[6].left = 0xd3;
  g_aCityBuildingLayoutRects[1].left = 0x0;
  g_aCityBuildingLayoutRects[1].top = 0x0;
  g_aCityBuildingLayoutRects[1].right = 0x0;
  g_aCityBuildingLayoutRects[1].bottom = 0x0;
  g_aCityBuildingLayoutRects[2].left = 0x0;
  g_aCityBuildingLayoutRects[2].top = 0x0;
  g_aCityBuildingLayoutRects[2].right = 0x0;
  g_aCityBuildingLayoutRects[2].bottom = 0x0;
  g_aCityBuildingLayoutRects[4].top = 0xd1;
  g_aCityBuildingLayoutRects[4].right = 0xe4;
  g_aCityBuildingLayoutRects[4].bottom = 0xe0;
  g_aCityBuildingLayoutRects[5].left = 0x0;
  g_aCityBuildingLayoutRects[5].top = 0x0;
  g_aCityBuildingLayoutRects[5].right = 0x0;
  g_aCityBuildingLayoutRects[5].bottom = 0x0;
  g_aCityBuildingLayoutRects[6].top = 0xd4;
  g_aCityBuildingLayoutRects[6].right = 0x111;
  g_aCityBuildingLayoutRects[6].bottom = 0x10f;
  g_aCityBuildingLayoutRects[7].left = 0x0;
  g_aCityBuildingLayoutRects[7].top = 0x0;
  g_aCityBuildingLayoutRects[7].right = 0x0;
  g_aCityBuildingLayoutRects[7].bottom = 0x0;
  g_aCityBuildingLayoutRects[8].left = 0x0;
  g_aCityBuildingLayoutRects[8].top = 0x0;
  g_aCityBuildingLayoutRects[8].right = 0x0;
  g_aCityBuildingLayoutRects[8].bottom = 0x0;
  g_aCityBuildingLayoutRects[9].left = 0x1b4;
  g_aCityBuildingLayoutRects[9].top = 0x15a;
  g_aCityBuildingLayoutRects[9].right = 0x1c3;
  g_aCityBuildingLayoutRects[9].bottom = 0x169;
  g_aCityBuildingLayoutRects[10].left = 0x0;
  g_aCityBuildingLayoutRects[10].top = 0x0;
  g_aCityBuildingLayoutRects[10].right = 0x0;
  g_aCityBuildingLayoutRects[10].bottom = 0x0;
  g_aCityBuildingLayoutRects[11].left = 0x0;
  g_aCityBuildingLayoutRects[11].top = 0x0;
  g_aCityBuildingLayoutRects[11].right = 0x0;
  g_aCityBuildingLayoutRects[11].bottom = 0x0;
  g_aCityBuildingLayoutRects[12].left = 0x1a9;
  g_aCityBuildingLayoutRects[12].top = 0x14c;
  g_aCityBuildingLayoutRects[12].right = 0x1c3;
  g_aCityBuildingLayoutRects[12].bottom = 0x169;
  g_aCityBuildingLayoutRects[13].left = 0x16b;
  g_aCityBuildingLayoutRects[13].top = 0x116;
  g_aCityBuildingLayoutRects[13].right = 0x187;
  g_aCityBuildingLayoutRects[13].bottom = 0x131;
  g_aCityBuildingLayoutRects[14].left = 0x0;
  g_aCityBuildingLayoutRects[14].top = 0x0;
  g_aCityBuildingLayoutRects[14].right = 0x0;
  g_aCityBuildingLayoutRects[14].bottom = 0x0;
  g_aCityBuildingLayoutRects[15].left = 0x1a9;
  g_aCityBuildingLayoutRects[15].top = 0x14c;
  g_aCityBuildingLayoutRects[15].right = 0x1c3;
  g_aCityBuildingLayoutRects[15].bottom = 0x169;
  g_aCityBuildingLayoutRects[16].left = 0x173;
  g_aCityBuildingLayoutRects[16].top = 0x123;
  g_aCityBuildingLayoutRects[16].right = 0x199;
  g_aCityBuildingLayoutRects[16].bottom = 0x14b;
  g_aCityBuildingLayoutRects[17].left = 0x0;
  g_aCityBuildingLayoutRects[19].top = 0xed;
  g_aCityBuildingLayoutRects[22].top = 0xed;
  g_aCityBuildingLayoutRects[17].top = 0x0;
  g_aCityBuildingLayoutRects[17].right = 0x0;
  g_aCityBuildingLayoutRects[17].bottom = 0x0;
  g_aCityBuildingLayoutRects[18].left = 0x16c;
  g_aCityBuildingLayoutRects[18].top = 0xb7;
  g_aCityBuildingLayoutRects[18].right = 0x192;
  g_aCityBuildingLayoutRects[18].bottom = 0xeb;
  g_aCityBuildingLayoutRects[19].left = 0x185;
  g_aCityBuildingLayoutRects[19].right = 0x1ce;
  g_aCityBuildingLayoutRects[19].bottom = 0x10d;
  g_aCityBuildingLayoutRects[20].left = 0x0;
  g_aCityBuildingLayoutRects[20].top = 0x0;
  g_aCityBuildingLayoutRects[20].right = 0x0;
  g_aCityBuildingLayoutRects[20].bottom = 0x0;
  g_aCityBuildingLayoutRects[21].left = 0x155;
  g_aCityBuildingLayoutRects[21].top = 0xb6;
  g_aCityBuildingLayoutRects[21].right = 0x192;
  g_aCityBuildingLayoutRects[21].bottom = 0xf7;
  g_aCityBuildingLayoutRects[22].left = 0x16f;
  g_aCityBuildingLayoutRects[22].right = 0x1cd;
  g_aCityBuildingLayoutRects[22].bottom = 0x11b;
  g_aCityBuildingLayoutRects[23].left = 0x0;
  g_aCityBuildingLayoutRects[23].top = 0x0;
  g_aCityBuildingLayoutRects[23].right = 0x0;
  g_aCityBuildingLayoutRects[23].bottom = 0x0;
  g_aCityBuildingLayoutRects[24].left = 0x158;
  g_aCityBuildingLayoutRects[24].top = 0xa1;
  g_aCityBuildingLayoutRects[24].right = 0x166;
  g_aCityBuildingLayoutRects[24].bottom = 0xbc;
  g_aCityBuildingLayoutRects[25].left = 0x171;
  g_aCityBuildingLayoutRects[25].top = 0x107;
  g_aCityBuildingLayoutRects[25].right = 0x179;
  g_aCityBuildingLayoutRects[25].bottom = 0x10f;
  g_aCityBuildingLayoutRects[26].left = 0x12e;
  g_aCityBuildingLayoutRects[26].top = 0xef;
  g_aCityBuildingLayoutRects[26].right = 0x13f;
  g_aCityBuildingLayoutRects[26].bottom = 0xfa;
  g_aCityBuildingLayoutRects[27].left = 0x1d8;
  g_aCityBuildingLayoutRects[27].top = 0x11a;
  g_aCityBuildingLayoutRects[27].right = 0x1f3;
  g_aCityBuildingLayoutRects[27].bottom = 0x14e;
  g_aCityBuildingLayoutRects[28].left = 0x1ba;
  g_aCityBuildingLayoutRects[28].top = 0x13d;
  g_aCityBuildingLayoutRects[28].right = 0x1d0;
  g_aCityBuildingLayoutRects[28].bottom = 0x146;
  g_aCityBuildingLayoutRects[29].left = 0x0;
  g_aCityBuildingLayoutRects[29].top = 0x0;
  g_aCityBuildingLayoutRects[29].right = 0x0;
  g_aCityBuildingLayoutRects[29].bottom = 0x0;
  g_aCityBuildingLayoutRects[30].left = 0x1df;
  g_aCityBuildingLayoutRects[30].top = 0x124;
  g_aCityBuildingLayoutRects[30].right = 0x1f2;
  g_aCityBuildingLayoutRects[30].bottom = 0x14e;
  g_aCityBuildingLayoutRects[31].left = 0x1c6;
  g_aCityBuildingLayoutRects[31].top = 0xfa;
  g_aCityBuildingLayoutRects[31].right = 0x1e3;
  g_aCityBuildingLayoutRects[31].bottom = 0x115;
  g_aCityBuildingLayoutRects[32].left = 0x0;
  g_aCityBuildingLayoutRects[32].top = 0x0;
  g_aCityBuildingLayoutRects[32].right = 0x0;
  g_aCityBuildingLayoutRects[32].bottom = 0x0;
  g_aCityBuildingLayoutRects[33].left = 0x1da;
  g_aCityBuildingLayoutRects[33].top = 0xd5;
  g_aCityBuildingLayoutRects[33].right = 0x21a;
  g_aCityBuildingLayoutRects[33].bottom = 0x113;
  g_aCityBuildingLayoutRects[34].left = 0x1bb;
  g_aCityBuildingLayoutRects[34].top = 0x121;
  g_aCityBuildingLayoutRects[34].right = 0x208;
  g_aCityBuildingLayoutRects[34].bottom = 0x14c;
  g_aCityBuildingLayoutRects[35].left = 0x0;
  g_aCityBuildingLayoutRects[35].top = 0x0;
  g_aCityBuildingLayoutRects[35].right = 0x0;
  g_aCityBuildingLayoutRects[35].bottom = 0x0;
  g_aCityBuildingLayoutRects[36].left = 0xb3;
  g_aCityBuildingLayoutRects[36].top = 0x144;
  g_aCityBuildingLayoutRects[36].right = 0xc3;
  g_aCityBuildingLayoutRects[36].bottom = 0x156;
  g_aCityBuildingLayoutRects[37].left = 0xb4;
  g_aCityBuildingLayoutRects[37].top = 0x15e;
  g_aCityBuildingLayoutRects[37].right = 0xd2;
  g_aCityBuildingLayoutRects[37].bottom = 0x173;
  g_aCityBuildingLayoutRects[38].left = 0x0;
  g_aCityBuildingLayoutRects[38].top = 0x0;
  g_aCityBuildingLayoutRects[38].right = 0x0;
  g_aCityBuildingLayoutRects[38].bottom = 0x0;
  g_aCityBuildingLayoutRects[39].left = 0x8d;
  g_aCityBuildingLayoutRects[39].top = 0x124;
  g_aCityBuildingLayoutRects[39].right = 0xa9;
  g_aCityBuildingLayoutRects[39].bottom = 0x141;
  g_aCityBuildingLayoutRects[40].left = 0xc2;
  g_aCityBuildingLayoutRects[40].top = 0x157;
  g_aCityBuildingLayoutRects[40].right = 0xda;
  g_aCityBuildingLayoutRects[40].bottom = 0x169;
  new (&g_aCityBuildingLayoutRects[41]) CRect(121, 325, 160, 338);
  new (&g_aCityBuildingLayoutRects[42]) CRect(185, 345, 224, 381);
  new (&g_aCityBuildingLayoutRects[43]) CRect(94, 326, 146, 368);
  new (&g_aCityBuildingLayoutRects[44]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[45]) CRect(284, 374, 299, 388);
  new (&g_aCityBuildingLayoutRects[46]) CRect(273, 402, 322, 439);
  new (&g_aCityBuildingLayoutRects[47]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[48]) CRect(303, 328, 327, 351);
  new (&g_aCityBuildingLayoutRects[49]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[50]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[51]) CRect(273, 327, 294, 348);
  new (&g_aCityBuildingLayoutRects[52]) CRect(304, 324, 328, 347);
  new (&g_aCityBuildingLayoutRects[53]) CRect(340, 362, 360, 381);
  new (&g_aCityBuildingLayoutRects[54]) CRect(441, 152, 463, 170);
  new (&g_aCityBuildingLayoutRects[55]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[56]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[57]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[58]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[59]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[60]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[61]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[62]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[63]) CRect(464, 130, 488, 153);
  new (&g_aCityBuildingLayoutRects[64]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[65]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[66]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[67]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[68]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[69]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[70]) CRect(0, 0, 0, 0);
  new (&g_aCityBuildingLayoutRects[71]) CRect(0, 0, 0, 0);
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
// FUNCTION: IMPERIALISM 0x00584e80
TToolBarCluster::~TToolBarCluster() {}

// Resolves the turn-event dialog node for message context 0x102c (the "capabilities" dialog),
// computes its placement, and refreshes it. Standalone helper (no `this`) -- matches the

// FUNCTION: IMPERIALISM 0x00584ea0
void TToolBarCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TCluster::DoEvent(commandId, sourceHandler, event);

  bool eligible = g_pApplication->InModalState() == 0;
  if (g_pApplication->screenModeAt24 > 1) {
    eligible = false;
  }
  if (commandId != 10 || !eligible) {
    return;
  }

  unsigned int tag = sourceHandler->controlTag;
  switch (tag) {
  case kControlTagDoneCaps:
    g_pSimMgr->StartNextPhase();
    break;
  case kControlTagFlagCaps:
    DispatchUiRuntimeMessage102CAndRefreshActiveView();
    break;
  case kControlTagRestartCaps:
    ReinitializeGameFlowAndPostTurnEventCode(kTurnEventRebuildRegisteredWindows);
    break;
  case kControlTagScoreCaps:
    g_pAmbitApplication->PostTurnEventCodeMessage2420(EncodeTurnEventCode(kTurnEventGameScore));
    break;
  case kControlTagCity:
    g_pSimMgr->EnterOptionalPhase(0x6a);
    break;
  case kControlTagDipl:
    g_pSimMgr->EnterOptionalPhase(0x68);
    break;
  case kControlTagMmap:
    g_pSimMgr->EnterOptionalPhase(0x6d);
    break;
  case kControlTagTrad:
    g_pSimMgr->EnterOptionalPhase(0x67);
    break;
  case kControlTagTran:
    g_pSimMgr->EnterOptionalPhase(0x69);
    break;
  case kControlTagEnd:
    if (g_pSimMgr->mode != 0x11) {
      g_pSimMgr->StartNextPhase();
      break;
    }
    {
      short nationId = g_pSimMgr->GetActiveNationId();
      short abilityIndex = g_pTechMgr->ConsumeFirstPendingAbilityUnlock(nationId);
      if (abilityIndex != -1) {
        g_pViewMgr->ShowAbilityStatusReport(abilityIndex);
      } else {
        g_pSimMgr->StartNextPhase();
      }
    }
    break;
  case kControlTagQuer:
    if (g_pSimMgr->mode == 4 || g_pSimMgr->mode == 0x12 || g_pSimMgr->mode == 5) {
      g_pViewMgr->DispatchUiRuntimeMessage101AAndRefreshActiveView();
    } else {
      g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
    }
    break;
  case kControlTagDefe:
  case kControlTagMove:
  case kControlTagOpt1:
  case kControlTagOpt2: {
    TView* dialogRoot = ownerContext->ResolveControlByTag(kControlTagDialog);
    dialogRoot->AssertValid();
    dialogRoot->DoEvent(10, sourceHandler, event);
    break;
  }
  }
}

// FUNCTION: IMPERIALISM 0x005851c0
void TToolBarCluster::HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                                          RgnHandle hitArg) {
  if (ResolveControlByTag(kManifestTagCivi) != 0) {
    CString label(g_pSmallViewsEmptyText_00662B90);

    TView* mainControl = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
    if (mainControl == 0) {
      FailNilPointerInUSmallViews(0x406);
    }
    if (mainControl->ResolveControlByTag(kControlTagGOLD) == 0) {
      FailNilPointerInUSmallViews(0x409);
    }

    // Hover bucket over the toolbar's 3x2 civilian-panel grid: rows at y in
    // (0xbe,0x100)/(0x100,0x141)/(0x141,0x183), columns split at x == 0x3f. The
    // bucket only gates the hover-help lookup; the string is the same for all six.
    int y = point->y;
    if (y > 0xbe && y < 0x183) {
      int x = point->x;
      if (x > 0 && x < 0x7e) {
        short bucket = -1;
        if (y < 0x100) {
          bucket = static_cast<short>(x >= 0x3f);
        } else if (y > 0x100 && y < 0x141) {
          bucket = static_cast<short>((x >= 0x3f) + 2);
        } else if (y > 0x141) {
          bucket = static_cast<short>((x >= 0x3f) + 4);
        }
        if (bucket > -1 && bucket < 6) {
          g_pSimMgr->GetString(0x272d, 0xb, &label);
        }
      }
    }

    TView* cursControl = mainControl->ResolveControlByTag(kControlTagCurs);
    if (cursControl == 0) {
      FailNilPointerInUSmallViews(0x448);
    }
    static_cast<TStaticText*>(cursControl)->SetTextAndMaybeRefresh(&label, 1);
  }
  TView::HandleCursorHoverSelectionByChildHitTestAndFallback(point, hitArg);
}

// FUNCTION: IMPERIALISM 0x005853f0
void TToolBarCluster::RefreshTurnOrderStatusPanelTextsAndControls() {
  CString text;

  TView* mainControl = GetWindow()->ResolveControlByTag(kControlTagMain);
  mainControl->AssertValid();
  SetControlHoverHelpText(CString(g_szEmptyString), this);

  TView* control = ResolveControlByTag(kControlTagFlagCaps);
  if (control != 0) {
    g_pSimMgr->GetString(0x2730, 0, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagQuer);
  if (control != 0) {
    g_pSimMgr->GetString(0x2730, 2, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagTrad);
  if (control != 0 && control->IsEnabled()) {
    g_pSimMgr->GetString(0x2730, 0x13, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagCity);
  if (control != 0 && control->IsEnabled()) {
    g_pSimMgr->GetString(0x2730, 0x15, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagTran);
  if (control != 0 && control->IsEnabled()) {
    g_pSimMgr->GetString(0x2730, 0x16, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagDipl);
  if (control != 0 && control->IsEnabled()) {
    g_pSimMgr->GetString(0x2730, 0x14, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagEnd);
  if (control == 0) {
    TView* thirdToolbar = ownerContext->ResolveControlByTag(kControlTagToo3);
    if (thirdToolbar != 0) {
      control = thirdToolbar->ResolveControlByTag(kControlTagEnd);
    }
  }
  if (control != 0) {
    short stringIndex = 7;
    switch (g_pViewMgr->currentTurnEventCode) {
    case kTurnEventDiplomacyMap:
      stringIndex = 0xf;
      break;
    case kTurnEventTradeOverview:
    case kTurnEventIndustryOverview:
      stringIndex = 0x10;
      break;
    case kTurnEventCityProduction:
      stringIndex = 0xe;
      break;
    case kTurnEventStrategicMap:
      stringIndex = 0x11;
      break;
    case kTurnEventTransport:
    case kTurnEventTechnologyStore:
      stringIndex = 0xc;
      break;
    case kTurnEventDealBook:
      stringIndex = 0xd;
      break;
    }
    g_pSimMgr->GetString(0x2730, stringIndex, &text);
    SetControlHoverHelpText(text, control);
  }

  control = ResolveControlByTag(kControlTagTree);
  if (control != 0) {
    g_pSimMgr->GetSeason(&text);
    SetControlHoverHelpText(text, control);
  }

  TDropShadowText* seasonControl =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagSeas));
  if (seasonControl != 0) {
    CString seasonLabel;
    CString yearLabel;
    g_pSimMgr->GetString(0x2730, 0x12, &seasonLabel);
    g_pSimMgr->GetString(0x2730, 8, &yearLabel);
    text = seasonLabel + g_szListSeparator_00695760 + yearLabel;
    SetControlHoverHelpText(text, seasonControl);
    ApplyUiTextStyleAndThemeFlags(seasonControl, 0, 0xc, 0x2b6c, 0x2b67);
    seasonControl->SetTextAlignmentAndMaybeRefresh(-2, 0);
  } else {
    TDropShadowNumberText* yearControl =
        static_cast<TDropShadowNumberText*>(ResolveControlByTag(kControlTagYear));
    if (yearControl != 0) {
      g_pSimMgr->GetString(0x2730, 8, &text);
      SetControlHoverHelpText(text, yearControl);
      ApplyUiNumberTextStyleAndThemeColor(yearControl, 0, 0xe, 0x2b6c, 0x2b67);
      yearControl->SetTextAlignmentAndMaybeRefresh(1, 0);
    }
  }

  TDropShadowText* treasuryControl =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTrea));
  if (treasuryControl != 0) {
    g_pSimMgr->GetString(0x2730, 9, &text);
    SetControlHoverHelpText(text, treasuryControl);
    ApplyUiTextStyleAndThemeFlags(treasuryControl, 0, 0xc, 0x2b6c, 0x2b67);
    treasuryControl->SetTextAlignmentAndMaybeRefresh(1, 0);
  }

  TDropShadowText* wordControl =
      static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagWord));
  if (wordControl != 0) {
    ApplyUiTextStyleAndThemeFlags(wordControl, 0, 0xc, 0x2b6c, 0x2b67);
    wordControl->SetTextAlignmentAndMaybeRefresh(1, 0);
    g_pSimMgr->GetString(0x2730, 9, &text);
    wordControl->SetTextAndMaybeRefresh(&text, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00585ba0
void TToolBarCluster::UpdateControlTagTreaTextFromNationAndMapContext(short nationId) {
  // 'trea' tag: the active nation's treasury balance, only when the slot is eligible
  // for event processing (matches TSimMgr::IsNationSlotEligibleForEventProcessing's
  // major-slot/profile-band gate).
  CString treaText;
  if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(nationId)) {
    g_pSimMgr->NumToCurrency(g_apNationStates[nationId]->treasuryValue10, &treaText);
  }
  TView* treaControl = this->ResolveControlByTag(kControlTagTrea); // 'trea'
  if (treaControl != nullptr) {
    static_cast<TStaticText*>(treaControl)->SetTextAndMaybeRefresh(&treaText, 1);
  }

  // 'seas' tag: "<season>, <year>" turn-status text (present on the main map toolbar).
  TView* seasControl = this->ResolveControlByTag(kControlTagSeas); // 'seas'
  if (seasControl != nullptr) {
    CString seasonText;
    g_pSimMgr->GetSeason(&seasonText);
    int year = 1815 + g_pSimMgr->economicTurn / 4;
    CString yearText;
    yearText.Format("%d", year);
    CString seasText = seasonText + ", " + yearText;
    static_cast<TStaticText*>(seasControl)->SetTextAndMaybeRefresh(&seasText, 1);
    return;
  }

  // 'forc' tag: pending city-action-gate unit cost (present on the tactical/army
  // toolbar variant instead of 'seas'), expanded through the localized "[0]" template.
  TView* forcControl = this->ResolveControlByTag(kControlTagForc); // 'forc'
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
  static_cast<TStaticText*>(forcControl)->SetTextAndMaybeRefresh(&forcText, 1);
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
  // Turn-event dialog roots resolved by message context are TWindow-derived popups (several
  // other ResolveTurnEventDialogNodeByMessageContext callers already cast to TWindow*, e.g.
  // TLanguageMgr.cpp/TViewMgr.cpp) -- confirmed here by arity: TWindow::
  // ExecuteViewModalStateWithPushPopChain() takes zero args, matching this callsite's bare
  // `call [edi+0x1ac]` exactly, whereas the byte-coincident TControl::NoOpUiViewSlotHandler
  // takes two.
  TWindow* node = static_cast<TWindow*>(
      g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventFlagButton));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUViewMgr_0069B6BC, 0xf6c);
  }
  CPoint placement;
  g_pViewMgr->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->Locate(placement, 0);
  node->PoseModally();
  node->Close();
  node->Free();
}
