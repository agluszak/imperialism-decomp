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
#include "game/map/TZone.h"
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
