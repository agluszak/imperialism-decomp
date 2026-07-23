#include "game/city_ui/TIndustryView.h"
#include "game/city_ui/TCityProductionView.h"

#include "game/CSubViewIterator.h"
#include "game/city/TCity.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_widgets/TIndustryCluster.h"
#include "game/city/TItemOrder.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_control_tags.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

static __inline void SetIndustryControlEnabledIfChanged(TView* control, bool enabled) {
  if ((control->IsActionable() != 0) != enabled) {
    control->SetEnabled(enabled, 1);
  }
}
// SYNTHETIC: IMPERIALISM 0x004cc6b0
// TIndustryView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cc770
// TIndustryView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIndustryView, TBuildingView)

// FUNCTION: IMPERIALISM 0x004cc790
TIndustryView::TIndustryView()
    : TBuildingView(), unresolvedZeroA0(0), selectedIndustryUnitTypeA4(static_cast<short>(0xffff)) {
}

// SYNTHETIC: IMPERIALISM 0x004cc7d0
// TIndustryView::`scalar deleting destructor'
TIndustryView::~TIndustryView() {}

// FUNCTION: IMPERIALISM 0x004cc820
void TIndustryView::DoStartup() {
  static const short industryUnitTypesByPage[7] = {8, 13, 11, 15, 9, 14, 12};
  if (embeddedPageIndex9E >= 0 && embeddedPageIndex9E < 7) {
    selectedIndustryUnitTypeA4 = industryUnitTypesByPage[embeddedPageIndex9E];
  }

  TextStyle headingStyle;
  BuildUiTextStyleDescriptor(&headingStyle, 0, 0xc, 0x2b67);

  CString displayText;
  TStaticText* nameText = static_cast<TStaticText*>(ResolveControlByTag(0x6e616d65u)); // 'name'
  if (nameText != 0) {
    g_pSimMgr->GetString(0x2719, embeddedPageIndex9E, &displayText);
    nameText->InstallTextStyle(headingStyle, 0);
    nameText->SetTextAlignmentAndMaybeRefresh(-2, 0);
    nameText->SetTextAndMaybeRefresh(&displayText, 0);
  }

  TStaticText* capacityText = static_cast<TStaticText*>(ResolveControlByTag(0x63617054u)); // 'capT'
  if (capacityText != 0) {
    CString numberText;
    CString templateText;
    numberText.Format(g_szDecimalFormat, city94->GetBuildingType(embeddedPageIndex9E));
    g_pSimMgr->GetString(0x2738, 0x10, &templateText);
    scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(numberText));
    capacityText->InstallTextStyle(headingStyle, 0);
    capacityText->SetTextAlignmentAndMaybeRefresh(-2, 0);
    capacityText->SetTextAndMaybeRefresh(&displayText, 0);
  }

  TStaticText* provinceText = static_cast<TStaticText*>(ResolveControlByTag(0x70726f76u)); // 'prov'
  if (provinceText != 0) {
    CString numberText;
    CString templateText;
    numberText.Format(g_szDecimalFormat, city94->ownerNationAc->ownedRegionList->GetSize());
    g_pSimMgr->GetString(0x2738, 0x1d, &templateText);
    scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(numberText));
    provinceText->InstallTextStyle(headingStyle, 0);
    provinceText->SetTextAlignmentAndMaybeRefresh(-2, 0);
    provinceText->SetTextAndMaybeRefresh(&displayText, 0);
  }

  TStaticText* conjunctionText =
      static_cast<TStaticText*>(ResolveControlByTag(0x6f722020u)); // 'or  '
  if (conjunctionText != 0) {
    g_pSimMgr->GetString(0x2738, 0x11, &displayText);
    conjunctionText->InstallTextStyle(headingStyle, 0);
    conjunctionText->SetTextAlignmentAndMaybeRefresh(1, 0);
    conjunctionText->SetTextAndMaybeRefresh(&displayText, 0);
  }

  SetControlHoverHelpText(CString(g_szEmptyString), this);

  TView* expansionControl = ResolveControlByTag(0x65787061u); // 'expa'
  if (expansionControl != 0) {
    g_pSimMgr->GetString(0x2738, 0x12, &displayText);
    SetControlHoverHelpText(displayText, expansionControl);
  }

  TView* flagControl = ResolveControlByTag(0x666c6167u); // 'flag'
  if (flagControl != 0) {
    if (flagControl->IsActionable() != 0) {
      g_pSimMgr->GetString(0x2738, 0x13, &displayText);
    } else {
      displayText = g_szEmptyString;
    }
    SetControlHoverHelpText(displayText, flagControl);
  }

  TView* equationControl = ResolveControlByTag(0x65717561u); // 'equa'
  if (equationControl != 0) {
    g_pSimMgr->GetString(0x2738, embeddedPageIndex9E, &displayText);
    SetControlHoverHelpText(displayText, equationControl);
  }

  TextStyle valueStyle;
  BuildUiTextStyleDescriptor(&valueStyle, 0, 9, 0x2b69);
  CString mappedValueText(s_mcflavor_00696674);

  TStaticText* valueBalanceText =
      static_cast<TStaticText*>(ResolveControlByTag(0x6c616256u)); // 'Vbal'
  if (valueBalanceText != 0) {
    valueBalanceText->InstallTextStyle(valueStyle, 0);
    valueBalanceText->SetTextAndMaybeRefresh(&mappedValueText, 0);
  }

  CSubViewIterator iterator(this);
  TView* child = iterator.FirstSubView();
  while (iterator.MoreSubViews()) {
    if (child->childList44 == 0) {
      for (short resource = 0; resource < 0x17; ++resource) {
        if (child->controlTag == g_pTradeSummarySelectionMap[resource]) {
          TStaticText* resourceText = static_cast<TStaticText*>(child);
          resourceText->InstallTextStyle(valueStyle, 0);
          resourceText->SetTextAndMaybeRefresh(&mappedValueText, 0);
          break;
        }
      }
    }
    child = iterator.NextSubView();
  }
}

// FUNCTION: IMPERIALISM 0x004ccf30
void TIndustryView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa && sourceHandler->controlTag == kControlTagExpa) {
    TView* owner = GetWindow();
    TWindow* ownerWindow = static_cast<TWindow*>(owner);
    bool wasDisabled = ownerWindow->nativeWindow50->EnableWindow(0) == 0;

    TView* mainControl = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
    if (mainControl == nullptr) {
      FailNilPointerWithAssert("D:\\Ambit\\Cross\\UCityViews.cpp", 0x84c);
    }

    g_pUiRuntimeContext->ShowBuildingExpansionDialog(
        embeddedPageIndex9E, city94, static_cast<TCityProductionView*>(mainControl));

    TView* owner2 = GetWindow();
    static_cast<TWindow*>(owner2)->nativeWindow50->EnableWindow(wasDisabled);
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004cd040
void TIndustryView::UpdateFields() {
  if (city94 == 0) {
    return;
  }

  short primaryResource = -1;
  short secondaryResource = -1;
  bool primaryMissing = false;
  bool secondaryMissing = false;

  if (selectedIndustryUnitTypeA4 > 0) {
    TItemOrder* order = static_cast<TItemOrder*>(city94->orderSlotsE4[selectedIndustryUnitTypeA4]);
    if (order != 0) {
      primaryResource = order->primaryInputResourceId;
      secondaryResource = order->secondaryInputResourceId;
      if (secondaryResource < 0) {
        primaryMissing = city94->CityStockByType(primaryResource) < 2;
      } else {
        primaryMissing = city94->CityStockByType(primaryResource) < 1;
        secondaryMissing = city94->CityStockByType(secondaryResource) < 1;
      }
    }
  } else if (embeddedPageIndex9E == 0xe) {
    primaryResource = 9;    // lumber
    secondaryResource = 11; // steel
    primaryMissing = city94->cityStockLumberC8 < 1;
    secondaryMissing = city94->cityStockSteelCC < 1;
  }

  CSubViewIterator iterator(this);
  TView* child = iterator.FirstSubView();
  while (iterator.MoreSubViews()) {
    for (short resource = 0; resource < 0x17; ++resource) {
      if (child->controlTag == g_pTradeSummarySelectionMap[resource]) {
        if (child->childList44 == 0) {
          bool shouldEnable = (primaryMissing && primaryResource == resource) ||
                              (secondaryMissing && secondaryResource == resource);
          SetIndustryControlEnabledIfChanged(child, shouldEnable);
        } else {
          static_cast<TIndustryCluster*>(child)->UpdateMax();
        }
      }
    }

    if (child->controlTag == 0x666c6167u) { // 'flag'
      TProductionOrder* flagOrder = static_cast<TProductionOrder*>(
          city94->orderSlotsE4[static_cast<short>(embeddedPageIndex9E + 0x35)]);
      SetIndustryControlEnabledIfChanged(child, flagOrder->quantityField04 != 0);
    }

    if (child->controlTag == 0x6c616256u) { // 'Vbal'
      SetIndustryControlEnabledIfChanged(child, city94->productionSummary1d8->strength >= 2);
    }

    child = iterator.NextSubView();
  }

  if (embeddedPageIndex9E == 0xc) {
    TView* grainControl = ResolveControlByTag(0x67726169u); // 'grai'
    grainControl->AssertValid();
    SetIndustryControlEnabledIfChanged(grainControl, city94->cityStockGrainD8 >= 2);

    TView* fruitControl = ResolveControlByTag(0x70726f64u); // 'prod'
    fruitControl->AssertValid();
    SetIndustryControlEnabledIfChanged(fruitControl, city94->cityStockFruitDA >= 1);

    TView* fishControl = ResolveControlByTag(0x66697368u); // 'fish'
    fishControl->AssertValid();
    SetIndustryControlEnabledIfChanged(
        fishControl, static_cast<int>(city94->cityStockFishDC) + city94->cityStockLivestockDE >= 1);
  } else if (embeddedPageIndex9E == 0xf) {
    const unsigned int controlTags[3] = {0x666f6f64u, 0x6675726eu,
                                         0x636c6f74u}; // 'food', 'furn', 'clot'
    const short resourceSlots[3] = {7, 14, 13};
    for (int index = 0; index < 3; ++index) {
      TView* control = ResolveControlByTag(controlTags[index]);
      control->AssertValid();
      SetIndustryControlEnabledIfChanged(control,
                                         city94->CityStockByType(resourceSlots[index]) >= 1);
    }
  }

  TView* flagControl = ResolveControlByTag(0x666c6167u); // 'flag'
  CString hoverHelp;
  if (flagControl != 0) {
    if (flagControl->IsActionable() != 0) {
      g_pSimMgr->GetString(0x2738, 0x13, &hoverHelp);
    } else {
      hoverHelp = g_szEmptyString;
    }
    SetControlHoverHelpTextAltEntry(hoverHelp, flagControl);
  }
}
