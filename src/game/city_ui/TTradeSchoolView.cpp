#include "game/city_ui/TTradeSchoolView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TPopulationMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/globals/global_types.h"
#include "game/globals/city_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004cd760
// TTradeSchoolView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cd820
// TTradeSchoolView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeSchoolView, TIndustryView)

// FUNCTION: IMPERIALISM 0x004cd840
TTradeSchoolView::TTradeSchoolView() : TIndustryView() {}

// SYNTHETIC: IMPERIALISM 0x004cd880
// TTradeSchoolView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004cd8b0
TTradeSchoolView::~TTradeSchoolView() {}

// FUNCTION: IMPERIALISM 0x004cd8d0
void TTradeSchoolView::DoStartup() {
  SetState(0, 0);

  TextStyle titleStyle;
  BuildUiTextStyleDescriptor(&titleStyle, 0, 0x18, 0x2b67);

  CString text;
  TStaticText* nameText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagName)); // 'name'
  if (nameText != 0) {
    g_pSimMgr->GetString(0x2719, embeddedPageIndex9E, &text);
    nameText->InstallTextStyle(titleStyle, 0);
    nameText->SetTextAlignmentAndMaybeRefresh(1, 0);
    nameText->SetTextAndMaybeRefresh(&text, 0);
  }

  SetControlHoverHelpText(CString(g_szEmptyString), this);

  const unsigned int equationHelpTags[3] = {kControlTagEqu1, kControlTagEqu2,
                                            kControlTagEqu3}; // 'equ1'-'equ3'
  for (short equation = 0; equation < 3; ++equation) {
    TView* equationControl = ResolveControlByTag(equationHelpTags[equation]);
    if (equationControl != 0) {
      g_pSimMgr->GetString(0x2738, static_cast<short>(0x18 + equation), &text);
      SetControlHoverHelpText(text, equationControl);
    }
  }

  LoadUiStringByGroupAndIndexToControlObject(0x2738, 0x1f,
                                             ResolveControlByTag(kControlTagEqu4)); // 'equ4'
  LoadUiStringByGroupAndIndexToControlObject(0x2738, 0x20,
                                             ResolveControlByTag(kControlTagEqu5)); // 'equ5'

  TextStyle valueStyle;
  BuildUiTextStyleDescriptor(&valueStyle, 0, 9, 0x2b69);
  CString mappedValueText(s_mcflavor_00696674);
  const unsigned int valueTags[6] = {
      kControlTagPap1, kControlTagPap2, kControlTagMon1, // 'pap1', 'pap2', 'mon1'
      kControlTagMon2, kControlTagUntV, kControlTagTraV};
  for (int valueIndex = 0; valueIndex < 6; ++valueIndex) {
    TStaticText* valueText = static_cast<TStaticText*>(ResolveControlByTag(valueTags[valueIndex]));
    if (valueText == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityViews_00696650,
                               static_cast<int>(0x99e + valueIndex * 5));
      continue;
    }
    valueText->InstallTextStyle(valueStyle, 0);
    valueText->SetTextAndMaybeRefresh(&mappedValueText, 0);
  }

  TextStyle costStyle;
  BuildUiTextStyleDescriptor(&costStyle, 0, 0xe, 0x2b67);
  const unsigned int costTags[2] = {kControlTagCos1, kControlTagCos2}; // 'cos1', 'cos2'
  const int costs[2] = {100, 1000};
  for (int costIndex = 0; costIndex < 2; ++costIndex) {
    TStaticText* costText = static_cast<TStaticText*>(ResolveControlByTag(costTags[costIndex]));
    if (costText == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityViews_00696650, costIndex == 0 ? 0x9c0 : 0x9c7);
      continue;
    }
    g_pSimMgr->NumToCurrency(costs[costIndex], &text);
    costText->InstallTextStyle(costStyle, 0);
    costText->SetTextAndMaybeRefresh(&text, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004ce070
void TTradeSchoolView::UpdateFields() {
  if (city94 == 0) {
    return;
  }

  TPopulationMgr* population = city94->productionSummary1d8;
#define UPDATE_TRADE_SCHOOL_CONTROL(controlTag, assertLine, enableCondition)                       \
  control = ResolveControlByTag(controlTag);                                                       \
  if (control == 0) {                                                                              \
    FailNilPointerWithAssert(s_SourcePathUCityViews_00696650, assertLine);                         \
  }                                                                                                \
  if (enableCondition) {                                                                           \
    if (control->IsActionable() == 0) {                                                            \
      control->SetEnabled(1, 1);                                                                   \
    }                                                                                              \
  } else {                                                                                         \
    if (control->IsActionable() != 0) {                                                            \
      control->SetEnabled(0, 1);                                                                   \
    }                                                                                              \
  }

  TView* control;
  UPDATE_TRADE_SCHOOL_CONTROL(kControlTagPap1, 0x9df, city94->cityStockPaperCA >= 1);
  UPDATE_TRADE_SCHOOL_CONTROL(kControlTagPap2, 0x9ef, city94->cityStockPaperCA >= 2);
  UPDATE_TRADE_SCHOOL_CONTROL(kControlTagMon1, 0xa00,
                              city94->ownerNationAc->ComputeAvailableDiplomacyBudget() >= 100);
  UPDATE_TRADE_SCHOOL_CONTROL(kControlTagMon2, 0xa11,
                              city94->ownerNationAc->ComputeAvailableDiplomacyBudget() >= 1000);

  short availableWorkers = population->strength;
  short workerLimit = population->productionSlots14->lowSkillCount04;
  if (availableWorkers >= workerLimit) {
    availableWorkers = workerLimit;
  }
  UPDATE_TRADE_SCHOOL_CONTROL(kControlTagUntV, 0xa23, availableWorkers != 0);

  availableWorkers = static_cast<short>(population->strength / 2);
  workerLimit = population->productionSlots14->mediumSkillCount06;
  if (availableWorkers >= workerLimit) {
    availableWorkers = workerLimit;
  }
  UPDATE_TRADE_SCHOOL_CONTROL(kControlTagTraV, 0xa34, availableWorkers != 0);
#undef UPDATE_TRADE_SCHOOL_CONTROL
}
