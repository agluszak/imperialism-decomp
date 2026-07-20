#include "game/TTradeSchoolView.h"

#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/TPopulationMgr.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

static __inline void SetTradeSchoolControlEnabledIfChanged(TView* control, bool enabled) {
  if ((control->IsActionable() != 0) != enabled) {
    control->SetEnabled(enabled, 1);
  }
}
// SYNTHETIC: IMPERIALISM 0x004cd760
// TTradeSchoolView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004cd820
// TTradeSchoolView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeSchoolView, TIndustryView)

// FUNCTION: IMPERIALISM 0x004cd840
TTradeSchoolView::TTradeSchoolView() : TIndustryView() {}

// SYNTHETIC: IMPERIALISM 0x004cd880
// TTradeSchoolView::`scalar deleting destructor'
TTradeSchoolView::~TTradeSchoolView() {}

// FUNCTION: IMPERIALISM 0x004cd8d0
void TTradeSchoolView::DoStartup() {
  SetState(0, 0);

  TUiTextStyleDescriptor titleStyle;
  BuildUiTextStyleDescriptor(&titleStyle, 0, 0x18, 0x2b67);

  CString text;
  TStaticText* nameText = static_cast<TStaticText*>(ResolveControlByTag(0x6e616d65u)); // 'name'
  if (nameText != 0) {
    g_pSimMgr->GetString(0x2719, embeddedPageIndex9E, &text);
    nameText->SetTextStyleAndMaybeRefresh(&titleStyle, 0);
    nameText->SetTextAlignmentAndMaybeRefresh(1, 0);
    nameText->SetTextAndMaybeRefresh(&text, 0);
  }

  SetControlHoverHelpText(CString(g_szEmptyString), this);

  const unsigned int equationHelpTags[3] = {0x65717531u, 0x65717532u, 0x65717533u}; // 'equ1'-'equ3'
  for (short equation = 0; equation < 3; ++equation) {
    TView* equationControl = ResolveControlByTag(equationHelpTags[equation]);
    if (equationControl != 0) {
      g_pSimMgr->GetString(0x2738, static_cast<short>(0x18 + equation), &text);
      SetControlHoverHelpText(text, equationControl);
    }
  }

  LoadUiStringByGroupAndIndexToControlObject(0x2738, 0x1f,
                                             ResolveControlByTag(0x65717534u)); // 'equ4'
  LoadUiStringByGroupAndIndexToControlObject(0x2738, 0x20,
                                             ResolveControlByTag(0x65717535u)); // 'equ5'

  TUiTextStyleDescriptor valueStyle;
  BuildUiTextStyleDescriptor(&valueStyle, 0, 9, 0x2b69);
  CString mappedValueText(s_mcflavor_00696674);
  const unsigned int valueTags[6] = {
      0x70617031u, 0x70617032u, 0x6d6f6e31u, // 'pap1', 'pap2', 'mon1'
      0x6d6f6e32u, 0x756e7456u, 0x74726156u  // 'mon2', 'untV', 'traV'
  };
  for (int valueIndex = 0; valueIndex < 6; ++valueIndex) {
    TStaticText* valueText = static_cast<TStaticText*>(ResolveControlByTag(valueTags[valueIndex]));
    if (valueText == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityViews_00696650,
                               static_cast<int>(0x99e + valueIndex * 5));
      continue;
    }
    valueText->SetTextStyleAndMaybeRefresh(&valueStyle, 0);
    valueText->SetTextAndMaybeRefresh(&mappedValueText, 0);
  }

  TUiTextStyleDescriptor costStyle;
  BuildUiTextStyleDescriptor(&costStyle, 0, 0xe, 0x2b67);
  const unsigned int costTags[2] = {0x636f7331u, 0x636f7332u}; // 'cos1', 'cos2'
  const int costs[2] = {100, 1000};
  for (int costIndex = 0; costIndex < 2; ++costIndex) {
    TStaticText* costText = static_cast<TStaticText*>(ResolveControlByTag(costTags[costIndex]));
    if (costText == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityViews_00696650, costIndex == 0 ? 0x9c0 : 0x9c7);
      continue;
    }
    g_pSimMgr->FormatIntegerString(costs[costIndex], &text);
    costText->SetTextStyleAndMaybeRefresh(&costStyle, 0);
    costText->SetTextAndMaybeRefresh(&text, 0);
  }
}

// FUNCTION: IMPERIALISM 0x004ce070
void TTradeSchoolView::UpdateFields() {
  if (city94 == 0) {
    return;
  }

  const unsigned int controlTags[6] = {
      0x70617031u, 0x70617032u, 0x6d6f6e31u, // 'pap1', 'pap2', 'mon1'
      0x6d6f6e32u, 0x756e7456u, 0x74726156u  // 'mon2', 'untV', 'traV'
  };
  const int assertLines[6] = {0x9df, 0x9ef, 0xa00, 0xa11, 0xa23, 0xa34};
  bool shouldEnable[6];
  shouldEnable[0] = city94->cityStockPaperCA >= 1;
  shouldEnable[1] = city94->cityStockPaperCA >= 2;

  int availableBudget = city94->ownerNationAc->ComputeAvailableDiplomacyBudget();
  shouldEnable[2] = availableBudget >= 100;
  shouldEnable[3] = availableBudget >= 1000;

  TPopulationMgr* population = city94->productionSummary1d8;
  short availableWorkers = population->stockLevel1c;
  short professionalLimit = population->productionSlots14->valueAt4;
  if (availableWorkers > professionalLimit) {
    availableWorkers = professionalLimit;
  }
  shouldEnable[4] = availableWorkers != 0;

  short railWorkers = static_cast<short>(population->stockLevel1c / 2);
  short railLimit = population->productionSlots14->valueAt6;
  if (railWorkers > railLimit) {
    railWorkers = railLimit;
  }
  shouldEnable[5] = railWorkers != 0;

  for (int controlIndex = 0; controlIndex < 6; ++controlIndex) {
    TView* control = ResolveControlByTag(controlTags[controlIndex]);
    if (control == 0) {
      FailNilPointerWithAssert(s_SourcePathUCityViews_00696650, assertLines[controlIndex]);
      continue;
    }
    SetTradeSchoolControlEnabledIfChanged(control, shouldEnable[controlIndex]);
  }
}
