#include "game/ui_widgets/TArmyInfoView.h"
#include "game/mfc.h"

#include "game/gfx/ui_invalidation_guard.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/TStaticText.h"
#include "game/core/CString.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TControl.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_map.h"
#include "game/globals/ui_widgets_globals.h"

// SYNTHETIC: IMPERIALISM 0x00591500
// TArmyInfoView::CreateObject
// SYNTHETIC: IMPERIALISM 0x00591580
// TArmyInfoView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyInfoView, TPicture)

// FUNCTION: IMPERIALISM 0x005915a0
TArmyInfoView::TArmyInfoView() : TPicture() {}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x005915d0
// TArmyInfoView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00591600
TArmyInfoView::~TArmyInfoView() {}

// FUNCTION: IMPERIALISM 0x00591620
void TArmyInfoView::StuffValues(short cityRecordIndex, int* categoryCounts) {
  CString reportText;
  CString categoryName;
  CString countText;
  int renderedCategoryCount = 0;
  CString orderTemplate;
  CString cityName;

  TextStyle titleStyle;
  TextStyle bodyStyle;
  TextStyle smallStyle;
  TextStyle smallBoldStyle;
  titleStyle.textColor = 0;
  bodyStyle.textColor = 0;
  smallStyle.textColor = 0;
  smallBoldStyle.textColor = 0;

  InitializeUiTextStyleDescriptor(&titleStyle, 0, 0xe, 0x2b67, 1);
  BuildUiTextStyleDescriptor(&bodyStyle, 0, 0xc, 0x2b67);
  InitializeUiTextStyleDescriptor(&smallStyle, 0, 0xa, 0x2b67, 3);
  InitializeUiTextStyleDescriptor(&smallBoldStyle, 2, 0xa, 0x2b67, 3);

  TStaticText* control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitl));
  if (control == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSmallViews_006992F0, 0x18fd);
  }
  g_pSimMgr->GetString(0x2744, 0xb, &reportText);
  control->SetTextAndMaybeRefresh(&reportText, 1);
  control->InstallTextStyle(titleStyle, 0);

  control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLab2));
  if (control == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSmallViews_006992F0, 0x1902);
  }
  g_pSimMgr->GetString(0x2744, 0xc, &reportText);
  control->SetTextAndMaybeRefresh(&reportText, 1);
  control->InstallTextStyle(bodyStyle, 0);

  control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagLab3));
  if (control == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSmallViews_006992F0, 0x1907);
  }
  g_pSimMgr->GetString(0x2744, 0xd, &reportText);
  control->SetTextAndMaybeRefresh(&reportText, 1);
  control->InstallTextStyle(bodyStyle, 0);

  {
    CString emptyReport(g_pSmallViewsEmptyText_00662B90);
    reportText = emptyReport;
  }
  for (int categoryIndex = 0; categoryIndex < 10; ++categoryIndex) {
    int count = categoryCounts[categoryIndex];
    if (count != 0) {
      countText.Format(g_szDecimalFormat, count);
      g_pSimMgr->GetString(0x2726, static_cast<short>(categoryIndex), &categoryName);
      if (renderedCategoryCount == 0) {
        CString categoryLine = countText + s_szSpaceSeparator_00695794 + categoryName;
        reportText = categoryLine;
      } else {
        reportText +=
            g_szListSeparator_00695760 + countText + s_szSpaceSeparator_00695794 + categoryName;
      }
      ++renderedCategoryCount;
    }
  }

  control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagWhom));
  if (control == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSmallViews_006992F0, 0x191b);
  }
  control->SetTextAndMaybeRefresh(&reportText, 1);
  control->InstallTextStyle(smallStyle, 0);

  control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagGene));
  if (control == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSmallViews_006992F0, 0x1920);
  }
  {
    CString emptyGeneralText(g_pSmallViewsEmptyText_00662B90);
    control->SetTextAndMaybeRefresh(&emptyGeneralText, 1);
  }
  control->InstallTextStyle(smallStyle, 0);

  short cityOwner = g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(cityRecordIndex);
  short activeNation = g_pSimMgr->GetActiveNationId();
  short orderTemplateIndex = static_cast<short>(cityOwner == activeNation ? 0xa : 0xe);
  g_pSimMgr->GetString(0x2744, orderTemplateIndex, &orderTemplate);
  g_pGlobalMapState->AssignCityRecordDisplayName(cityRecordIndex, &cityName);
  scanBracketExpressions(g_pSimMgr, &reportText, static_cast<LPCSTR>(orderTemplate),
                         static_cast<LPCSTR>(cityName));

  control = static_cast<TStaticText*>(ResolveControlByTag(kControlTagOrds));
  if (control == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUSmallViews_006992F0, 0x192c);
  }
  control->SetTextAndMaybeRefresh(&reportText, 1);
  control->InstallTextStyle(smallStyle, 0);
}
