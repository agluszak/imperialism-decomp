#include "game/TTradeBookView.h"

#include "game/TControl.h"
#include "game/TDropShadowText.h"
#include "game/TEventHandler.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00435690
// TTradeBookView::`scalar deleting destructor'
TTradeBookView::~TTradeBookView() {}
// SYNTHETIC: IMPERIALISM 0x005bde30
// TTradeBookView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bded0
// TTradeBookView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBookView, TView)

TTradeBookView::TTradeBookView() {}

// FUNCTION: IMPERIALISM 0x005bdef0
void TTradeBookView::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

  field60 = static_cast<TControl*>(ResolveControlByTag(kControlTagLcor));
  field64 = static_cast<TControl*>(ResolveControlByTag(kControlTagRcor));
  field68 = static_cast<TControl*>(ResolveControlByTag(kControlTagTbou));
  field6c = static_cast<TControl*>(ResolveControlByTag(kControlTagTsol));

  TStaticText* rtilControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagRtil));
  rtilControl->AssertValid();
  TStaticText* titLControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitL));
  titLControl->AssertValid();

  ApplyUiTextStyleAndThemeFlags(static_cast<TDropShadowText*>(rtilControl), 0, 0x12, 0x2b6b, 0x2b6c);
  ApplyUiTextStyleAndThemeFlags(static_cast<TDropShadowText*>(titLControl), 0, 0x12, 0x2b6b, 0x2b6c);

  CString quarterText;
  CString formattedText;
  short quarterValue = static_cast<short>(g_pSimMgr->quarterGateTick2c / 4 + 0x717);
  formattedText.Format(g_szDecimalFormat, quarterValue);
  g_pSimMgr->FormatSeasonName(&quarterText);

  CString combined;
  combined = quarterText + s_szSpaceSeparator_00695794 + formattedText;
  rtilControl->AssignTextSharedRefIfChangedAndMaybeInvalidate(&combined, 0);
  rtilControl->SetEnabled(1, 1);
}

// FUNCTION: IMPERIALISM 0x005be370
void TTradeBookView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    if (sourceHandler->controlTag == kControlTagRcor) {
      UpdatePagerButtonStatesAndRefreshPanels(field74 + 1);
    } else if (sourceHandler->controlTag == kControlTagLcor) {
      UpdatePagerButtonStatesAndRefreshPanels(field74 - 1);
    }
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005be3e0
void TTradeBookView::UpdatePagerButtonStatesAndRefreshPanels(int page) {
  field60->SetState(page != 1, 0);
  field60->SetEnabled(page != 1, 1);
  bool hasMore = page + 2 <= field70;
  field64->SetState(hasMore, 0);
  field64->SetEnabled(hasMore, 1);
  field68->ReturnZeroFromUiSlot6C(page);
  field6c->ReturnZeroFromUiSlot6C(page);
}
