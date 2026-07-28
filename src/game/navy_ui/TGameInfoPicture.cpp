#include "game/navy_ui/TGameInfoPicture.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/ui_screens/CString.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x0056b800
// TGameInfoPicture::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0056b830
TGameInfoPicture::~TGameInfoPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056b780
// TGameInfoPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056b850
// TGameInfoPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameInfoPicture, TPicture)

// FUNCTION: IMPERIALISM 0x0056b870
void TGameInfoPicture::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  CString text;
  for (int i = 0; i < 5; ++i) {
    g_pSimMgr->GetString(0x2757, static_cast<short>(i + 0xf), &text);
    RefreshActiveControlThenApplyThemeStyleAndCaption(kControlTagHdr0 + i, 0, 0xc, 0x2b67, 1, text);
  }

  for (int j = 0; j < 0xe; ++j) {
    TView* control = ResolveControlByTag(kControlTagTxta + j);
    control->AssertValid();
    g_pSimMgr->GetString(0x2757, static_cast<short>(j), &text);
    RefreshActiveControlThenApplyThemeStyleAndCaption(kControlTagTxta + j, 0, 0xa, 0x2b67, 1, text);
  }
}

// FUNCTION: IMPERIALISM 0x0056b9b0
void TGameInfoPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  CString message;
  if (commandId != 0xa) {
    TControl::DoEvent(commandId, sourceHandler, event);
    return;
  }

  unsigned int tag = sourceHandler->controlTag;
  if (tag == kControlTagButn) { // 'butn' — newspaper
    if (g_pNewsMgr->perNationStoryLastUsedTick[0] != 0) {
      g_pSimMgr->EnterOptionalPhase(0x66);
    } else {
      g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x275e, 6, 2, 0);
    }
    return;
  }
  if (tag == kControlTagButm) { // 'butm' — military/battle report
    short activeNationId = g_pSimMgr->GetActiveNationId();
    if (g_pMapContextActionManager->ScanMapContextActionEntriesForCodeMatch(activeNationId)) {
      g_pSimMgr->EnterOptionalPhase(0x65);
    } else {
      g_pSimMgr->GetString(0x273d, 0x12, &message);
      g_pUiRuntimeContext->ModalMessage(message, g_ptQueryFloaterModalMessage, 1, 0);
    }
    return;
  }
  if (tag == kControlTagButl) { // 'butl' — trade/deals
    if (g_pSimMgr->GetEconomicTurn() == 1) {
      g_pSimMgr->GetString(0x2741, 9, &message);
      g_pUiRuntimeContext->ModalMessage(message, g_ptQueryFloaterModalMessage, 0, 0);
    } else {
      g_pSimMgr->EnterOptionalPhase(0x64);
    }
    return;
  }
  if (tag == kControlTagOkay) { // 'okay'
    g_pSimMgr->StartNextPhase();
    return;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
