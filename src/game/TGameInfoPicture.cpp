#include "game/TGameInfoPicture.h"

#include "game/CString.h"
#include "game/TArmyMgr.h"
#include "game/TNewsMgr.h"
#include "game/TSimMgr.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x0056b800
// TGameInfoPicture::`scalar deleting destructor'
TGameInfoPicture::~TGameInfoPicture() {}
// SYNTHETIC: IMPERIALISM 0x0056b780
// TGameInfoPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056b850
// TGameInfoPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGameInfoPicture, TPicture)

TGameInfoPicture::TGameInfoPicture() {}

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
  if (tag == 0x6275746e) { // 'butn' — newspaper
    if (g_pInterNationEventQueueManager->perNationStoryLastUsedTick[0] != 0) {
      g_pSimMgr->EnterOptionalPhase(0x66);
    } else {
      g_pUiRuntimeContext->ShowLocalizedUiPromptByGroupAndIndex(0x275e, 6, 2, 0);
    }
    return;
  }
  if (tag == 0x6275746d) { // 'butm' — military/battle report
    short activeNationId = g_pSimMgr->GetActiveNationId();
    if (g_pMapContextActionManager->ScanMapContextActionEntriesForCodeMatch(activeNationId)) {
      g_pSimMgr->EnterOptionalPhase(0x65);
    } else {
      g_pSimMgr->GetString(0x273d, 0x12, &message);
      g_pUiRuntimeContext->ModalMessage(message, g_ptQueryFloaterModalMessage, 1, 0);
    }
    return;
  }
  if (tag == 0x6275746c) { // 'butl' — trade/deals
    if (g_pSimMgr->GetEconomicTurn() == 1) {
      g_pSimMgr->GetString(0x2741, 9, &message);
      g_pUiRuntimeContext->ModalMessage(message, g_ptQueryFloaterModalMessage, 0, 0);
    } else {
      g_pSimMgr->EnterOptionalPhase(0x64);
    }
    return;
  }
  if (tag == 0x6f6b6179) { // 'okay'
    g_pSimMgr->StartNextPhase();
    return;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
