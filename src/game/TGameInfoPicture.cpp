#include "game/TGameInfoPicture.h"

#include "game/CString.h"
#include "game/TSimMgr.h"
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
void TGameInfoPicture::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);

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
void TGameInfoPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) { }
