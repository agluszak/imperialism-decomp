#include "game/app/TModalTemplateDialog.h"

#include "game/gfx/TResourceMgr.h" // g_pResourceMgr
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005e1bc0
TLowDiskWarningDialog::TLowDiskWarningDialog(void* initParam)
    : TModalTemplateDialog(0x98, static_cast<CWnd*>(initParam)), promptText() {
  promptText = g_szEmptyString;
}

// FUNCTION: IMPERIALISM 0x005e1c90
void TLowDiskWarningDialog::DoDataExchange(CDataExchange* pDX) {
  DDX_Text(pDX, 0x3ee, promptText);
}

#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(TLowDiskWarningDialog, CDialog)
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x005e1ce0
BOOL TLowDiskWarningDialog::OnInitDialog() {
  CDialog::OnInitDialog();
  CString caption;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&caption, 0x275c, 1);
  SetWindowText(static_cast<LPCSTR>(caption));
  return TRUE;
}
