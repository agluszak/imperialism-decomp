#include "game/gfx/TAutoResolutionDialog.h"

#include "game/gfx/TResourceMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include <stddef.h>

namespace {

ASSERT_SIZE(TModalDialogBase, 0x74);
ASSERT_OFFSET(TAutoResolutionDialog, primaryDialogControl, 0x74);
ASSERT_OFFSET(TAutoResolutionDialog, secondaryDialogControl, 0xb0);
ASSERT_OFFSET(TAutoResolutionDialog, autoResolutionCheckState, 0xec);
ASSERT_SIZE(TAutoResolutionDialog, 0xf0);
ASSERT_SIZE(CDialog, 0x5c);
ASSERT_SIZE(CWnd, 0x3c);

} // namespace

// FUNCTION: IMPERIALISM 0x004152e0
TAutoResolutionDialog::~TAutoResolutionDialog() {}

// FUNCTION: IMPERIALISM 0x0047dfd0
TAutoResolutionDialog::TAutoResolutionDialog(void* initParam)
    : TModalDialogBase(0xfb, static_cast<CWnd*>(initParam)), autoResolutionCheckState(0) {}

// FUNCTION: IMPERIALISM 0x0047e0c0
void TAutoResolutionDialog::DoDataExchange(CDataExchange* pDX) {
  DDX_Control(pDX, 0x434, primaryDialogControl);
  DDX_Check(pDX, 0x434, autoResolutionCheckState);
}

#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(TAutoResolutionDialog, CDialog)
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x0047e120
BOOL TAutoResolutionDialog::OnInitDialog() {
  CDialog::OnInitDialog();
  CString text;
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&text, 0x2763, 0x11);
  primaryDialogControl.SetWindowText(static_cast<LPCSTR>(text));
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&text, 0x2763, 0x13);
  SetWindowText(static_cast<LPCSTR>(text));
  UpdateData(FALSE);
  return TRUE;
}
