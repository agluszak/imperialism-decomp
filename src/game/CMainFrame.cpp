#include "game/CMainFrame.h"

#include "game/ImperialismApp.h"
#include "game/TBackdropWindow.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TSimMgr.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

#include <new>

extern undefined4 TMacViewMgr_OnCommand_ID_800C_ShowCityViewSelectionDialog(void);

namespace {

void ReleaseFrameRefTarget(CObject* target) {
  if (target != nullptr) {
    delete target;
  }
}

void* GetValueAtOffset98(CWnd* wnd) {
  return *reinterpret_cast<void**>(reinterpret_cast<char*>(wnd) + 0x98);
}

} // namespace

CMainFrameRefTarget::~CMainFrameRefTarget() {}

// FUNCTION: IMPERIALISM 0x00413a20
BOOL CMainFrame::PreTranslateMessage(MSG* msg) {
  RefreshBackdropOnInputMessages(msg);
  return CFrameWnd::PreTranslateMessage(msg);
}

// MCI notify callback (mode 0x20d == MCI_MODE_STOP): when the intro movie stops, run the
// screen-exit path so the followup turn-event code (main menu, etc.) gets posted. The
// original registers this by address only (no static xrefs; runtime registration site
// still unidentified — see bd imperialism-decomp-1uj.57.4).
// FUNCTION: IMPERIALISM 0x00484230
int __stdcall AdvanceTurnStateWhenMovieMciModeStops(int wParam, int mciMode) {
  (void)wParam;
  if (mciMode == 0x20d) {
    g_pUiRuntimeContext->HandleTurnStateExitAndPostFollowupEventCode(0);
  }
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00484af0
// CMainFrame::CreateObject

// SYNTHETIC: IMPERIALISM 0x00484bb0
// CMainFrame::GetRuntimeClass

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
ON_WM_CREATE()
ON_MESSAGE(0x030F, OnMsg030F)
ON_WM_PALETTECHANGED()
ON_COMMAND(100, OnStartupCommand100)
ON_MESSAGE(0x2420, HandleCustomMessage2420DispatchTurnEvent)
ON_COMMAND(0x8009, OnCommand8009)
ON_COMMAND(0x800C, OnCommand800C)
END_MESSAGE_MAP()

// FUNCTION: IMPERIALISM 0x00484bf0
CMainFrame::CMainFrame()
    : CFrameWnd(), field_BC(0), field_C0(0x100005f), field_C4(0), field_CC(1) {}

// FUNCTION: IMPERIALISM 0x00484c70
CMainFrame::~CMainFrame() {
  ReleaseFrameRefTarget(field_BC);
  ReleaseFrameRefTarget(field_C4);
}

// FUNCTION: IMPERIALISM 0x00484d00
int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct) {
  field_BC = 0;
  if (CFrameWnd::OnCreate(lpCreateStruct) == -1) {
    return -1;
  }
  WrapperFor_AllocateWithFallbackHandler_At0049cc60(this);
  field_BC = g_pModuleLibraryCacheState->EnsureDefaultDibPalette();
  TryRealizeViewPaletteAndInvalidateWindow();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00484d70
void CMainFrame::ConfigureTopLevelWindowStyleAndPlacement(int width, int height) {
  field_CC = 0;
  ModifyStyle(0x00C00000, 0, 0);
  ModifyStyleEx(0x200, 0, 0);
  if (GetValueAtOffset98(this) != nullptr) {
    ModifyStyleEx(0x200, 0, 0);
    ModifyStyleEx(0x300, 0, 0);
  }
  RECT rect;
  rect.left = 0;
  rect.top = 0;
  rect.right = width;
  rect.bottom = height;
  AdjustWindowRectEx(&rect, 0x14CF0000, TRUE, 0x100);
  SetWindowPos(NULL, 0, 0, rect.right - rect.left, rect.bottom - rect.top, 0x16);
  WINDOWPLACEMENT placement;
  placement.length = sizeof(WINDOWPLACEMENT);
  GetWindowPlacement(&placement);
  if (placement.showCmd != SW_SHOWMAXIMIZED) {
    placement.showCmd = SW_SHOWMAXIMIZED;
    placement.ptMinPosition.x = 0;
    placement.ptMinPosition.y = 0;
    SetWindowPlacement(&placement);
  }
}

// FUNCTION: IMPERIALISM 0x00484f70
BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs) {
  cs.hMenu = NULL;
  cs.style = 0x02000000;
  cs.x = (int)0xFFFFFC18;
  return CFrameWnd::PreCreateWindow(cs);
}

// FUNCTION: IMPERIALISM 0x00484ff0
int CMainFrame::TryRealizeViewPaletteAndInvalidateWindow() {
  if (field_BC == 0) {
    return 0;
  }
  const MSG* msg = GetCurrentMessage();
  const BOOL background = (msg != nullptr && msg->message == 0x311) ? TRUE : FALSE;
  CClientDC dc(this);
  CPalette* priorPalette = dc.SelectPalette(field_BC, background);
  const UINT realized = dc.RealizePalette();
  dc.SelectPalette(priorPalette, TRUE);
  if (realized == 0) {
    return 0;
  }
  InvalidateRect(NULL, TRUE);
  return 1;
}

// FUNCTION: IMPERIALISM 0x00485110
void CMainFrame::OnPaletteChanged(CWnd* pFocusWnd) {
  if (pFocusWnd != this) {
    HWND focusHwnd = NULL;
    if (pFocusWnd != NULL) {
      focusHwnd = pFocusWnd->GetSafeHwnd();
    }
    if (!::IsChild(GetSafeHwnd(), focusHwnd)) {
      TryRealizeViewPaletteAndInvalidateWindow();
    }
  }
}

LRESULT CMainFrame::OnMsg030F(WPARAM wParam, LPARAM lParam) {
  (void)wParam;
  (void)lParam;
  TryRealizeViewPaletteAndInvalidateWindow();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00485180
void CMainFrame::OnCommand8009() {
  field_BC = g_pModuleLibraryCacheState->EnsureDefaultDibPalette();
  TryRealizeViewPaletteAndInvalidateWindow();
}

void CMainFrame::OnCommand800C() {
  TMacViewMgr_OnCommand_ID_800C_ShowCityViewSelectionDialog();
}

void CMainFrame::OnStartupCommand100() {
  DispatchStartupCommand100ToAppSingleton();
}

// FUNCTION: IMPERIALISM 0x00485920
LRESULT CMainFrame::HandleCustomMessage2420DispatchTurnEvent(WPARAM wParam, LPARAM lParam) {
  (void)lParam;
  g_pUiRuntimeContext->DispatchTurnEventSlot4C(static_cast<short>(wParam),
                                               g_pSimMgr->GetActiveNationId());
  return 0;
}
