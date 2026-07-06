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

// Entry order follows the original map at 0x648648. Original entries whose handlers are
// still not ported: ON_COMMAND(0x800D, 0x485590) (forwards through TViewMgr slot 0x19,
// byte 0x64 — needs TViewMgr slots 0x10..0x19 modeled), ON_COMMAND(0x8013, 0x4855b0)
// (terrain-overlay dialog), ON_WM_ERASEBKGND (0x4859d0) (lazy backdrop object + tile
// loop), ON_MESSAGE(0xBC0, 0x485960) (lParam-object dispatch); each needs its own
// class/type recovery before porting.
BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
ON_WM_QUERYNEWPALETTE()
ON_WM_PALETTECHANGED()
ON_WM_CREATE()
ON_COMMAND(0x8009, OnCommand8009)
ON_COMMAND(0x800C, OnCommand800C)
ON_WM_PAINT()
ON_WM_CHAR()
ON_WM_ACTIVATE()
ON_WM_ACTIVATEAPP()
ON_COMMAND(ID_HELP_FINDER, CFrameWnd::OnHelpFinder)
ON_COMMAND(ID_HELP, CFrameWnd::OnHelp)
ON_COMMAND(ID_CONTEXT_HELP, CFrameWnd::OnContextHelp)
ON_COMMAND(ID_DEFAULT_HELP, CFrameWnd::OnHelpFinder)
ON_COMMAND(100, OnStartupCommand100)
ON_MESSAGE(0x464, OnMsg0464)
ON_MESSAGE(0x2420, HandleCustomMessage2420DispatchTurnEvent)
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
  OnQueryNewPalette();
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

// FUNCTION: IMPERIALISM 0x00484fb0
LRESULT CMainFrame::OnMsg0464(WPARAM wParam, LPARAM lParam) {
  (void)wParam;
  (void)lParam;
  g_pImperialismApp->HandleStartupCommand100();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00484fd0
void CMainFrame::OnStartupCommand100() {
  g_pImperialismApp->HandleStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x00484ff0
BOOL CMainFrame::OnQueryNewPalette() {
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
      OnQueryNewPalette();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00485180
void CMainFrame::OnCommand8009() {
  field_BC = g_pModuleLibraryCacheState->EnsureDefaultDibPalette();
  OnQueryNewPalette();
}

void CMainFrame::OnCommand800C() {
  TMacViewMgr_OnCommand_ID_800C_ShowCityViewSelectionDialog();
}

// FUNCTION: IMPERIALISM 0x00485920
LRESULT CMainFrame::HandleCustomMessage2420DispatchTurnEvent(WPARAM wParam, LPARAM lParam) {
  (void)lParam;
  g_pUiRuntimeContext->DispatchTurnEventSlot4C(static_cast<short>(wParam),
                                               g_pSimMgr->GetActiveNationId());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00485990
int CMainFrame::SetFieldC0AndInvalidateWindowIfChanged(int styleValue) {
  int priorValue = field_C0;
  if (priorValue != styleValue) {
    field_C0 = styleValue;
    InvalidateRect(NULL, TRUE);
  }
  return priorValue;
}

// FUNCTION: IMPERIALISM 0x00485bd0
void CMainFrame::OnPaint() {
  CPaintDC dc(this);
}

// FUNCTION: IMPERIALISM 0x00485c00
void CMainFrame::OnChar(UINT nChar, UINT nRepCnt, UINT nFlags) {
  (void)nChar;
  (void)nRepCnt;
  (void)nFlags;
  Default();
}

// FUNCTION: IMPERIALISM 0x00485c60
void CMainFrame::OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized) {
  CFrameWnd::OnActivate(nState, pWndOther, bMinimized);
}

// FUNCTION: IMPERIALISM 0x00485c90
void CMainFrame::OnActivateApp(BOOL bActive, DWORD dwThreadID) {
  (void)dwThreadID;
  Default();
  WINDOWPLACEMENT placement;
  placement.length = sizeof(WINDOWPLACEMENT);
  GetWindowPlacement(&placement);
  if (bActive == 0 && placement.showCmd != SW_SHOWMINIMIZED) {
    placement.showCmd = SW_SHOWMINIMIZED;
    placement.ptMinPosition.y = -1000;
    placement.ptMinPosition.x = -1000;
    placement.flags = 3;
    SetWindowPlacement(&placement);
  }
}
