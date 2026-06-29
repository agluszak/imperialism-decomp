#include "game/CMainFrame.h"

#include "game/ImperialismApp.h"
#include "game/TBackdropWindow.h"
#include "game/TModuleLibraryCacheTableStateB.h"

#include <new>

extern undefined4 ResolveBmpResourceHandleWithDefault3B6(void);
extern undefined4 thunk_DispatchHandleMapLookupWithReadPtrProbe(void);
extern undefined4 TMacViewMgr_OnCommand_ID_800C_ShowCityViewSelectionDialog(void);

namespace {

void ReleaseFrameRefTarget(CMainFrameRefTarget* target) {
  if (target != nullptr) {
    target->ReleaseWithFlag(1);
  }
}

void* GetValueAtOffset98(CWnd* wnd) {
  return *reinterpret_cast<void**>(reinterpret_cast<char*>(wnd) + 0x98);
}

int ResolveBmpHandleFromModuleCache(TModuleLibraryCacheTableStateB* cache) {
  typedef int(__fastcall * ResolveBmpProc)(TModuleLibraryCacheTableStateB*);
  ResolveBmpProc resolve = (ResolveBmpProc)(void*)ResolveBmpResourceHandleWithDefault3B6;
  return resolve(cache);
}

undefined4 DispatchHandleMapLookup(undefined4 handle, int flag) {
  typedef undefined4(__cdecl * ProbeProc)(undefined4, int);
  ProbeProc probe = (ProbeProc)(void*)thunk_DispatchHandleMapLookupWithReadPtrProbe;
  return probe(handle, flag);
}

} // namespace

CMainFrameRefTarget::~CMainFrameRefTarget() {}

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
ON_WM_CREATE()
ON_MESSAGE(0x030F, OnMsg030F)
ON_WM_PALETTECHANGED()
ON_COMMAND(100, OnStartupCommand100)
ON_COMMAND(0x8009, OnCommand8009)
ON_COMMAND(0x800C, OnCommand800C)
END_MESSAGE_MAP()

// FUNCTION: IMPERIALISM 0x00413a20
BOOL CMainFrame::PreTranslateMessage(MSG* msg) {
  RefreshBackdropOnInputMessages(msg);
  return CFrameWnd::PreTranslateMessage(msg);
}

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
  field_BC = reinterpret_cast<CMainFrameRefTarget*>(
      ResolveBmpHandleFromModuleCache(g_pModuleLibraryCacheState));
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
  const int paletteChangedMsg = (msg != nullptr && msg->message == 0x311) ? 1 : 0;
  undefined4 priorHandle =
      DispatchHandleMapLookup(reinterpret_cast<undefined4>(field_BC), paletteChangedMsg);
  CClientDC dc(this);
  const UINT realized = dc.RealizePalette();
  DispatchHandleMapLookup(priorHandle, 1);
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
  field_BC = reinterpret_cast<CMainFrameRefTarget*>(
      ResolveBmpHandleFromModuleCache(g_pModuleLibraryCacheState));
  TryRealizeViewPaletteAndInvalidateWindow();
}

void CMainFrame::OnCommand800C() {
  TMacViewMgr_OnCommand_ID_800C_ShowCityViewSelectionDialog();
}

void CMainFrame::OnStartupCommand100() {
  DispatchStartupCommand100ToAppSingleton();
}
