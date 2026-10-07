#include "game/nation_domain_types.h"
#include "game/menu_commands.h"
#include "game/ui_core/CMainFrame.h"

#include "game/pointer_representation.h"
#include "game/ui_core/TCommand.h"
#include "game/ui_core/CIncludeView.h" // GetMainViewHostFromActiveThread()->m_hWnd
#include "game/turn_event_codes.h"
#include "game/ImperialismApp.h"
#include "game/gfx/TBackdropWindow.h"
#include "game/gfx/TResourceMgr.h"
#include "game/gfx/TTemplateDialogs.h"
#include "game/city_ui/TCountry.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include <new>

// The MCI stop-notify handler (0x00484230) is CIncludeView's MCIWNDM_NOTIFYMODE (msg 0x4c8)
// message-map entry — see CIncludeView::OnMciNotifyMode.

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

#ifndef IMPERIALISM_LINT
BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
ON_WM_QUERYNEWPALETTE()
ON_WM_PALETTECHANGED()
ON_WM_CREATE()
ON_COMMAND(kCmdResetPalette, OnResetPalette)
ON_COMMAND(kCmdWarpToScreen, OnWarpToScreen)
ON_COMMAND(kCmdShowDealBook, OnShowDealBook)
ON_COMMAND(kCmdConductDiplomacy, OnConductDiplomacy)
ON_WM_PAINT()
ON_WM_CHAR()
ON_WM_ACTIVATE()
ON_WM_ACTIVATEAPP()
ON_WM_ERASEBKGND()
ON_COMMAND(ID_HELP_FINDER, CFrameWnd::OnHelpFinder)
ON_COMMAND(ID_HELP, CFrameWnd::OnHelp)
ON_COMMAND(ID_CONTEXT_HELP, CFrameWnd::OnContextHelp)
ON_COMMAND(ID_DEFAULT_HELP, CFrameWnd::OnHelpFinder)
ON_COMMAND(100, OnStartupCommand100)
ON_MESSAGE(0x464, OnMsg0464)
ON_MESSAGE(0xBC0, OnMsg0BC0)
ON_MESSAGE(0x2420, OnTurnEventCodeMessage)
END_MESSAGE_MAP()
#endif

// FUNCTION: IMPERIALISM 0x00484bf0
CMainFrame::CMainFrame() : CFrameWnd(), m_pDibPalette(0), m_pBackdropDib(0), field_CC(1) {
  m_backgroundColor = kTiledBackdropSentinelColor;
}

// FUNCTION: IMPERIALISM 0x00484c70
CMainFrame::~CMainFrame() {
  if (m_pDibPalette != 0) {
    delete m_pDibPalette;
  }
  if (m_pBackdropDib != 0) {
    delete m_pBackdropDib;
  }
}

// FUNCTION: IMPERIALISM 0x00484d00
int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct) {
  m_pDibPalette = 0;
  if (CFrameWnd::OnCreate(lpCreateStruct) == -1) {
    return -1;
  }
  CreateBackdropWindowIfSplashEnabled(this);
  m_pDibPalette = g_pResourceMgr->EnsureDefaultDibPalette();
  OnQueryNewPalette();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00484d70
void CMainFrame::ConfigureTopLevelWindowStyleAndPlacement(int width, int height) {
  field_CC = 0;
  ModifyStyle(0x00C00000, 0, 0);
  ModifyStyleEx(0x200, 0, 0);
  if (GetActiveView() != NULL) {
    GetActiveView()->ModifyStyleEx(0x200, 0, 0);
    GetActiveView()->ModifyStyleEx(0x300, 0, 0);
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
  g_pImperialismApp->HandleStartupCommand100();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00484fd0
void CMainFrame::OnStartupCommand100() {
  g_pImperialismApp->HandleStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x00484ff0
BOOL CMainFrame::OnQueryNewPalette() {
  if (m_pDibPalette == 0) {
    return 0;
  }
  const MSG* msg = GetCurrentMessage();
  const BOOL background = (msg != NULL && msg->message == 0x311) ? TRUE : FALSE;
  CClientDC dc(this);
  CPalette* priorPalette = dc.SelectPalette(m_pDibPalette, background);
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

// FUNCTION: IMPERIALISM 0x00485150
CDibPal* CMainFrame::ReplacePaletteAndRealize(CDibPal* palette) {
  CDibPal* previousPalette = m_pDibPalette;
  m_pDibPalette = palette;
  OnQueryNewPalette();
  return previousPalette;
}

// FUNCTION: IMPERIALISM 0x00485180
void CMainFrame::OnResetPalette() {
  m_pDibPalette = g_pResourceMgr->EnsureDefaultDibPalette();
  OnQueryNewPalette();
}

// FUNCTION: IMPERIALISM 0x004851b0
void CMainFrame::OnWarpToScreen() {
  TWarpToScreenDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();

  dialog.slider.SetRange(0, 6, FALSE);
  HWND hSlider = dialog.slider.m_hWnd;
  HWND hList = dialog.listbox.m_hWnd;

  ::SendMessageA(hSlider, TBM_SETPOS, 1, g_pViewMgr->currentTurnEventNationSlot);

  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694e18);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694e08);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694df8);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694de8);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694dd4);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694dbc);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694da4);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694d94);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694d80);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694d68);

  ::SendMessageA(hList, LB_SETITEMDATA, 0, kTurnEventCitySiteSelector);
  ::SendMessageA(hList, LB_SETITEMDATA, 1, kTurnEventCitySiteSelector);
  ::SendMessageA(hList, LB_SETITEMDATA, 2, kTurnEventDiplomacyMap);
  ::SendMessageA(hList, LB_SETITEMDATA, 3, kTurnEventOfferSheet);
  ::SendMessageA(hList, LB_SETITEMDATA, 4, kTurnEventTradeOverview);
  ::SendMessageA(hList, LB_SETITEMDATA, 5, kTurnEventDiplomacyMap);
  ::SendMessageA(hList, LB_SETITEMDATA, 6, kTurnEventCityProduction);
  ::SendMessageA(hList, LB_SETITEMDATA, 7, kTurnEventDealBook);
  ::SendMessageA(hList, LB_SETITEMDATA, 8, kTurnEventStrategicMap);
  ::SendMessageA(hList, LB_SETITEMDATA, 9, kTurnEventTransport);

  ::SendMessageA(hList, LB_SETCURSEL, 4, 0);

  if (dialog.DoModal() == 1) {
    LRESULT sliderPos = ::SendMessageA(hSlider, TBM_GETPOS, 0, 0);
    WPARAM selectedRow = ::SendMessageA(hList, LB_GETCURSEL, 0, 0);
    LRESULT eventCode = ::SendMessageA(hList, LB_GETITEMDATA, selectedRow, 0);
    g_pViewMgr->DispatchTurnEvent(static_cast<short>(eventCode), static_cast<int>(sliderPos));
  }
}

// FUNCTION: IMPERIALISM 0x00485590
void CMainFrame::OnShowDealBook() {
  g_pViewMgr->ShowDealBookScreen(0);
}

// FUNCTION: IMPERIALISM 0x004855b0
void CMainFrame::OnConductDiplomacy() {
  while (true) {
    TConductDiplomacyDialog dialog(0);
    dialog.PrepareAndCreateModalFromTemplate();

    int nationIndex = 0;
    TCountry** country;
    for (country = g_apTerrainTypeDescriptorTable;
         country < &g_apTerrainTypeDescriptorTable[kMajorNationCount]; ++country) {
      CString label;
      CString name;
      (*country)->FormatOverlayTerrainLabelText(&name);
      label.Format("Great Power %2d, %s", nationIndex, static_cast<const char*>(name));
      dialog.listbox.AddString(label);
      dialog.listbox.SetItemData(nationIndex, nationIndex);
      ++nationIndex;
    }
    if (nationIndex < kNationSlotCount) {
      for (country = &g_apTerrainTypeDescriptorTable[nationIndex];
           country < &g_apTerrainTypeDescriptorTable[kNationSlotCount]; ++country) {
        CString label;
        CString name;
        (*country)->FormatOverlayTerrainLabelText(&name);
        label.Format("Minor Nation %2d, %s", nationIndex, static_cast<const char*>(name));
        dialog.listbox.AddString(label);
        dialog.listbox.SetItemData(nationIndex, nationIndex);
        ++nationIndex;
      }
    }

    dialog.listbox.SetSel(0, g_pSimMgr->GetPlayerCountry());
    dialog.listbox.SetCurSel(0);
    if (dialog.DoModal() != 1) {
      break;
    }
  }
  g_pImperialismApp->PostStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x00485920
LRESULT CMainFrame::OnTurnEventCodeMessage(WPARAM wParam, LPARAM lParam) {
  g_pViewMgr->DispatchTurnEvent(static_cast<short>(wParam), g_pSimMgr->GetPlayerCountry());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00485960
LRESULT CMainFrame::OnMsg0BC0(WPARAM wParam, LPARAM lParam) {
  TCommand* command = static_cast<TCommand*>(PointerFromAddressLong32(lParam));
  command->AssertValid();
  command->Process();
  return 0;
}

// FUNCTION: IMPERIALISM 0x00485990
COLORREF CMainFrame::SetBackgroundColorAndInvalidate(COLORREF color) {
  COLORREF priorValue = m_backgroundColor;
  if (priorValue != color) {
    m_backgroundColor = color;
    InvalidateRect(NULL, TRUE);
  }
  return priorValue;
}

// FUNCTION: IMPERIALISM 0x004859d0
BOOL CMainFrame::OnEraseBkgnd(CDC* pDC) {
  if (m_backgroundColor != kTiledBackdropSentinelColor) {
    g_pResourceMgr->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(pDC, FALSE);
    RECT solidRect;
    GetClientRect(&solidRect);
    pDC->FillSolidRect(&solidRect, m_backgroundColor);
    return TRUE;
  }
  if (m_pBackdropDib == 0) {
    m_pBackdropDib = new CDib();
    m_pBackdropDib->LoadBitmapResourceAndInitializeSurfaceState(MAKEINTRESOURCE(0x119), 0);
  }
  RECT clientRect;
  GetClientRect(&clientRect);
  int tileRows = (clientRect.bottom - clientRect.top) / 128;
  int tileCols = (clientRect.right - clientRect.left) / 128;
  m_pBackdropDib->SelectAndRealizeDibPalette(pDC, FALSE);
  POINT tile;
  tile.x = 0;
  tile.y = 0;
  for (int row = 0; row <= tileRows; ++row) {
    tile.x = 0;
    for (int col = 0; col <= tileCols; ++col) {
      m_pBackdropDib->StretchDibitsFromStoredBitmapToHdc(pDC, &tile);
      tile.x += 128;
    }
    tile.y += 128;
  }
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x00485bd0
void CMainFrame::OnPaint() {
  CPaintDC dc(this);
}

// FUNCTION: IMPERIALISM 0x00485c00
void CMainFrame::OnChar(UINT nChar, UINT nRepCnt, UINT nFlags) {
  Default();
}

// FUNCTION: IMPERIALISM 0x00485c20
void CMainFrame::WinHelp(DWORD dwData, UINT nCmd) {
  if (GetMainViewHostFromActiveThread() != NULL) {
    ::SendMessage(GetMainViewHostFromActiveThread()->m_hWnd, WM_KEYDOWN, VK_F1, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00485c60
void CMainFrame::OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized) {
  CFrameWnd::OnActivate(nState, pWndOther, bMinimized);
}

// FUNCTION: IMPERIALISM 0x00485c90
void CMainFrame::OnActivateApp(BOOL bActive, DWORD dwThreadID) {
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
