#include "game/CMainFrame.h"

#include "game/ImperialismApp.h"

#include <new>

// FUNCTION: IMPERIALISM 0x00484af0
CObject* PASCAL CMainFrame::CreateObject() {
  CMainFrame* pFrame = nullptr;
  try {
    pFrame = new CMainFrame;
  } catch (...) {
    pFrame = nullptr;
  }
  return pFrame;
}

// GLOBAL: IMPERIALISM 0x00648628
IMPLEMENT_RUNTIMECLASS(CMainFrame, CFrameWnd, 0xFFFF, CMainFrame::CreateObject, NULL)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
ON_COMMAND(100, OnStartupCommand100)
END_MESSAGE_MAP()

// FUNCTION: IMPERIALISM 0x00484bf0
CMainFrame::CMainFrame() : CFrameWnd(), field_BC(0), field_C0(0x100005f), field_C4(0), field_CC(1) {}

void CMainFrame::OnStartupCommand100() {
  DispatchStartupCommand100ToAppSingleton();
}
