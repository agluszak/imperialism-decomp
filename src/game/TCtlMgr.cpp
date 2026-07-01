#include "game/TCtlMgr.h"

// SYNTHETIC: IMPERIALISM 0x0048eaf0
// TCtlMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCtlMgr, TControl)

TCtlMgr::TCtlMgr() {}

// FUNCTION: IMPERIALISM 0x0048ea00
TCtlMgr* TCtlMgr::CreateTCtlMgrInstance() {
  return new TCtlMgr();
}
