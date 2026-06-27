#include "game/TCtlMgr.h"

IMPLEMENT_DYNCREATE(TCtlMgr, TControl)

TCtlMgr::TCtlMgr() {}

// FUNCTION: IMPERIALISM 0x0048ea00
TCtlMgr* TCtlMgr::CreateTCtlMgrInstance() {
  return new TCtlMgr();
}
