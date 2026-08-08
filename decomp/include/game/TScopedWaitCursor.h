#pragma once

#include "game/mfc.h"

// RAII wait-cursor guard over CWinApp::Begin/EndWaitCursor. The original inlines
// both calls at every use site; keeping the ctor/dtor in-class preserves that
// __inline emission. Shared by TAssetMgr and TLoungeDialog (one definition).
struct TScopedWaitCursor {
  TScopedWaitCursor() {
    AfxGetApp()->BeginWaitCursor();
  }
  ~TScopedWaitCursor() {
    AfxGetApp()->EndWaitCursor();
  }
};
