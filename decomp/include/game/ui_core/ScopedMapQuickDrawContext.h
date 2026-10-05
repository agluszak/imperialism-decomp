#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_core/TView.h"

struct ScopedMapQuickDrawContext {
  CClientDC clientDc;
  TView* renderTarget;

  explicit ScopedMapQuickDrawContext(TView* renderTarget);
  ScopedMapQuickDrawContext(TView* renderTarget, RECT* clipRect);
  ~ScopedMapQuickDrawContext();
};

ASSERT_SIZE(ScopedMapQuickDrawContext, 0x18);
int BindScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc);
void ReleaseScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc);

class CDib;

CDC* GetActiveQuickDrawDc();
CDib* GetActiveQuickDrawSurfaceDib();
