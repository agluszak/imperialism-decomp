#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TView.h"

struct ScopedMapQuickDrawContext {
  CClientDC clientDc;
  TView* renderTarget;

  explicit ScopedMapQuickDrawContext(TView* renderTarget);
  ~ScopedMapQuickDrawContext();

  int* IntersectClipRectOnPrimaryAndSecondaryDc(int* clipRect);
};

ASSERT_SIZE(ScopedMapQuickDrawContext, 0x18);

typedef ScopedMapQuickDrawContext ScopedMapQuickDrawContextGuard;

// existingDc: the caller-supplied CDC to bind (e.g. CMcWindow::OnPaint's CPaintDC), or
// null to bind a fresh CDC wrapping the view window's DC.
int BindScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc);
void ReleaseScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc);
