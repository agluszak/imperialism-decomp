#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/TView.h"

struct ScopedMapQuickDrawContext {
  CClientDC clientDc;
  TView* renderTarget;

  explicit ScopedMapQuickDrawContext(TView* renderTarget);
  ScopedMapQuickDrawContext(TView* renderTarget, RECT* clipRect);
  ~ScopedMapQuickDrawContext();

  int* IntersectClipRectOnPrimaryAndSecondaryDc(int* clipRect);
};

ASSERT_SIZE(ScopedMapQuickDrawContext, 0x18);

typedef ScopedMapQuickDrawContext ScopedMapQuickDrawContextGuard;

// existingDc: the caller-supplied CDC to bind (e.g. CMcWindow::OnPaint's CPaintDC), or
// null to bind a fresh CDC wrapping the view window's DC.
int BindScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc);
void ReleaseScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc);

class CDib;

// The CDC render code should draw through right now: the QuickDraw memory DC when one
// is bound, else the scoped map DC-handle object. 0x00494660
CDC* GetActiveQuickDrawDc();
// Backing CDib of the active QuickDraw surface context, or null when the context head
// still points at the static sentinel (no surface pushed yet). 0x00494680
CDib* GetActiveQuickDrawSurfaceDib();
