#include "game/CIncludeView.h"

#include "game/TView.h"

IMPLEMENT_DYNCREATE(CIncludeView, CView)

CIncludeView::CIncludeView() : CView() {}

void CIncludeView::OnDraw(CDC* pDC) {
  (void)pDC;
}

// Install this view as the native host window for the given TView (and its whole
// subtree), then let it resolve the 'main' control tag against itself.
// FUNCTION: IMPERIALISM 0x00483340
void CIncludeView::SetUiRuntimeContextAndActivateMain(TView* activeDialog) {
  m_activeDialogContext = activeDialog;
  activeDialog->PropagateUiResourceContextRecursive(this);
  activeDialog->ResolveControlByTag(0x6d61696e);
}
