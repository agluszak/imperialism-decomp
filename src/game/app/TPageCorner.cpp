#include "game/app/TPageCorner.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"

// SYNTHETIC: IMPERIALISM 0x004302d0
// TPageCorner::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00430300
TPageCorner::~TPageCorner() {}
// SYNTHETIC: IMPERIALISM 0x0056f7b0
// TPageCorner::CreateObject

// SYNTHETIC: IMPERIALISM 0x0056f830
// TPageCorner::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPageCorner, TColorKeyPicture)

// FUNCTION: IMPERIALISM 0x0044a6c0
TPageCorner::TPageCorner() {}

// A page corner is only "hit" on its own triangular half: the left corner takes clicks
// above the diagonal (x < y), any other corner takes clicks below the mirrored diagonal.
// Clicks on the other half fall through as unhandled so the page underneath gets them.
// FUNCTION: IMPERIALISM 0x0056f850
char TPageCorner::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (controlTag == kControlTagLcor) {
    if (point.x < point.y) {
      return TView::HandleMouseDown(point, event, origin);
    }
  } else if (frameHeight38 - point.y < point.x) {
    return TView::HandleMouseDown(point, event, origin);
  }
  return 0;
}
