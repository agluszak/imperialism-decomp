#include "game/app/TPageCorner.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"

// FUNCTION: IMPERIALISM 0x00430300
TPageCorner::~TPageCorner() {}

IMPLEMENT_DYNCREATE(TPageCorner, TColorKeyPicture)

// FUNCTION: IMPERIALISM 0x0044a6c0
TPageCorner::TPageCorner() {}

// FUNCTION: IMPERIALISM 0x0056f850
bool TPageCorner::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (controlTag == kControlTagLcor) {
    if (point.x < point.y) {
      return TView::HandleMouseDown(point, event, origin);
    }
  } else if (frameHeight - point.y < point.x) {
    return TView::HandleMouseDown(point, event, origin);
  }
  return false;
}
