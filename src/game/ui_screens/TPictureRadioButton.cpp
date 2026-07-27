#include "game/ui_screens/TPictureRadioButton.h"

#include "game/gfx/CDib.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_screens/TUberCluster.h"
// SYNTHETIC: IMPERIALISM 0x00570cc0
// TPictureRadioButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00570d40
// TPictureRadioButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureRadioButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00570d60
TPictureRadioButton::TPictureRadioButton() {}

// SYNTHETIC: IMPERIALISM 0x00570d90
// TPictureRadioButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00570dc0
TPictureRadioButton::~TPictureRadioButton() {}

// FUNCTION: IMPERIALISM 0x00570de0
void TPictureRadioButton::ViewEnable(char isEnabled, char refreshNow) {
  short pictureId = glyphBase84;
  short alternatePictureId = static_cast<short>(controlValue3c);
  char currentState = IsEnabled();
  if (((isEnabled != 0 && currentState == 0) || (isEnabled == 0 && currentState != 0)) &&
      alternatePictureId != 0) {
    SetPictureResourceIdAndRefresh(alternatePictureId, false);
    controlValue3c = pictureId;
    DefaultSize(true);
    viewEnabled = isEnabled;
    SetEnabled(!isEnabled, refreshNow);
  }
  TView::SetState(isEnabled, refreshNow);
}

// FUNCTION: IMPERIALISM 0x00570ea0
void TPictureRadioButton::DefaultSize(bool refreshNow) {
  (void)refreshNow;
  CPoint bitmapSize;
  CPoint* dimensions = cachedBitmap->CopyBitmapDimensionsToPoint(&bitmapSize);
  CPoint bottomRight;
  bottomRight.x = ownerLocalX + dimensions->x;
  bottomRight.y = ownerLocalY + dimensions->y;
  CRect bounds;
  QueryBounds(&bounds);
  bounds.right = bounds.left + bottomRight.x - ownerLocalX;
  bounds.bottom = bounds.top + bottomRight.y - ownerLocalY;
  ApplyBounds(&bounds, true);
}

// FUNCTION: IMPERIALISM 0x00570f40
void TPictureRadioButton::Select(bool isPressed, bool notifyParent) {
  if (IsEnabled()) {
    SetEnabled(isPressed, notifyParent);
    if (isPressed) {
      static_cast<TCluster*>(ownerContext)->SetSelectedChildTagAndRefresh(controlTag);
    }
    PrepareForDrawing();
    PaintOrInvalidateControl(0);
  }
}

// A radio button ignores the press unless it is currently deselected and enabled; the
// press position never matters. The original re-reads IsSelected() after the enable check
// instead of reusing the first result (two separate virtual calls in the listing), and
// keeps the toggle-on / toggle-off notifications as two distinct HandleEvent callsites.
// The owner is the hosting TUberCluster, whose slot 0x73 reports whether any sibling in
// the group is currently selected: with nothing selected anywhere the press is swallowed.
// FUNCTION: IMPERIALISM 0x00570fb0
char TPictureRadioButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                                          CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;
  if (IsSelected()) {
    return 0;
  }
  if (IsEnabled() == 0) {
    return 0;
  }
  bool wasSelected = IsSelected();
  if (!wasSelected && static_cast<TUberCluster*>(ownerContext)->IsTradeControlAtMinimum() == 0) {
    return 1;
  }
  Select(!wasSelected, true);
  if (wasSelected) {
    ownerContext->HandleEvent(0x67, this, 0);
  } else {
    ownerContext->HandleEvent(0x68, this, 0);
  }
  return 1;
}
