#include "game/ui_screens/TPictureRadioButton.h"

#include "game/gfx/CDib.h"
#include "game/ui_core/TCluster.h"
#include "game/ui_screens/TUberCluster.h"

IMPLEMENT_DYNCREATE(TPictureRadioButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00570d60
TPictureRadioButton::TPictureRadioButton() {}

// FUNCTION: IMPERIALISM 0x00570dc0
TPictureRadioButton::~TPictureRadioButton() {}

// FUNCTION: IMPERIALISM 0x00570de0
void TPictureRadioButton::ViewEnable(char isEnabled, char refreshNow) {
  short pictureId = glyphBase;
  short alternatePictureId = static_cast<short>(controlValue);
  char currentState = IsEnabled();
  if (((isEnabled != 0 && currentState == 0) || (isEnabled == 0 && currentState != 0)) &&
      alternatePictureId != 0) {
    SetPictureRsrcID(alternatePictureId, false);
    controlValue = pictureId;
    DefaultSize(true);
    viewEnabled = isEnabled;
    Show(!isEnabled, refreshNow);
  }
  TView::ViewEnable(isEnabled, refreshNow);
}

// FUNCTION: IMPERIALISM 0x00570ea0
void TPictureRadioButton::DefaultSize(bool refreshNow) {
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
    Show(isPressed, notifyParent);
    if (isPressed) {
      static_cast<TCluster*>(ownerContext)->SetSelectedChildTagAndRefresh(controlTag);
    }
    PrepareForDrawing();
    PaintOrInvalidateControl(0);
  }
}

// FUNCTION: IMPERIALISM 0x00570fb0
char TPictureRadioButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                                          CPoint origin) {
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
