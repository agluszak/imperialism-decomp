#include "game/TPictureRadioButton.h"

#include "game/CDib.h"
#include "game/TCluster.h"
// SYNTHETIC: IMPERIALISM 0x00570cc0
// TPictureRadioButton::CreateObject

// SYNTHETIC: IMPERIALISM 0x00570d40
// TPictureRadioButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureRadioButton, TToggleButton)

// FUNCTION: IMPERIALISM 0x00570d60
TPictureRadioButton::TPictureRadioButton() {}

// SYNTHETIC: IMPERIALISM 0x00570d90
// TPictureRadioButton::`scalar deleting destructor'
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
    field08 = isEnabled;
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

// FUNCTION: IMPERIALISM 0x00570fb0
char TPictureRadioButton::HandleMouseDown(const CPoint& point, TToolboxEvent* event,
                                          CPoint origin) {
  (void)point;
  (void)event;
  (void)origin;
  return 0;
}
