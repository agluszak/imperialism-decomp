#include "game/TIconSlider.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/quickdraw_regions.h"
// SYNTHETIC: IMPERIALISM 0x005062d0
// TIconSlider::CreateObject

// SYNTHETIC: IMPERIALISM 0x005063a0
// TIconSlider::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIconSlider, TIconBar)

// FUNCTION: IMPERIALISM 0x005063c0
TIconSlider::TIconSlider()
    : TIconBar(), value9c(0), knobBitmapA0(0), minTrackOffsetB4(0), maxTrackOffsetB6(0) {
  knobBaseRectA4.left = 0;
  knobBaseRectA4.top = 0;
  knobBaseRectA4.right = 0;
  knobBaseRectA4.bottom = 0;
}

// SYNTHETIC: IMPERIALISM 0x00506430
// TIconSlider::`scalar deleting destructor'
TIconSlider::~TIconSlider() {}

// FUNCTION: IMPERIALISM 0x00506480
void TIconSlider::DoPostCreate(int arg) {
  TIconBar::DoPostCreate(arg);

  knobBitmapA0 = CreateBitmapResourceLoaderHandle(0x3eb);
  RECT rect;
  CopyRect(&rect, &(*knobBitmapA0)->bitmapRect);

  int width = rect.right - rect.left;
  int height = rect.bottom - rect.top;
  minTrackOffsetB4 = 0;
  knobBaseRectA4.left = 0;
  knobBaseRectA4.top = 0;
  knobBaseRectA4.right = width;
  knobHeightB8 = static_cast<short>(height);
  knobWidthBA = static_cast<short>(width);
  maxTrackOffsetB6 = static_cast<short>(frameWidth34 - width);
  knobBaseRectA4.bottom = height;
}

// FUNCTION: IMPERIALISM 0x00506560
void TIconSlider::SetMax(short maxValue) {
  maxTrackOffsetB6 = iconSpacing98 * maxValue;
}

// FUNCTION: IMPERIALISM 0x00506590
void TIconSlider::SetNumIcons(short numIcons) {
  numIcons96 = numIcons;
}

// FUNCTION: IMPERIALISM 0x005065b0
char TIconSlider::KnobContainsMouse(const CPoint* point) {
  RECT knobRect;
  GetKnobRect(knobRect);
  return static_cast<char>(PtInRect(&knobRect, *point));
}

// FUNCTION: IMPERIALISM 0x005065f0
char TIconSlider::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  if (KnobContainsMouse(point) != 0) {
    TIconBar::DispatchUiMouseMoveToChildren(point, arg2, arg3, arg4);
    return 1;
  }

  int nextValue = point->x;
  if (maxTrackOffsetB6 < nextValue) {
    nextValue = maxTrackOffsetB6;
  }
  value9c = static_cast<short>(nextValue) / iconSpacing98;
  RefreshControl();
  ownerContext->DispatchEvent(0x6c, this, 0);
  return 1;
}

// Draws the inherited tick strip, then lets the slider resolve/refresh its thumb
// bitmap resource (slot 0x78, DrawKnob).
// FUNCTION: IMPERIALISM 0x00506690
void TIconSlider::ApplyRectSlot110(RECT* rectBuffer) {
  TIconBar::ApplyRectSlot110(rectBuffer);
  DrawKnob();
}

// FUNCTION: IMPERIALISM 0x005066c0
void TIconSlider::DrawKnob() {
  RECT knobRect;
  GetKnobRect(knobRect);
  QDLoadResource(knobBitmapA0);
  BlitBitmapResourceLoaderToActiveDc(knobBitmapA0, &knobRect);
}

// FUNCTION: IMPERIALISM 0x00506710
void TIconSlider::GetKnobRect(RECT& knobRect) {
  knobRect = knobBaseRectA4;
  short offset = static_cast<short>(value9c * iconSpacing98 - knobWidthBA / 2 + iconSpacing98 / 2);
  OffsetRect(&knobRect, offset, 0);
}

// FUNCTION: IMPERIALISM 0x005067a0
void TIconSlider::DispatchPictureResourceCommand(int nEventType, void* pEventSender,
                                                 void* pEventDataA, void* pEventDataB,
                                                 int nCommandFlag) {
  (void)nCommandFlag;
  CPoint* startPoint = static_cast<CPoint*>(pEventSender);
  CPoint* previousPoint = static_cast<CPoint*>(pEventDataA);
  CPoint* currentPoint = static_cast<CPoint*>(pEventDataB);

  RECT previousKnobRect;
  GetKnobRect(previousKnobRect);
  RECT currentKnobRect = previousKnobRect;

  int previousOffset = previousPoint->x - startPoint->x;
  int minOffset = minTrackOffsetB4 - previousKnobRect.left;
  if (previousOffset <= minOffset) {
    previousOffset = minOffset;
  }
  int maxOffset = maxTrackOffsetB6 - previousKnobRect.left;
  if (previousOffset < maxOffset) {
    maxOffset = previousOffset;
  }
  OffsetRect(&previousKnobRect, static_cast<short>(maxOffset), 0);

  int currentOffset = currentPoint->x - startPoint->x;
  minOffset = minTrackOffsetB4 - currentKnobRect.left;
  if (currentOffset <= minOffset) {
    currentOffset = minOffset;
  }
  maxOffset = maxTrackOffsetB6 - currentKnobRect.left;
  if (maxOffset <= currentOffset) {
    currentOffset = maxOffset;
  }
  OffsetRect(&currentKnobRect, static_cast<short>(currentOffset), 0);

  if (nEventType == 2) {
    value9c = static_cast<short>(knobWidthBA / 2 + currentKnobRect.left) / iconSpacing98;
    GetKnobRect(currentKnobRect);
  }

  RECT redrawRect = previousKnobRect;
  if (previousKnobRect.right <= currentKnobRect.right) {
    redrawRect.right = currentKnobRect.right;
  } else if (currentKnobRect.left <= previousKnobRect.left) {
    redrawRect.left = currentKnobRect.left;
  }

  RgnHandle savedClip = NewRgn();
  GetClip(savedClip);
  ClipRect(&redrawRect);

  RECT barRect;
  OffsetRectByCachedPos(&redrawRect, &barRect);
  TIconBar::ApplyRectSlot110(&barRect);

  SetClip(savedClip);
  DisposeRgn(savedClip);

  QDLoadResource(knobBitmapA0);
  BlitBitmapResourceLoaderToActiveDc(knobBitmapA0, &currentKnobRect);
  if (nEventType == 2) {
    ownerContext->DispatchEvent(0x6c, this, 0);
  }
}
