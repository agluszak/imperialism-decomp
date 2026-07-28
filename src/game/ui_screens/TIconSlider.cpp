#include "game/ui_screens/TIconSlider.h"

#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/gfx/quickdraw_regions.h"
// SYNTHETIC: IMPERIALISM 0x005062d0
// TIconSlider::CreateObject

// SYNTHETIC: IMPERIALISM 0x005063a0
// TIconSlider::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIconSlider, TIconBar)

// FUNCTION: IMPERIALISM 0x005063c0
TIconSlider::TIconSlider()
    : TIconBar(), value(0), knobBitmap(0), minTrackOffset(0), maxTrackOffset(0) {
  knobBaseRect.left = 0;
  knobBaseRect.top = 0;
  knobBaseRect.right = 0;
  knobBaseRect.bottom = 0;
}

// SYNTHETIC: IMPERIALISM 0x00506430
// TIconSlider::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00506460
TIconSlider::~TIconSlider() {}

// FUNCTION: IMPERIALISM 0x00506480
void TIconSlider::DoPostCreate(int arg) {
  TIconBar::DoPostCreate(arg);

  knobBitmap = CreateBitmapResourceLoaderHandle(0x3eb);
  RECT rect;
  CopyRect(&rect, &(*knobBitmap)->bitmapRect);

  int width = rect.right - rect.left;
  int height = rect.bottom - rect.top;
  minTrackOffset = 0;
  knobBaseRect.left = 0;
  knobBaseRect.top = 0;
  knobBaseRect.right = width;
  knobHeight = static_cast<short>(height);
  knobWidth = static_cast<short>(width);
  maxTrackOffset = static_cast<short>(frameWidth34 - width);
  knobBaseRect.bottom = height;
}

// FUNCTION: IMPERIALISM 0x00506560
void TIconSlider::SetMax(short maxValue) {
  maxTrackOffset = iconSpacing98 * maxValue;
}

// FUNCTION: IMPERIALISM 0x00506590
void TIconSlider::SetNumIcons(short numIcons) {
  numIcons96 = numIcons;
}

// FUNCTION: IMPERIALISM 0x005065b0
char TIconSlider::KnobContainsMouse(const CPoint& point) {
  RECT knobRect;
  GetKnobRect(knobRect);
  return static_cast<char>(PtInRect(&knobRect, point));
}

// FUNCTION: IMPERIALISM 0x005065f0
char TIconSlider::HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (KnobContainsMouse(point) != 0) {
    TIconBar::HandleMouseDown(point, event, origin);
    return 1;
  }

  int nextValue = point.x;
  if (maxTrackOffset < nextValue) {
    nextValue = maxTrackOffset;
  }
  value = static_cast<short>(nextValue) / iconSpacing98;
  RefreshControl();
  ownerContext->HandleEvent(0x6c, this, 0);
  return 1;
}

// Draws the inherited tick strip, then lets the slider resolve/refresh its thumb
// bitmap resource (slot 0x78, DrawKnob).
// FUNCTION: IMPERIALISM 0x00506690
void TIconSlider::Draw(RECT* rectBuffer) {
  TIconBar::Draw(rectBuffer);
  DrawKnob();
}

// FUNCTION: IMPERIALISM 0x005066c0
void TIconSlider::DrawKnob() {
  RECT knobRect;
  GetKnobRect(knobRect);
  QDLoadResource(knobBitmap);
  BlitBitmapResourceLoaderToActiveDc(knobBitmap, &knobRect);
}

// FUNCTION: IMPERIALISM 0x00506710
void TIconSlider::GetKnobRect(RECT& knobRect) {
  knobRect = knobBaseRect;
  short offset = static_cast<short>(value * iconSpacing98 - knobWidth / 2 + iconSpacing98 / 2);
  OffsetRect(&knobRect, offset, 0);
}

// FUNCTION: IMPERIALISM 0x005067a0
void TIconSlider::TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                             CPoint& currentPoint, unsigned char commandFlag) {
  (void)commandFlag;
  RECT previousKnobRect;
  GetKnobRect(previousKnobRect);
  RECT currentKnobRect = previousKnobRect;

  int previousOffset = previousPoint.x - startPoint.x;
  int minOffset = minTrackOffset - previousKnobRect.left;
  if (previousOffset <= minOffset) {
    previousOffset = minOffset;
  }
  int maxOffset = maxTrackOffset - previousKnobRect.left;
  if (previousOffset < maxOffset) {
    maxOffset = previousOffset;
  }
  OffsetRect(&previousKnobRect, static_cast<short>(maxOffset), 0);

  int currentOffset = currentPoint.x - startPoint.x;
  minOffset = minTrackOffset - currentKnobRect.left;
  if (currentOffset <= minOffset) {
    currentOffset = minOffset;
  }
  maxOffset = maxTrackOffset - currentKnobRect.left;
  if (maxOffset <= currentOffset) {
    currentOffset = maxOffset;
  }
  OffsetRect(&currentKnobRect, static_cast<short>(currentOffset), 0);

  if (phase == kTrackPhaseEnd) {
    value = static_cast<short>(knobWidth / 2 + currentKnobRect.left) / iconSpacing98;
    GetKnobRect(currentKnobRect);
  }

  CRect redrawRect = previousKnobRect;
  if (previousKnobRect.right <= currentKnobRect.right) {
    redrawRect.right = currentKnobRect.right;
  } else if (currentKnobRect.left <= previousKnobRect.left) {
    redrawRect.left = currentKnobRect.left;
  }

  RgnHandle savedClip = NewRgn();
  GetClip(savedClip);
  ClipRect(&redrawRect);

  CRect barRect;
  OffsetRectByCachedPos(&redrawRect, &barRect);
  TIconBar::Draw(&barRect);

  SetClip(savedClip);
  DisposeRgn(savedClip);

  QDLoadResource(knobBitmap);
  BlitBitmapResourceLoaderToActiveDc(knobBitmap, &currentKnobRect);
  if (phase == kTrackPhaseEnd) {
    ownerContext->HandleEvent(0x6c, this, 0);
  }
}
