#pragma once

#include "compat.h"
#include "game/app/TAnimation.h"
#include "game/ui_screens/TIconBar.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00657c60
class TIconSlider : public TIconBar {
public:
  DECLARE_DYNCREATE(TIconSlider)
  virtual ~TIconSlider() override;

  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual char HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, unsigned char commandFlag) override;
  virtual void SetNumIcons(short numIcons) override;
  virtual void SetMax(short maxValue);
  virtual char KnobContainsMouse(const CPoint& point);
  virtual void DrawKnob();
  virtual void GetKnobRect(RECT& knobRect);

  // TIconBar's own slice ends at 0x9c (RTTI oracle); all zeroed by the ctor except
  // pad_bc, which the ctor never touches (RTTI oracle confirms sizeof(TIconSlider) ==
  // 0xbc, 4 bytes past field_b6).
  short value9c;
  TBitmapResourceLoader** knobBitmapA0;
  RECT knobBaseRectA4;
  short minTrackOffsetB4;
  short maxTrackOffsetB6;
  short knobHeightB8;
  short knobWidthBA;

  TIconSlider();
};

ASSERT_SIZE(TIconSlider, 0xbc);
