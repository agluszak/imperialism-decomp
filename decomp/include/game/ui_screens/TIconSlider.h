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
                          CPoint& currentPoint, bool commandFlag) override;
  virtual void SetNumIcons(short numIcons) override;
  virtual void SetMax(short maxValue);
  virtual char KnobContainsMouse(const CPoint& point);
  virtual void DrawKnob();
  virtual void GetKnobRect(RECT& knobRect);

  short value;
  TBitmapResourceLoader** knobBitmap;
  RECT knobBaseRect;
  short minTrackOffset;
  short maxTrackOffset;
  short knobHeight;
  short knobWidth;

  TIconSlider();
};

ASSERT_SIZE(TIconSlider, 0xbc);
