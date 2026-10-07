#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/ui_tags_screens.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006614c8
class TScrollBarView : public TControl {
public:
  DECLARE_DYNCREATE(TScrollBarView)
  virtual ~TScrollBarView() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;

  class TScrollView* ownerView;
  short minValue;     // bounded-value component A (button span, seeded 0x12)
  short maxValue;     // bounded-value component B (frameHeight - 0x24)
  short currentValue; // clamped current value (seeded 0x12)
  short word8e;       // allocation padding/unobserved so far
  struct TQuickDrawSurfaceContext* surfaceContext;

  TScrollBarView() : surfaceContext(0) {}

  void IScrollBarView(class TScrollView* panel, int* offsetLayout, int* sizeLayout);

  void RefreshCityViewport();
  void SetThumb(int percent, unsigned char refresh);
};
ASSERT_SIZE(TScrollBarView, 0x94);
