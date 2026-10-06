#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/ui_tags_screens.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006614c8
class TScrollBarView : public TControl {
public:
  DECLARE_DYNCREATE(TScrollBarView)
  virtual ~TScrollBarView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;       // slot 0x07 0x5746e0
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005747c0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x574720
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x574970
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x574830
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          bool commandFlag) override; // slot 0x68 0x574d10

  class TScrollView* ownerView;
  short word88; // 0x88 — bounded-value component A (button span, seeded 0x12)
  short word8a; // 0x8a — bounded-value component B (frameHeight - 0x24)
  short word8c; // 0x8c — clamped current value (seeded 0x12)
  short word8e; // 0x8e — allocation padding/unobserved so far
  struct TQuickDrawSurfaceContext* surfaceContext;

  TScrollBarView() : surfaceContext(0) {}

  void IScrollBarView(class TScrollView* panel, int* offsetLayout, int* sizeLayout);

  void RefreshCityDialogScrollableViewportWithQuickDrawContext();
  void SetThumb(int percent, unsigned char refresh); // 0x574e20
};
ASSERT_SIZE(TScrollBarView, 0x94);
