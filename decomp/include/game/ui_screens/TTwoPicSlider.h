#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00641bd0
class TTwoPicSlider : public TControl {
public:
  DECLARE_DYNCREATE(TTwoPicSlider)
  virtual ~TTwoPicSlider() override;
  virtual void Free() override;
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint, bool commandFlag) override;
  virtual void Draw(RECT* rectBuffer) override;

  TQuickDrawSurfaceContext* lowerSurface;
  TQuickDrawSurfaceContext* upperSurface;
  TQuickDrawSurfaceContext* compositeSurface;
  short splitPosition;
  unsigned char pad92[2];
  int mode;

  TTwoPicSlider();

  void SetPicture(int baseBitmapId);
};
ASSERT_SIZE(TTwoPicSlider, 0x98);
