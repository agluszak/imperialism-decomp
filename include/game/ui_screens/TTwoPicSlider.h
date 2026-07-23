#pragma once

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00641bd0
class TTwoPicSlider : public TControl {
public:
  DECLARE_DYNCREATE(TTwoPicSlider)
  virtual ~TTwoPicSlider() override;
  virtual void Free() override; // slot 0x07 0x0056e2f0
  virtual void TrackMouse(TrackPhase phase, CPoint& startPoint, CPoint& previousPoint,
                          CPoint& currentPoint,
                          unsigned char commandFlag) override; // slot 0x68 0x0056e640
  virtual void Draw(RECT* rectBuffer) override;                // slot 0x44 0x0056e370

  TQuickDrawSurfaceContext* lowerSurface;     // 0x84
  TQuickDrawSurfaceContext* upperSurface;     // 0x88
  TQuickDrawSurfaceContext* compositeSurface; // 0x8C
  short splitPosition;                        // 0x90
  unsigned char pad92[2];
  int mode; // 0x94

  TTwoPicSlider();

  void InitializePictureSurfaces(int baseBitmapId); // 0x0056e200
};
