#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/mfc.h"

class TStream;
class TView;

// VTABLE: IMPERIALISM 0x0064bdd0
class TAdorner : public TObject {
public:
  DECLARE_DYNCREATE(TAdorner)
  // FUNCTION: IMPERIALISM 0x0049dae0
  virtual ~TAdorner() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void AddedToView(TView* view);
  virtual void RemovedFromView(TView* view);
  virtual void Draw(TView* view, const RECT& bounds);
  virtual void ViewChangedFrame(TView* view, const RECT& oldFrame, const RECT& newFrame,
                                unsigned char redraw);
  virtual void InvalidateAdorner(TView* view);
  virtual void DrawLine(signed char colorIndex, short x1, short y1, short length);
  virtual bool DoesAdorn(TView* view);

  TAdorner() {
    ReportAssertionFailure("D:\\Ambit\\Cross\\UDisplayMgr.cpp", 0x69);
  }

  unsigned long adornerId;
  unsigned char adornerFlags;
  unsigned char pad09[3];
};
ASSERT_SIZE(TAdorner, 0xc);
