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
  virtual ~TAdorner() override {}                     // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;     // slot 0x05 0x49d990
  virtual void ReadFrom(TStream* stream) override;    // slot 0x06 0x49d960
  virtual void AddedToView(TView* view);              // slot 0x0a 0x49d900
  virtual void RemovedFromView(TView* view);          // slot 0x0b 0x49d930
  virtual void Draw(TView* view, const RECT& bounds); // slot 0x0c 0x49d9c0
  virtual void ViewChangedFrame(TView* view, const RECT& oldFrame, const RECT& newFrame,
                                unsigned char redraw); // slot 0x0d 0x49d9f0
  virtual void InvalidateAdorner(TView* view);         // slot 0x0e 0x49da20
  virtual void DrawLine(signed char colorIndex, short x1, short y1,
                        short length); // slot 0x0f 0x49da50
  virtual bool DoesAdorn(TView* view); // slot 0x10 0x49da80

  TAdorner() {
    ReportAssertionFailure("D:\\Ambit\\Cross\\UDisplayMgr.cpp", 0x69);
  }

  unsigned long adornerId;
  unsigned char adornerFlags;
  unsigned char pad09[3];
};
ASSERT_SIZE(TAdorner, 0xc);
