#pragma once

#include "game/TAdorner.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006566f0
class TColorFill : public TAdorner {
public:
  DECLARE_DYNCREATE(TColorFill)
  virtual ~TColorFill() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x49d990)
  // slot 0x06 ReadFrom inherited unchanged (0x49d960)
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a AddedToView inherited unchanged (0x49d900)
  // slot 0x0b RemovedFromView inherited unchanged (0x49d930)
  // Real override, not a no-op: a nil-pointer assert guarded by a private static flag (see
  // TColorFill.cpp) -- the base class's shared invalidation-flag-pulse default does not
  // apply here.
  virtual void Draw(TView* view, const RECT& bounds) override; // slot 0x0c 0x4ff1c0
  // slot 0x0d ViewChangedFrame inherited unchanged (0x49d9f0)
  // slot 0x0e InvalidateAdorner inherited unchanged (0x49da20)
  // slot 0x0f DrawLine inherited unchanged (0x49da50)
  // slot 0x10 DoesAdorn inherited unchanged (0x49da80)

  TColorFill();
};
