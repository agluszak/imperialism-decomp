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
  // slot 0x0a AdornerSlot0A inherited unchanged (0x49d900)
  // slot 0x0b AdornerSlot0B inherited unchanged (0x49d930)
  virtual undefined AdornerSlot0C(int unusedArg1, int unusedArg2) override; // slot 0x0c 0x4ff1c0
  // slot 0x0d AdornerSlot0D inherited unchanged (0x49d9f0)
  // slot 0x0e AdornerSlot0E inherited unchanged (0x49da20)
  // slot 0x0f AdornerSlot0F inherited unchanged (0x49da50)
  // slot 0x10 AdornerSlot10 inherited unchanged (0x49da80)

  TColorFill();
};
