#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0064f540
class TLaborPool : public TObject {
public:
  DECLARE_DYNCREATE(TLaborPool)
  virtual ~TLaborPool() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x4b21d0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b2220
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins44_004b2270(int param_1, short param_2); // slot 0x0a 0x4b2270
  virtual undefined CreateTCityInstance(int param_1, short param_2); // slot 0x0b 0x4b2340

  TLaborPool();
};

