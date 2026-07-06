#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TTask and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTask -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a970
class TTask : public TObject {
public:
// === BEGIN GENERATED DECLS (TTask) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTask)
  virtual ~TTask() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5adc50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5adc90
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins04_005adc30(); // slot 0x0a 0x5adc30
// === END GENERATED DECLS (TTask) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTask 0xCTOR`).

  TTask();
};

