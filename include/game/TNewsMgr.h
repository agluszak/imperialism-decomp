#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TNewsMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TNewsMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0065c598
class TNewsMgr : public TObject {
public:
// === BEGIN GENERATED DECLS (TNewsMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNewsMgr)
  virtual ~TNewsMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x55b8c0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x55b8a0
  virtual void Free() override; // slot 0x07 0x55b820
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
// === END GENERATED DECLS (TNewsMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNewsMgr 0xCTOR`).

  TNewsMgr();
};

