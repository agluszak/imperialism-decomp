#pragma once

#include "compat.h"
#include "game/mfc.h"

class TStream;

// MFC TObject: game object root between CObject and TEventHandler (vtable 0x006485c0).
// VTABLE: IMPERIALISM 0x006485c0
class TObject : public CObject {
public:
  DECLARE_SERIAL(TObject)
  // In-class inline: the original binary has no out-of-line TObject::TObject — every
  // derived constructor absorbs it (e.g. TNetMgr::TNetMgr 0x5e33e0 is a single vptr
  // store), so an out-of-line definition would pessimize all of them into a call.
  // NOOP: verified empty in original 0x005e33e0 (no standalone body exists; every
  // derived ctor absorbs it — e.g. TNetMgr::TNetMgr is just the vptr store)
  TObject() {}
  // Inline so every derived game-object destructor can reproduce the original direct
  // CObject vtable reset instead of calling an out-of-line TObject destructor.
  // FUNCTION: IMPERIALISM 0x00485f50
  virtual ~TObject() override {}

  void Serialize(CArchive& archive) override;
  virtual void WriteTo(TStream* stream);
  virtual void ReadFrom(TStream* stream);
  virtual void Free();
  virtual TObject* ShallowClone();
  virtual TObject* ShallowFree();
};

ASSERT_SIZE(TObject, 0x4);
