#pragma once

#include "compat.h"
#include "game/mfc.h"

class TStream;

// MFC TObject: game object root between CObject and TEventHandler (vtable 0x006485c0).
// VTABLE: IMPERIALISM 0x006485c0
class TObject : public CObject {
public:
  DECLARE_SERIAL(TObject)
  // FUNCTION: IMPERIALISM 0x00484970
  TObject() {} // NOOP: verified empty in original 0x00484970; VC5 emits the vptr store.
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
