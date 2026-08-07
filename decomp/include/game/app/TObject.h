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
  // Inline so every derived game-object destructor can reproduce the original direct
  // CObject vtable reset instead of calling an out-of-line TObject destructor.
  // 0x4849c0 is the per-TU duplicate COMDAT copy the linker kept beside the
  // canonical 0x485f50 (byte-identical; per_tu_duplicate row in
  // config/template_aliases.csv recognizes it — do not claim it separately,
  // reccmp drops a second marker on the same body as a duplicate address).
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
