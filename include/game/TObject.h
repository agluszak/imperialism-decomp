#pragma once

#include "compat.h"
#include "game/mfc.h"

class TStream;

// MFC TObject: game object root between CObject and TEventHandler (vtable 0x006485c0).
// VTABLE: IMPERIALISM 0x006485c0
class TObject : public CObject {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  void Serialize(CArchive& archive) override;
  virtual void WriteTo(TStream* stream);
  virtual void ReadFrom(TStream* stream);
  virtual void Free();
  virtual TObject* ShallowClone();
  virtual TObject* ShallowFree();

  void RestoreConstructionSentinelVtable();
};

ASSERT_SIZE(TObject, 0x4);
