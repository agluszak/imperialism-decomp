#pragma once

#include "compat.h"
#include "game/mfc.h"

class TStream;

// MFC TObject: the root game object layer between CObject and TEventHandler.
// It has no fields beyond the inherited CObject vptr.
class TObject : public CObject {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  void Serialize(CArchive& archive) override;
  virtual void WriteTo(TStream* stream);  // slot 5
  virtual void ReadFrom(TStream* stream); // slot 6
  virtual void Free();                    // slot 7
  virtual TObject* ShallowClone();        // slot 8
  virtual TObject* ShallowFree();         // slot 9
};

ASSERT_SIZE(TObject, 0x4);
