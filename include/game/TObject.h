#pragma once

#include "compat.h"
#include "game/mfc.h"

// MFC TObject: the root game object layer between CObject and TEventHandler.
// It has no fields beyond the inherited CObject vptr.
class TObject : public CObject {
public:
  CRuntimeClass* GetRuntimeClass() const override;
};

ASSERT_SIZE(TObject, 0x4);
