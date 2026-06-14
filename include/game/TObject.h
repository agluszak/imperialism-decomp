#pragma once

#include "compat.h"
#include "game/CObject.h"

// MFC TObject: the root game object layer between CObject and TEventHandler.
// It has no fields beyond the inherited CObject vptr.
class TObject : public CObject {
public:
  CRuntimeClass* GetRuntimeClass() override;
};

ASSERT_SIZE(TObject, 0x4);
