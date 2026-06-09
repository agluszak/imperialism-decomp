#pragma once

#include "game/CObject.h"

// MFC CGdiObject handle storage (vtable 0x00671054 during base teardown).
class CGdiObject : public CObject {
public:
  int gdiHandle;

  virtual ~CGdiObject();

protected:
  CGdiObject();
};

// MFC CBrush — clip/map code constructs with vtable 0x0067106c.
// VTABLE: IMPERIALISM 0x0067106c
class CBrush : public CGdiObject {
public:
  CBrush();

  bool AttachRegionHandleToClipStateAndRegister();
};
