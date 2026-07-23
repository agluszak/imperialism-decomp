#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006606e8
class TNoHilitePicture : public TPicture {
public:
  DECLARE_DYNCREATE(TNoHilitePicture)
  virtual ~TNoHilitePicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void Hilite();                // slot 0x73 0x572bb0
  // Only the constructor's false write is currently visible on Windows; the Mac class
  // identity and Hilite override support this as the local highlight-state byte.
  bool hiliteState90; // +0x90

  TNoHilitePicture();
};
