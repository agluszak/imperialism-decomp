#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006606e8
class TNoHilitePicture : public TPicture {
public:
  DECLARE_DYNCREATE(TNoHilitePicture)
  virtual ~TNoHilitePicture() override;
  virtual void Hilite();
  bool hiliteState;

  // FUNCTION: IMPERIALISM 0x00572b30
  TNoHilitePicture() {
    hiliteState = false;
  }
};
ASSERT_SIZE(TNoHilitePicture, 0x94);
