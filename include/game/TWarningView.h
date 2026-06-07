#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x6687b8
class TWarningView : public TPictureResourceEntryBase {
public:
  char pad_90_to_93[0x04];

  TWarningView();
  virtual ~TWarningView();
};

ASSERT_SIZE(TWarningView, 0x94);
