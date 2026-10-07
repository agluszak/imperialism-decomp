#pragma once

#include "compat.h"

#include "game/ui_core/TNumberText.h"

// VTABLE: IMPERIALISM 0x0066c740
class TPictureNumberText : public TNumberText {
public:
  DECLARE_DYNCREATE(TPictureNumberText)
  ~TPictureNumberText() override;

  TPictureNumberText(); // constructor
};
ASSERT_SIZE(TPictureNumberText, 0xac);
