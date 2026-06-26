#pragma once

#include "game/TNumberText.h"

// VTABLE: IMPERIALISM 0x0066c740
class TPictureNumberText : public TNumberText {
public:
  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 (0x5b51c0)
  ~TPictureNumberText() override;                  // slot 0x01 (0x5b5210)

  TPictureNumberText(); // constructor (0x5b51e0)
};
