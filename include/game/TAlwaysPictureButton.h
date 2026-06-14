#pragma once

#include "compat.h"
#include "game/TPictureButton.h"

// VTABLE: IMPERIALISM 0x65e928
struct CRuntimeClass;
class TAlwaysPictureButton : public TPictureButton {
public:
  TAlwaysPictureButton();
  CRuntimeClass* GetRuntimeClass() override;
  // ~TAlwaysPictureButton is compiler-generated (implicit virtual dtor).
};

ASSERT_SIZE(TAlwaysPictureButton, 0x94);
