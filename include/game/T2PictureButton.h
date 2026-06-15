#pragma once

#include "compat.h"
#include "game/TPictureButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65eb60
class T2PictureButton : public TPictureButton {
public:
  T2PictureButton();
  virtual ~T2PictureButton() override;
  CRuntimeClass* GetRuntimeClass() override;
};

ASSERT_SIZE(T2PictureButton, 0x94);
