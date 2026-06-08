#pragma once

#include "compat.h"
#include "game/TPictureButton.h"

// VTABLE: IMPERIALISM 0x665608
class TClosePicture : public TPictureButton {
public:
  TClosePicture();
  virtual ~TClosePicture();

  virtual void* GetTEventHandlerClassNamePointer();
  virtual void vmethod_0072(int arg1, int arg2, int arg3, int arg4);
};

ASSERT_SIZE(TClosePicture, 0x94);
