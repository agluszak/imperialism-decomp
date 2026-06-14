#pragma once

#include "compat.h"
#include "game/CRuntimeClass.h"
#include "game/TPictureButton.h"

// VTABLE: IMPERIALISM 0x665608
class TClosePicture : public TPictureButton {
public:
  TClosePicture();
  virtual ~TClosePicture();

  virtual CRuntimeClass* GetTEventHandlerClassNamePointer();
  virtual char DispatchUiMouseEventToChildrenOrSelf_Impl(Point32* point, int arg2, int arg3,
                                                         int arg4);
};

ASSERT_SIZE(TClosePicture, 0x94);
