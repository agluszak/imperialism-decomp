#pragma once

#include "compat.h"
#include "game/CRuntimeClass.h"
#include "game/TPictureButton.h"

// VTABLE: IMPERIALISM 0x665608
class TClosePicture : public TPictureButton {
public:
  TClosePicture();
  virtual ~TClosePicture() override;

  virtual CRuntimeClass* GetRuntimeClass() const override; // 0x00 0x586b50 (override)
  virtual char DispatchUiMouseEventToChildrenOrSelf_Impl(CPoint* point, int arg2, int arg3,
                                                         int arg4) override;
};

ASSERT_SIZE(TClosePicture, 0x94);
