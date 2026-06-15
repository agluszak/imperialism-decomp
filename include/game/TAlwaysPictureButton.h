#pragma once

#include "compat.h"
#include "game/TPictureButton.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x65e928
class TAlwaysPictureButton : public TPictureButton {
public:
  TAlwaysPictureButton();
  CRuntimeClass* GetRuntimeClass() const override;
  // ~TAlwaysPictureButton is compiler-generated (implicit virtual dtor).
  void SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) override;
  virtual void Select(bool isPressed, bool notifyParent); // slot 0x1d0
};

ASSERT_SIZE(TAlwaysPictureButton, 0x94);
