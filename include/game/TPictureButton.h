#pragma once

#include "compat.h"
#include "game/TPictureResourceEntryBase.h"

// VTABLE: IMPERIALISM 0x65e6f8
class TPictureButton : public TPictureResourceEntryBase {
public:
  short glyph90;
  short timingWord92;

  TPictureButton();
  virtual ~TPictureButton() override;
  CRuntimeClass* GetRuntimeClass() const override;
  void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3, int arg4) override;
  void SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) override;
};

ASSERT_SIZE(TPictureButton, 0x94);
