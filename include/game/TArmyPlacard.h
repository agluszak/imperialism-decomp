#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTArmyPlacard;
extern "C" int g_pClassDescTArmyPlacard;

// VTABLE: IMPERIALISM 0x667638
class TArmyPlacard : public TPictureButton {
public:
  TArmyPlacard();
  virtual ~TArmyPlacard();

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bc20();
  void RenderArmyPlacardWithShadow();
  void RenderRightAlignedNumericOverlayWithShadow();
};
