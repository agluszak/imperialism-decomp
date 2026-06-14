#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTArmyPlacard;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTArmyPlacard;

// VTABLE: IMPERIALISM 0x667638
class TArmyPlacard : public TPictureButton {
public:
  TArmyPlacard();
  virtual ~TArmyPlacard() override;
  CRuntimeClass* GetRuntimeClass() override;

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bc20();
  void RenderArmyPlacardWithShadow();
  void RenderRightAlignedNumericOverlayWithShadow();
};
