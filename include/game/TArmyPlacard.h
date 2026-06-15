#pragma once

#include "game/TPictureResourceEntryBase.h"

extern "C" int g_vtblTArmyPlacard;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTArmyPlacard;

// VTABLE: IMPERIALISM 0x667448
class TArmyPlacard : public TPictureResourceEntryBase {
public:
  short glyph90;

  TArmyPlacard();
  virtual ~TArmyPlacard() override;
  CRuntimeClass* GetRuntimeClass() override;

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bc20();
  void RenderArmyPlacardWithShadow();
  void ApplyRectSlot110(RECT* rectBuffer) override; // 0x110 0x58bfe0
  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  bool IsSelected(short value = -1, bool refreshNow = true) override;
};
