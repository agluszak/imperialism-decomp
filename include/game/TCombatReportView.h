#pragma once

#include "game/TPictureResourceEntryBase.h"

extern "C" int g_vtblTCombatReportView;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTCombatReportView;

// VTABLE: IMPERIALISM 0x6678a0
class TCombatReportView : public TPictureResourceEntryBase {
public:
  short glyph90;
  short field92;
  short reportValue;

  TCombatReportView();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor).

  void HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void ApplyRectSlot110(RECT* rectBuffer) override;
  bool IsSelected(short value = -1, bool refreshNow = true) override;
};
