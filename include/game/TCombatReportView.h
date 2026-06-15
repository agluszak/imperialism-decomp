#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTCombatReportView;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTCombatReportView;

// VTABLE: IMPERIALISM 0x6678a0
class TCombatReportView : public TPictureButton {
public:
  short reportValue;

  TCombatReportView();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor).

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bcf0();
  void RenderCombatReportViewTextWithShadow();
};
