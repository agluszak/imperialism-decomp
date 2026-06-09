#pragma once

#include "game/TPictureButton.h"

extern "C" int g_vtblTCombatReportView;
extern "C" int g_pClassDescTCombatReportView;

// VTABLE: IMPERIALISM 0x6676f8
class TCombatReportView : public TPictureButton {
public:
  short reportValue;

  TCombatReportView();
  // Destructor is compiler-generated (implicit virtual dtor).

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bcf0();
  void RenderCombatReportViewTextWithShadow();
};
