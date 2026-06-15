#pragma once

#include "game/TButton.h"

struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTStatusButton;

// VTABLE: IMPERIALISM 0x664f68
class TStatusButton : public TButton {
public:
#ifdef __clang__
  using TView::OwnerPanel;
#endif

  TStatusButton();
  CRuntimeClass* GetRuntimeClass() override;

  int ControlTag() const;
  void* OwnerPanel() const;

  void HandleCityDialogSelectionAndBackControlReset(int selectedIndex, TEventHandler* sourceHandler, TEvent* event);
};

TStatusButton* __cdecl CreateTStatusButtonInstance(void);
