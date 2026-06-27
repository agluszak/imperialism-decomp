#pragma once

#include "game/TButton.h"

struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTStatusButton;

// VTABLE: IMPERIALISM 0x664f68
class TStatusButton : public TButton {
public:
  TStatusButton();
  DECLARE_DYNCREATE(TStatusButton)
  void HandleEvent(int selectedIndex, TEventHandler* sourceHandler, TEvent* event) override;
};

TStatusButton* __cdecl CreateTStatusButtonInstance(void);
