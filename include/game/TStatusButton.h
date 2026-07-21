#pragma once

#include "game/TButton.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x664f68
class TStatusButton : public TButton {
public:
  TStatusButton();
  DECLARE_DYNCREATE(TStatusButton)
  void DoEvent(int selectedIndex, TEventHandler* sourceHandler, TEvent* event) override;
};

TStatusButton* __cdecl CreateTStatusButtonInstance(void);
