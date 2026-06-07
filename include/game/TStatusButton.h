#pragma once

#include "game/TButton.h"

extern "C" int g_pClassDescTStatusButton;

// VTABLE: IMPERIALISM 0x664f68
class TStatusButton : public TButton {
public:
  TStatusButton();

  int ControlTag() const;
  void* OwnerPanel() const;
};
