#pragma once

#include "game/TControl.h"

extern "C" int g_vtblTNumberedArrowButton;
extern "C" int g_pClassDescTNumberedArrowButton;

// VTABLE: IMPERIALISM 0x667678
class TNumberedArrowButton : public TControl {
public:
  short value84;
  short value86;

  TNumberedArrowButton();
  virtual ~TNumberedArrowButton();
};
