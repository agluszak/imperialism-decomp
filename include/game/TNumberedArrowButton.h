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

  void OrphanCallChain_C3_I43_0058b750(char mode, char refreshParent);
  void OrphanCallChain_C2_I37_0058b8d0(short mode);
};
