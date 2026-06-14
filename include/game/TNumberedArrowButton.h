#pragma once

#include "game/TControl.h"

extern "C" int g_vtblTNumberedArrowButton;
struct CRuntimeClass;
extern "C" CRuntimeClass g_pClassDescTNumberedArrowButton;

// VTABLE: IMPERIALISM 0x667678
class TNumberedArrowButton : public TControl {
public:
  short value84;
  short value86;

  TNumberedArrowButton();
  CRuntimeClass* GetRuntimeClass() override;
  // Destructor is compiler-generated (implicit virtual dtor).

  void OrphanCallChain_C3_I43_0058b750(char mode, char refreshParent);
  void OrphanCallChain_C2_I37_0058b8d0(short mode);
  void OrphanCallChain_C1_I08_0058c330(short value84, char refreshFlag);
  void OrphanCallChain_C2_I23_0058c360(short value86, char refreshFlag);
};
