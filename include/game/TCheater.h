#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ec60
class TCheater : public TView {
public:
  DECLARE_DYNCREATE(TCheater)
  virtual ~TCheater() override; // slot 0x01 (scalar deleting destructor)
  virtual void ApplyCheats();   // slot 0x68 0x4b1410; Mac symbol oracle

  TCheater();

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended at 0x60. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field60;
};
