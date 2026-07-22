#pragma once

#include "game/TColorKeyPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065fd28
class TColorKeyButton : public TColorKeyPicture {
public:
  DECLARE_DYNCREATE(TColorKeyButton)
  virtual ~TColorKeyButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void HiliteState(unsigned char fEnabledState,
                           unsigned char fRefreshNow) override; // slot 0x70 0x571ff0
  virtual void DrawImmediate();                                 // slot 0x74 0x572060

  TColorKeyButton();

  // Original object size is 0x9c (CRuntimeClass m_nObjectSize); the source class ended at 0x98. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field98;
};
