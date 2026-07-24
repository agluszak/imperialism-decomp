#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064ec60
class TCheater : public TView {
public:
  DECLARE_DYNCREATE(TCheater)
  virtual ~TCheater() override; // slot 0x01 (scalar deleting destructor)
  virtual void ApplyCheats();   // slot 0x68 0x4b1410; Mac symbol oracle

  TCheater();

  // Two-phase init (MacApp IViewClass idiom): frame this cheater panel into `panel`, then
  // build its "Done" TStaticText caption and TButton child. 0x004b14a0, __thiscall.
  void ConstructTCheaterBaseState(TView* panel, int unusedArg);

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended at 0x60. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field60;
};
