#pragma once

#include "game/TView.h"
#include "game/mfc.h"
#include "game/ui_tags_common.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065ce28
class TShipView : public TView {
public:
  DECLARE_DYNCREATE(TShipView)
  virtual ~TShipView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005658d0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5654e0

  TShipView();

  // Original object size is 0x68 (CRuntimeClass m_nObjectSize); the source class ended at 0x60. Trailing 8 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  // The order node this row represents: Draw (0x5654e0) reads
  // type (+4), name (+0x18), strength (+0x1c), and
  // admiral (+0x20) through this pointer, matching TShip's layout exactly.
  TShip* shipNode60;
  class TTaskForce* field64;

  // Non-virtual: runs the rename dialog for field60 in response to the 'name' command.
  void RunEngineerOrderNameEditDialogAndApply();
};
