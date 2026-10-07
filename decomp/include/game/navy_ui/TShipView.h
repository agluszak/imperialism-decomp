#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x0065ce28
class TShipView : public TView {
public:
  DECLARE_DYNCREATE(TShipView)
  virtual ~TShipView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005658d0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5654e0

  // NOOP: verified empty in original 0x00565433
  TShipView() {}

  TShip* shipNode;
  class TTaskForce* taskForce;

  // Non-virtual: runs the rename dialog for field60 in response to the 'name' command.
  void RenameShip();

  void IShipView(TView* panel, int* offsetLayout, int* sizeLayout, int sizeDeterminerX,
                 int sizeDeterminerY, TShip* ship, class TTaskForce* taskForce);
};
ASSERT_SIZE(TShipView, 0x68);
