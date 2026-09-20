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

  // NOOP: verified empty in original 0x00565433 (no standalone TShipView::TShipView body exists: CreateObject 0x00565400 inlines this default ctor, calling the TView base ctor directly at that site)
  TShipView() {}

  // Original object size is 0x68 (CRuntimeClass m_nObjectSize); the fields below complete the extent so sizeof matches the original.
  // The order node this row represents: Draw (0x5654e0) reads
  // type (+4), name (+0x18), strength (+0x1c), and
  // admiral (+0x20) through this pointer, matching TShip's layout exactly.
  TShip* shipNode60;
  class TTaskForce* field64;

  // Non-virtual: runs the rename dialog for field60 in response to the 'name' command.
  void RunEngineerOrderNameEditDialogAndApply();

  // Mac oracle: IShipView(TView*, const VPoint&, const VPoint&, SizeDeterminer,
  // SizeDeterminer, TShip*, TTaskForce*). Dead standalone emission; live creation
  // sites inline the same init sequence. 0x00565490.
  void IShipView(TView* panel, int* offsetLayout, int* sizeLayout,
                 int sizeDeterminerX, int sizeDeterminerY, TShip* ship, class TTaskForce* taskForce);
};
ASSERT_SIZE(TShipView, 0x68);
