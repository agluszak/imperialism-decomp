#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064d100
class TArmyUnitView : public TView {
public:
  DECLARE_DYNCREATE(TArmyUnitView)
  virtual ~TArmyUnitView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void Draw(RECT* rectBuffer) override;
  class TMilitaryUnit* militaryUnit;

  // Non-virtual: runs the rename dialog for militaryUnit in response to the 'name' command.
  void RenameUnit();

  TArmyUnitView();

  void IArmyUnitView(TView* panel, int* offsetLayout, int* sizeLayout, int sizeDeterminerX,
                     int sizeDeterminerY, TMilitaryUnit* unit);
};
ASSERT_SIZE(TArmyUnitView, 0x64);
