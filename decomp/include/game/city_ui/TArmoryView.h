#pragma once

#include "compat.h"

#include "game/city_ui/TBuildingView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TUnitOrder;

// VTABLE: IMPERIALISM 0x00652b10
class TArmoryView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TArmoryView)
  virtual ~TArmoryView() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoStartup() override;
  virtual void UpdateFields() override;
  virtual void SetUnit(short nBuildingSlotId);

  TArmoryView();

  unsigned char paddingA0[4];
  short selectedRowIndex;
  TUnitOrder* selectedUnitOrder;
};
ASSERT_SIZE(TArmoryView, 0xac);
