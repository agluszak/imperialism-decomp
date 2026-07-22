#pragma once

#include "compat.h"
#include "game/TBuildingView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00652448
class TIndustryView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TIndustryView)
  virtual ~TIndustryView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004ccf30
  virtual void DoStartup() override;            // slot 0x75 0x4cc820
  virtual void UpdateFields() override;         // slot 0x76 0x4cd040
  // TBuildingView's slice ends at 0xa0; RTTI oracle confirms sizeof(TIndustryView) == 0xa8.
  // The +0xa0 dword has only the constructor's zero write. DoStartup maps the inherited
  // building category to a concrete industry unit type at +0xa4.
  int unresolvedZeroA0;
  short selectedIndustryUnitTypeA4;
  short padA6; // +0xa6

  TIndustryView();
};

ASSERT_SIZE(TIndustryView, 0xa8);
