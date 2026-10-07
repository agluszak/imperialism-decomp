#pragma once

#include "compat.h"

#include "game/city_ui/TBuildingView.h"
#include "game/mfc.h"

class TUnitOrder;

// VTABLE: IMPERIALISM 0x00651fc0
class TUniversityView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TUniversityView)
  virtual ~TUniversityView() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void DoStartup() override;
  virtual void UpdateFields() override;
  virtual void SetUnit(short recruitmentCategory);

  TUniversityView();

  unsigned char paddingA0[4];
  short selectedRecruitmentCategory;
  TUnitOrder* selectedRecruitmentOrder;
};
ASSERT_SIZE(TUniversityView, 0xac);
