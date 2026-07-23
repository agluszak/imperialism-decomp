#pragma once

#include "game/city_ui/TBuildingView.h"
#include "game/mfc.h"

class TUnitOrder;

// VTABLE: IMPERIALISM 0x00651fc0
class TUniversityView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TUniversityView)
  virtual ~TUniversityView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;        // slot 0x07 0x4cbf30
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;    // slot 0x0f 0x004cb8a0
  virtual void Draw(RECT* rectBuffer) override;    // slot 0x44 0x4cbf70
  virtual void DoStartup() override;               // slot 0x75 0x4cace0
  virtual void UpdateFields() override;            // slot 0x76 0x4cbb20
  virtual void SetUnit(short recruitmentCategory); // slot 0x79 0x4cb320

  TUniversityView();

  // Original object size is 0xac. Windows has no accesses in the +0xa0 dword.
  unsigned char paddingA0[4];
  // Selected recruitment category (0-8), written/read as a 16-bit value by
  // DoEvent's commandId 0xa/0xc branches; the upper half of the +0xa4 dword is
  // never touched by either writer, so it's split out rather than declared as int.
  short selectedRecruitmentCategoryA4;
  unsigned char paddingA6[2];
  // Selected city recruitment recipe. SetUnit indexes city94->orderSlotsE4 at
  // recruitmentCategory + 0x22; those entries are TUnitOrder objects, and UpdateFields
  // reads their per-unit paper and cash costs.
  TUnitOrder* selectedRecruitmentOrderA8;
};
