#pragma once

#include "compat.h"
#include "game/civilian_domain_types.h"
#include "game/nation_domain_types.h"
#include "game/ui_core/TView.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x006431b0
class TCivDescription : public TView {
public:
  DECLARE_DYNCREATE(TCivDescription)
  virtual ~TCivDescription() override;

  virtual void Draw(RECT* rectBuffer) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void DrawProspector(RECT* bounds);
  virtual void DrawEngineer(RECT* bounds);
  virtual void DrawDeveloper(RECT* bounds);
  CivilianUnitKindStorage selectedCivilianClass;
  NationSlot ownerNationId;
  short targetTileCountsBySlot[5];
  RECT legendRects[16];

  TCivDescription();

  void UpdateCivilianOrderClassAndRefreshTargetCounts(class TCivUnit* orderState);
  void CountWorkableSpaces(class TCivUnit* selectedOrder);
#ifdef IMPERIALISM_RUNTIME_TESTS
  bool ActivateLegendSlot(short slotIndex);
#endif
};
ASSERT_SIZE(TCivDescription, 0x170);
