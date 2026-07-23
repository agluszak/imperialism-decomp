#pragma once

#include "game/TBuildingView.h"
#include "game/mfc.h"
#include "game/ui_tags_city.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00651b30
class TShipyardView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TShipyardView)
  virtual ~TShipyardView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;      // slot 0x07 0x4c8340
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004c8ac0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4c9150
  virtual void DoStartup() override;            // slot 0x75 0x4c8390
  virtual void UpdateFields() override;         // slot 0x76 0x4c8a50
  // VC5 emits these overloads in reverse declaration order: declaring the short overload
  // first places SetStats(TView*) in original slot 0x79 and SetStats(short) in slot 0x7a.
  virtual void SetStats(short shipType);                          // slot 0x7a 0x4c9a60
  virtual void SetStats(TView* sourceControl);                    // slot 0x79 0x4c9d20
  virtual void GetCostString(CString* output, short actionIndex); // slot 0x7b 0x4c97c0
  // RET-imm evidence (RET 0x4) shows this takes one stack arg -- the imported 0-arg
  // Ghidra prototype undercounted it; DoStartup passes
  // buildQueueSlotValues[0] (sign-extended) as the sole argument.
  virtual void SetShip(short shipType); // slot 0x7c 0x4c8d70

  TShipyardView();

  // Own fields at +0xa0..+0xcc (RTTI m_nObjectSize 0xcc vs TBuildingView's 0xa0).
  // CreateObject (0x4c8200) only re-zeroes inherited
  // TBuildingView::city94/productionView98
  // and installs the vtable -- nothing new is written in this range at construction.
  // Two functions independently prove this range's shape and agree once reconciled:
  // DoStartup (0x4c8390) zeroes an 8-element array per 'but0'-'but7'
  // build-queue slot at +0xa4, then writes an int and a surface pointer at +0xb4/+0xb8;
  // Draw (0x4c9150) reads that same +0xa4 array indexed by
  // selectedRequirementRow (0-7, matching the 8 build-queue slots) as the row's resource
  // type -- one array, two roles, not a conflict. Draw also proves
  // commoditySpriteIds[4]/commodityRequiredAmounts[4] at +0xbc/+0xc4 (loop bound proven:
  // 4 slots, -1 = empty).
  short selectedRequirementRow; // +0xa0
  short selectedStatsRowA2;
  short buildQueueSlotValues[8]; // +0xa4..+0xb3 -- AKA requirementResourceTypeByRow
  int unresolvedZeroB4;          // +0xb4, only DoStartup's zero write is confirmed
  TQuickDrawSurfaceContext*
      iconSurfaceB8; // +0xb8 -- LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x264f)
  short commoditySpriteIds[4];       // +0xbc
  short commodityRequiredAmounts[4]; // +0xc4
};
