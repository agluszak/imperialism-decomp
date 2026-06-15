#pragma once

#include "game/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  // ~TShipAmtBar is compiler-generated (implicit virtual dtor).
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
