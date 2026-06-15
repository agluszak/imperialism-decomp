#pragma once

#include "game/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666998
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  virtual ~TShipAmtBar() override;
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
