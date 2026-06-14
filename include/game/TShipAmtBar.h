#pragma once

#include "game/TIndustryAmtBar.h"

// VTABLE: IMPERIALISM 0x666998
struct CRuntimeClass;
class TShipAmtBar : public TIndustryAmtBar {
public:
  TShipAmtBar();
  virtual ~TShipAmtBar() override;
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
