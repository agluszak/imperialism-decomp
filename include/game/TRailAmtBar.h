#pragma once

#include "game/TIndustryAmtBar.h"

struct CRuntimeClass;
// VTABLE: IMPERIALISM 0x666558
class TRailAmtBar : public TIndustryAmtBar {
public:
  TRailAmtBar();
  virtual ~TRailAmtBar() override;
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
