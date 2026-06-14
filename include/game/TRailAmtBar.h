#pragma once

#include "game/TIndustryAmtBar.h"

// VTABLE: IMPERIALISM 0x666558
struct CRuntimeClass;
class TRailAmtBar : public TIndustryAmtBar {
public:
  TRailAmtBar();
  virtual ~TRailAmtBar();
  CRuntimeClass* GetRuntimeClass() override;

  void DoPostCreate(struct TDocument* document);
  void DrawAmt();
};
