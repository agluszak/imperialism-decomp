#pragma once

#include "game/city/TProductionOrder.h"
#include "game/mfc.h"

class TStream;
class TCity;

enum eUnitOrderWorkforceMode {
  kLowSkillWorkforceMode = 1,
  kMediumSkillWorkforceMode = 2,
  kHighSkillWorkforceMode = 4
};

// VTABLE: IMPERIALISM 0x0064f8a0
class TUnitOrder : public TProductionOrder {
public:
  DECLARE_DYNCREATE(TUnitOrder)
  // FUNCTION: IMPERIALISM 0x004b6fc0
  virtual ~TUnitOrder() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool SetQuantity(short quantity) override;
  virtual short MaxOrder() override;

  void ReplaceOrder(short resourceTypeIndex, short primaryInputResourceId,
                    short primaryInputPerUnit, short secondaryInputResourceId,
                    short secondaryInputPerUnit, short cashCostPerUnit, short workforceMode);
  virtual void Produce() override;
  virtual void FillOrderSheet(OrderSheet* orderSheet, short quantity) override;
  virtual void IUnitOrder(TCity* city, short nEntryId, short nPrimaryInputResourceId,
                          short nPrimaryInputPerUnit, short nSecondaryInputResourceId,
                          short nSecondaryInputPerUnit, short nCashCostPerUnit,
                          short nWorkforceMode, byte bSpecialistMode);
  short primaryInputResourceId;   // nPrimaryInputResourceId
  short secondaryInputResourceId; // nSecondaryInputResourceId
  short primaryInputPerUnit;      // nPrimaryInputPerUnit
  short secondaryInputPerUnit;    // nSecondaryInputPerUnit
  short cashCostPerUnit;          // nCashCostPerUnit
  short workforceMode;            // serialized eUnitOrderWorkforceMode value
  unsigned char specialistMode;   // bSpecialistMode

  TUnitOrder() {}
};

ASSERT_SIZE(TUnitOrder, 0x5c);
