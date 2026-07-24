#include "game/city/TUnitOrder.h"

#include <string.h>

#include "game/ui_screens/CString.h"
#include "game/city/TCity.h"
#include "game/military/TCivUnit.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// SYNTHETIC: IMPERIALISM 0x004b6f20
// TUnitOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b6f50
// TUnitOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUnitOrder, TProductionOrder)

// SYNTHETIC: IMPERIALISM 0x004b6f90
// TUnitOrder::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b6fc0
TUnitOrder::~TUnitOrder() {}

// FUNCTION: IMPERIALISM 0x004b6fe0
void TUnitOrder::InitializeCityRecruitmentOrderContext(
    TCity* city, short nEntryId, short nPrimaryInputResourceId, short nPrimaryInputPerUnit,
    short nSecondaryInputResourceId, short nSecondaryInputPerUnit, short nCashCostPerUnit,
    short nWorkforceMode, byte bSpecialistMode) {
  cityField08 = city;
  summaryField0c = city->productionSummary1d8;
  resourceTypeIndex48 = nEntryId;
  quantityField04 = 0;
  memset(trackingSlots10, 0, sizeof(trackingSlots10));
  primaryInputResourceId = nPrimaryInputResourceId;
  primaryInputPerUnit = nPrimaryInputPerUnit;
  secondaryInputResourceId = nSecondaryInputResourceId;
  secondaryInputPerUnit = nSecondaryInputPerUnit;
  accumulatedValue = 0;
  cashCostPerUnit = nCashCostPerUnit;
  field40 = 0;
  field3e = 0;
  workforceMode = nWorkforceMode;
  specialistMode = bSpecialistMode;
}

// FUNCTION: IMPERIALISM 0x004b7080
short TUnitOrder::MaxOrder() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7210
bool TUnitOrder::SetQuantity(short param_1) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7320
void TUnitOrder::FillOrderSheet(OrderSheet* orderSheet, short quantity) {
  this->ResetOrderSheet(orderSheet);
  orderSheet->ForResourceCode(this->primaryInputResourceId) =
      static_cast<short>(this->primaryInputPerUnit * quantity);
  if (this->secondaryInputResourceId >= 0) {
    orderSheet->ForResourceCode(this->secondaryInputResourceId) =
        static_cast<short>(this->secondaryInputPerUnit * quantity);
  }
  if (this->workforceMode == kMediumSkillWorkforceMode) {
    orderSheet->slotByResourceCode[0x17] = quantity;
    return;
  }
  if (this->workforceMode == kHighSkillWorkforceMode) {
    orderSheet->slotByResourceCode[0x18] = quantity;
    return;
  }
  orderSheet->slotByResourceCode[0x3c] = quantity;
}

// Slot 0x0d: commit the pending recruitment delta for this city order. TUnitOrder's base
// override does the real work (subclasses like TPowerPlantOrder override it with a no-op).
// Reads the inherited TProductionOrder recipe fields (quantity/city/resource-type) plus this
// class's specialistMode, then spawns quantityField04 TCivUnit work orders into the city.
// FUNCTION: IMPERIALISM 0x004b73b0
void TUnitOrder::Produce() {
  short pendingDelta = quantityField04;
  TCity* cityContext = cityField08;
  if (pendingDelta <= 0 || cityContext == 0) {
    return;
  }

  CString sharedRefA;
  CString sharedRefB;

  short entryId = resourceTypeIndex48;
  unsigned char specialist = specialistMode;
  TSimMgr* localization = g_pSimMgr;
  if (localization != 0) {
    localization->GetString(static_cast<short>((specialist == 0) ? 0x2718 : 0x2717), entryId,
                            &sharedRefB);
  }

  unsigned char* cityRaw = reinterpret_cast<unsigned char*>(cityContext);
  short* cityQueueBase = reinterpret_cast<short*>(cityRaw + 0x4A);
  cityQueueBase[entryId] = static_cast<short>(cityQueueBase[entryId] + pendingDelta);

  int ownerState = *reinterpret_cast<int*>(cityRaw + 0xAC);
  short ownerNationSlot = 0;
  if (ownerState != 0) {
    ownerNationSlot =
        *reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(ownerState) + 0x0C);
  }

  for (short i = 0; i < pendingDelta; ++i) {
    TCivUnit* orderObject = new TCivUnit();
    if (orderObject == nullptr) {
      continue;
    }

    CivilianUnitKind unitKind = DecodeCivilianUnitKind(entryId);
    orderObject->ICivUnit(unitKind, i, ownerNationSlot);
  }

  quantityField04 = 0;
}

// The store order (0x48, 0x4c, 0x50, 0x4e, 0x52, 0x54, 0x56) follows the original's
// interleaved word moves.
// FUNCTION: IMPERIALISM 0x004b77e0
void TUnitOrder::SetOrderCostProfile(short resourceTypeIndex, short nPrimaryInputResourceId,
                                     short nPrimaryInputPerUnit, short nSecondaryInputResourceId,
                                     short nSecondaryInputPerUnit, short nCashCostPerUnit,
                                     short nWorkforceMode) {
  this->resourceTypeIndex48 = resourceTypeIndex;
  this->primaryInputResourceId = nPrimaryInputResourceId;
  this->primaryInputPerUnit = nPrimaryInputPerUnit;
  this->secondaryInputResourceId = nSecondaryInputResourceId;
  this->secondaryInputPerUnit = nSecondaryInputPerUnit;
  this->cashCostPerUnit = nCashCostPerUnit;
  this->workforceMode = nWorkforceMode;
}

// FUNCTION: IMPERIALISM 0x004b7850
void TUnitOrder::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&resourceTypeIndex48, 2);
  stream->WriteBytesSlot78(&quantityField04, 2);
  stream->WriteBytesSlot78(&field40, 2);
  stream->WriteBytesSlot78(&resourceTypeIndex48, 2);
  stream->WriteBytesSlot78(trackingSlots10, 0x2e);
  stream->WriteBytesSlot78(&accumulatedValue, 4);
  stream->WriteBytesSlot78(&primaryInputResourceId, 2);
  stream->WriteBytesSlot78(&secondaryInputResourceId, 2);
  stream->WriteBytesSlot78(&primaryInputPerUnit, 2);
  stream->WriteBytesSlot78(&secondaryInputPerUnit, 2);
  stream->WriteBytesSlot78(&cashCostPerUnit, 2);
  stream->WriteBytesSlot78(&workforceMode, 2);
  stream->WriteBytesSlot78(&specialistMode, 1);
}

// FUNCTION: IMPERIALISM 0x004b7920
void TUnitOrder::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(&quantityField04, 2);
  stream->ReadBytes(&field40, 2);
  stream->ReadBytes(&resourceTypeIndex48, 2);
  stream->ReadBytes(trackingSlots10, 0x2e);
  stream->ReadBytes(&accumulatedValue, 4);
  stream->ReadBytes(&primaryInputResourceId, 2);
  stream->ReadBytes(&secondaryInputResourceId, 2);
  stream->ReadBytes(&primaryInputPerUnit, 2);
  stream->ReadBytes(&secondaryInputPerUnit, 2);
  stream->ReadBytes(&cashCostPerUnit, 2);
  stream->ReadBytes(&workforceMode, 2);
  stream->ReadBytes(&specialistMode, 1);
}
