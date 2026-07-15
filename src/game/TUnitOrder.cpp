#include "game/TUnitOrder.h"

#include "game/CString.h"
#include "game/TCivUnit.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x004b6f20
// TUnitOrder::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b6f50
// TUnitOrder::GetRuntimeClass

IMPLEMENT_DYNCREATE(TUnitOrder, TProductionOrder)

TUnitOrder::TUnitOrder() {}

// SYNTHETIC: IMPERIALISM 0x004b6f90
// TUnitOrder::`scalar deleting destructor'
TUnitOrder::~TUnitOrder() {}

// FUNCTION: IMPERIALISM 0x004b6fe0
void TUnitOrder::InitializeCityRecruitmentOrderContext(
    void* pCityState, short nEntryId, short nPrimaryInputResourceId, short nPrimaryInputPerUnit,
    short nSecondaryInputResourceId, short nSecondaryInputPerUnit, short nCashCostPerUnit,
    short nWorkforceMode, byte bSpecialistMode) {}

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
  this->InitializeCityOrderItemWorkingBuffers(orderSheet);
  orderSheet->ForResourceCode(this->primaryInputResourceId) =
      static_cast<short>(this->primaryInputPerUnit * quantity);
  if (this->secondaryInputResourceId >= 0) {
    orderSheet->ForResourceCode(this->secondaryInputResourceId) =
        static_cast<short>(this->secondaryInputPerUnit * quantity);
  }
  if (this->workforceMode == 2) {
    orderSheet->slotByResourceCode[0x17] = quantity;
    return;
  }
  if (this->workforceMode == 4) {
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
undefined TUnitOrder::CommitIfPending() {
  short pendingDelta = quantityField04;
  TCity* cityContext = cityField08;
  if (pendingDelta <= 0 || cityContext == 0) {
    return 0;
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

    short packedOrderType = entryId;
    orderObject->InitializeCivWorkOrderState(packedOrderType, i, ownerNationSlot);
  }

  quantityField04 = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7850
void TUnitOrder::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004b7920
void TUnitOrder::ReadFrom(TStream* stream) {}
