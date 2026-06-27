#include "game/TUnitOrder.h"

#include "game/CString.h"
#include "game/TCivUnit.h"
#include "game/TSimMgr.h"

extern "C" TSimMgr* g_pLocalizationTable;

// FUNCTION: IMPERIALISM 0x004b6f50
CRuntimeClass* TUnitOrder::GetRuntimeClass() const {
  return 0;
}

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
undefined TUnitOrder::FillOrderSheet() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b73b0
undefined TUnitOrder::CommitIfPending() {
  unsigned char* raw = reinterpret_cast<unsigned char*>(this);
  short* pendingDeltaRef = reinterpret_cast<short*>(raw + 0x04);
  short pendingDelta = *pendingDeltaRef;
  void* cityContext = *reinterpret_cast<void**>(raw + 0x08);
  if (pendingDelta <= 0 || cityContext == 0) {
    return 0;
  }

  CString sharedRefA;
  CString sharedRefB;

  short entryId = *reinterpret_cast<short*>(raw + 0x48);
  unsigned char specialistMode = raw[0x58];
  TSimMgr* localization = g_pLocalizationTable;
  if (localization != 0) {
    localization->GetString(static_cast<short>((specialistMode == 0) ? 0x2718 : 0x2717), entryId,
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

    short packedOrderType = static_cast<short>(entryId);
    orderObject->InitializeCivWorkOrderState(packedOrderType, i, ownerNationSlot);
  }

  *pendingDeltaRef = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x004b7850
void TUnitOrder::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x004b7920
void TUnitOrder::ReadFrom(TStream* stream) {}
