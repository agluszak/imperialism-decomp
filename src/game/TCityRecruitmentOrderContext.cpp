#include "game/TCityRecruitmentOrderContext.h"

#include "game/CString.h"
#include "game/TCivUnit.h"
#include "game/TSimMgr.h"

extern "C" TSimMgr* g_pLocalizationTable;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// FUNCTION: IMPERIALISM 0x004b73b0
void TCityRecruitmentOrderContext::CommitCityRecruitmentOrderDelta() {
  short pendingDelta = this->pendingDelta;
  if (pendingDelta <= 0 || this->cityContext == 0) {
    return;
  }

  CString sharedRefA;
  CString sharedRefB;

  TSimMgr* localization = g_pLocalizationTable;
  if (localization != 0) {
    localization->GetString(static_cast<short>((this->specialistMode == 0) ? 0x2718 : 0x2717),
                            this->entryId, &sharedRefB);
  }

  short* cityQueueBase =
      reinterpret_cast<short*>(reinterpret_cast<unsigned char*>(this->cityContext) + 0x4A);
  cityQueueBase[this->entryId] = static_cast<short>(cityQueueBase[this->entryId] + pendingDelta);

  int ownerState =
      *reinterpret_cast<int*>(reinterpret_cast<unsigned char*>(this->cityContext) + 0xAC);
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

    short packedOrderType = static_cast<short>(this->entryId);
    orderObject->InitializeCivWorkOrderState(packedOrderType, i, ownerNationSlot);
  }

  this->pendingDelta = 0;
}
