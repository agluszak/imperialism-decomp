#include "game/tactical_ui/TShipBuildingTask.h"
#include "game/tactical_ui/TTaskList.h"

#include <string.h>

#include "game/city/TCity.h"
#include "game/city/TShipOrder.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
// SYNTHETIC: IMPERIALISM 0x005ae650
// TShipBuildingTask::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ae680
// TShipBuildingTask::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipBuildingTask, TCityTask)

// FUNCTION: IMPERIALISM 0x005ae6a0
TShipBuildingTask::TShipBuildingTask() : TCityTask() {}

// SYNTHETIC: IMPERIALISM 0x005ae6c0
// TShipBuildingTask::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005ae710
void TShipBuildingTask::IShipBuildingTask(short citySlotType, TCity* owner,
                                          short requestedShipType) {
  ownerCity = owner;
  citySlotIndex = citySlotType;
  remainingAttempts = 4;
  requestedAmount = 1;
  alreadyQueuedFlag = 0;
  if (citySlotType == 5) {
    remainingAttempts = 3;
  }
  requestedShipType14 = requestedShipType;
  waitingForShipOrderAdvance16 = 0;
  remainingAttempts += 2;
  serializedTaskKind = 2;
}

// FUNCTION: IMPERIALISM 0x005ae780
bool TShipBuildingTask::Execute(TTaskList* taskList) {
  TShipOrder* shipOrder = ownerCity->shipOrderSlots190[0];

  if (waitingForShipOrderAdvance16 == 0) {
    if (shipOrder->CanMakeProduct()) {
      if (remainingAttempts < 0) {
        remainingAttempts = 1;
      }
      ++remainingAttempts;
      waitingForShipOrderAdvance16 = 1;
      return false;
    }

    short deficits[0x17];
    memset(deficits, 0, sizeof(deficits));
    deficits[8] = static_cast<short>(g_industryActionCostWeightResCode08[requestedShipType14] -
                                     shipOrder->trackingSlots[8]);
    deficits[9] = static_cast<short>(g_industryActionCostWeightResCode09[requestedShipType14] -
                                     shipOrder->trackingSlots[9]);
    deficits[0xb] = static_cast<short>(g_industryActionCostWeightResCode0B[requestedShipType14] -
                                       shipOrder->trackingSlots[0xb]);
    deficits[0x10] = static_cast<short>(g_industryActionCostWeightResCode10[requestedShipType14] -
                                        shipOrder->trackingSlots[0x10]);
    deficits[0xc] = static_cast<short>(g_industryActionCostWeightResCode0C[requestedShipType14] -
                                       shipOrder->trackingSlots[0xc]);
    deficits[3] = static_cast<short>(g_industryActionCostWeightResCode03[requestedShipType14] -
                                     shipOrder->trackingSlots[3]);

    for (short resource = 0; resource < 0x17; ++resource) {
      short deficit = deficits[resource];
      if (deficit > 0) {
        short available = ownerCity->CityStockByType(resource);
        if (available > 0) {
          short consumed = deficit;
          if (available < deficit) {
            consumed = available;
          }
          ownerCity->CityStockByType(resource) = static_cast<short>(available - consumed);
          ownerCity->VerifyStocks();
          shipOrder->trackingSlots[resource] =
              static_cast<short>(shipOrder->trackingSlots[resource] + consumed);
          deficits[resource] = static_cast<short>(deficit - consumed);
        }
      }
    }

    if (alreadyQueuedFlag == 0) {
      for (short resource = 0; resource < 0x17; ++resource) {
        short deficit = deficits[resource];
        if (deficit > 0) {
          TCityTask* task = new TCityTask();
          task->citySlotIndex = resource;
          task->remainingAttempts = 4;
          task->ownerCity = ownerCity;
          task->requestedAmount = deficit;
          task->alreadyQueuedFlag = 0;
          if (resource == 5) {
            task->remainingAttempts = 3;
          }
          task->serializedTaskKind = 1;
          taskList->AddTail(task);
        }
      }
      ++remainingAttempts;
      alreadyQueuedFlag = 1;
      return false;
    }
  } else if (shipOrder->resourceTypeIndex != requestedShipType14) {
    return true;
  }

  ++remainingAttempts;
  return false;
}

// FUNCTION: IMPERIALISM 0x005ae9e0
void TShipBuildingTask::WriteTo(TStream* stream) {
  stream->WriteBytes(&serializedTaskKind, 1);
  TObject::WriteTo(stream);
  stream->WriteBytes(&citySlotIndex, 2);
  stream->WriteBytes(&remainingAttempts, 2);
  stream->WriteBytes(&requestedAmount, 2);
  stream->WriteBytes(&alreadyQueuedFlag, 2);
  stream->WriteBytes(&requestedShipType14, 2);
  stream->WriteBytes(&waitingForShipOrderAdvance16, 2);
}

// FUNCTION: IMPERIALISM 0x005aea70
void TShipBuildingTask::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&citySlotIndex, 2);
  stream->ReadBytes(&remainingAttempts, 2);
  stream->ReadBytes(&requestedAmount, 2);
  stream->ReadBytes(&alreadyQueuedFlag, 2);
  stream->ReadBytes(&requestedShipType14, 2);
  stream->ReadBytes(&waitingForShipOrderAdvance16, 2);
}
