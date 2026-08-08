#include "game/tactical_ui/TCityTask.h"
#include "game/tactical_ui/TTaskList.h"
#include "game/city/TCity.h"
#include "game/nation/TForeignMinister.h"
#include "game/nation/TGreatPower.h"
#include "game/city/TItemOrder.h"
#include "game/core/TStream.h"
#include "game/city/TUnitOrder.h"
#include "game/order_sheet.h"

// SYNTHETIC: IMPERIALISM 0x005adcd0
// TCityTask::CreateObject

// SYNTHETIC: IMPERIALISM 0x005add00
// TCityTask::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCityTask, TTask)

// FUNCTION: IMPERIALISM 0x005add20
TCityTask::TCityTask() {}

// SYNTHETIC: IMPERIALISM 0x005add40
// TCityTask::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005add90
void TCityTask::ICityTask(short citySlotType, TCity* owner, short amount) {
  ownerCity = owner;
  citySlotIndex = citySlotType;
  remainingAttempts = 4;
  requestedAmount = amount;
  alreadyQueuedFlag = 0;
  if (citySlotType == 5) {
    remainingAttempts = 3;
  }
  serializedTaskKind = 1;
}

// Resource-slot tasks use direct transport. Production-slot tasks fill the selected
// order and queue any prerequisite work needed to satisfy the request.
// FUNCTION: IMPERIALISM 0x005adde0
bool TCityTask::Execute(TTaskList* taskList) {
  bool fullySatisfied = true;
  if (citySlotIndex >= 0 && citySlotIndex <= 6) {
    requestedAmount = static_cast<short>(
        requestedAmount - ownerCity->DirectTransport(citySlotIndex, requestedAmount));
    if (requestedAmount > 0) {
      fullySatisfied = false;
    }
    --remainingAttempts;
    if (remainingAttempts == 0) {
      fullySatisfied = true;
    }
  }

  TProductionOrder* order = static_cast<TProductionOrder*>(ownerCity->orderSlotsE4[citySlotIndex]);
  if (order != 0) {
    short maxOrder = order->MaxOrder();
    short headroom = static_cast<short>(maxOrder - order->quantity);
    if (headroom < requestedAmount && order->limitingConstraint == kProductionOrderLimitResources) {
      OrderSheet sheet;
      order->FillOrderSheet(&sheet, requestedAmount);
      for (short i = 0; i < 0x17; ++i) {
        short amount = sheet.slotByResourceCode[i];
        if (amount != 0) {
          ownerCity->DirectTransport(i, amount);
        }
      }
      maxOrder = order->MaxOrder();
      headroom = static_cast<short>(maxOrder - order->quantity);
    }

    if (headroom < requestedAmount) {
      order->SetQuantity(maxOrder);
      requestedAmount = static_cast<short>(requestedAmount - headroom);
      fullySatisfied = false;

      if (citySlotIndex > 7 && citySlotIndex <= 0xc) {
        IncompleteMaterials();
      } else if (citySlotIndex >= 0xd && citySlotIndex <= 0x10) {
        IncompleteGoods(taskList);
      } else if ((citySlotIndex >= 0x35 && citySlotIndex <= 0x3b) || citySlotIndex == 0x33) {
        IncompleteCapacity(taskList);
      } else if ((citySlotIndex >= 0x19 && citySlotIndex <= 0x1c) ||
                 (citySlotIndex >= 0x22 && citySlotIndex <= 0x26)) {
        IncompleteLandUnit(taskList);
      } else if (citySlotIndex >= 0x17 && citySlotIndex <= 0x18) {
        IncompleteTraining(taskList);
      }
    } else {
      order->SetQuantity(static_cast<short>(order->quantity + requestedAmount));
      fullySatisfied = true;
    }

    if (!fullySatisfied && --remainingAttempts == 0) {
      fullySatisfied = true;
    }
  }
  return fullySatisfied;
}

// FUNCTION: IMPERIALISM 0x005ae010
void TCityTask::IncompleteTraining(TTaskList* taskList) {
  TProductionOrder* order = static_cast<TProductionOrder*>(ownerCity->orderSlotsE4[citySlotIndex]);
  order->MaxOrder();
  if (order->limitingConstraint == kProductionOrderLimitResources) {
    short amount = requestedAmount;
    if (citySlotIndex != 0x17) {
      amount = static_cast<short>(amount << 1);
    }
    TCityTask* newTask = new TCityTask();
    newTask->requestedAmount = amount;
    newTask->ownerCity = ownerCity;
    newTask->citySlotIndex = 0xa;
    newTask->alreadyQueuedFlag = 0;
    newTask->serializedTaskKind = 1;
    newTask->remainingAttempts = 1;
    taskList->AddTail(newTask);
    alreadyQueuedFlag = 1;
  }
  if (order->limitingConstraint == kProductionOrderLimitTreasury) {
    ownerCity->ownerNationAc->foreignMinister->PriceCheck();
  }
}

// FUNCTION: IMPERIALISM 0x005ae0e0
void TCityTask::IncompleteCapacity(TTaskList* taskList) {
  TProductionOrder* order = static_cast<TProductionOrder*>(ownerCity->orderSlotsE4[citySlotIndex]);
  order->MaxOrder();
  bool queuedAny = false;
  if (order->limitingConstraint == kProductionOrderLimitResources && alreadyQueuedFlag == 0) {
    short lumberDeficit = static_cast<short>(ownerCity->cityStockLumberC8 - requestedAmount);
    if (lumberDeficit < 0) {
      TCityTask* newTask = new TCityTask();
      newTask->ownerCity = ownerCity;
      newTask->citySlotIndex = 9;
      newTask->remainingAttempts = 4;
      newTask->requestedAmount = static_cast<short>(-lumberDeficit);
      newTask->alreadyQueuedFlag = 0;
      newTask->serializedTaskKind = 1;
      taskList->AddTail(newTask);
      queuedAny = true;
    }

    short steelDeficit = static_cast<short>(ownerCity->cityStockSteelCC - requestedAmount);
    if (steelDeficit < 0) {
      TCityTask* newTask = new TCityTask();
      newTask->ownerCity = ownerCity;
      newTask->citySlotIndex = 0xb;
      newTask->remainingAttempts = 4;
      newTask->requestedAmount = static_cast<short>(-steelDeficit);
      newTask->alreadyQueuedFlag = 0;
      newTask->serializedTaskKind = 1;
      taskList->AddTail(newTask);
      queuedAny = true;
    }

    if (queuedAny) {
      alreadyQueuedFlag = 1;
    }
  }
  ++remainingAttempts;
}

// FUNCTION: IMPERIALISM 0x005ae240
void TCityTask::IncompleteLandUnit(TTaskList* taskList) {
  TUnitOrder* order = static_cast<TUnitOrder*>(ownerCity->orderSlotsE4[citySlotIndex]);
  order->MaxOrder();
  if (order->limitingConstraint != kProductionOrderLimitResources || alreadyQueuedFlag != 0) {
    return;
  }

  short primaryStock = ownerCity->CityStockByType(order->primaryInputResourceId);
  short secondaryStock = 0;
  if (order->secondaryInputResourceId != -1) {
    secondaryStock = ownerCity->CityStockByType(order->secondaryInputResourceId);
  }

  bool queuedAny = false;
  int primaryDeficit = order->primaryInputPerUnit * requestedAmount - primaryStock;
  if (primaryDeficit > 0) {
    TCityTask* newTask = new TCityTask();
    newTask->citySlotIndex = order->primaryInputResourceId;
    newTask->remainingAttempts = 4;
    newTask->ownerCity = ownerCity;
    newTask->requestedAmount = static_cast<short>(primaryDeficit);
    newTask->alreadyQueuedFlag = 0;
    if (order->primaryInputResourceId == 5) {
      newTask->remainingAttempts = 3;
    }
    newTask->serializedTaskKind = 1;
    taskList->AddTail(newTask);
    queuedAny = true;
  }

  int secondaryDeficit = 0;
  if (order->secondaryInputResourceId != -1) {
    secondaryDeficit = order->secondaryInputPerUnit * requestedAmount - secondaryStock;
  }
  if (secondaryDeficit > 0) {
    TCityTask* newTask = new TCityTask();
    newTask->citySlotIndex = order->secondaryInputResourceId;
    newTask->remainingAttempts = 4;
    newTask->ownerCity = ownerCity;
    newTask->requestedAmount = static_cast<short>(secondaryDeficit);
    newTask->alreadyQueuedFlag = 0;
    if (order->secondaryInputResourceId == 5) {
      newTask->remainingAttempts = 3;
    }
    newTask->serializedTaskKind = 1;
    taskList->AddTail(newTask);
    queuedAny = true;
  }

  if (queuedAny) {
    alreadyQueuedFlag = 1;
  }
}

// FUNCTION: IMPERIALISM 0x005ae420
void TCityTask::IncompleteMaterials() {
  TProductionOrder* order = static_cast<TProductionOrder*>(ownerCity->orderSlotsE4[citySlotIndex]);
  TForeignMinister* foreignMinister = ownerCity->ownerNationAc->foreignMinister;

  OrderSheet sheet;
  order->FillOrderSheet(&sheet, requestedAmount);

  for (short i = 0; i < 0x17; ++i) {
    short amount = sheet.slotByResourceCode[i];
    if (amount != 0) {
      foreignMinister->PleaseBuy(i, amount);
      ownerCity->AddTransportRequest(i, amount);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005ae4b0
void TCityTask::IncompleteGoods(TTaskList* taskList) {
  TItemOrder* order = static_cast<TItemOrder*>(ownerCity->orderSlotsE4[citySlotIndex]);
  order->MaxOrder();
  if (order->limitingConstraint == kProductionOrderLimitResources && alreadyQueuedFlag == 0) {
    TCityTask* newTask = new TCityTask();
    newTask->citySlotIndex = order->primaryInputResourceId;
    newTask->remainingAttempts = 4;
    newTask->ownerCity = ownerCity;
    newTask->requestedAmount = static_cast<short>(requestedAmount * 2);
    newTask->alreadyQueuedFlag = 0;
    if (order->primaryInputResourceId == 5) {
      newTask->remainingAttempts = 3;
    }
    newTask->serializedTaskKind = 1;
    taskList->AddTail(newTask);
    alreadyQueuedFlag = 1;
  }
}

// FUNCTION: IMPERIALISM 0x005ae570
void TCityTask::WriteTo(TStream* stream) {
  stream->WriteBytes(&serializedTaskKind, 1);
  TObject::WriteTo(stream);
  stream->WriteBytes(&citySlotIndex, 2);
  stream->WriteBytes(&remainingAttempts, 2);
  stream->WriteBytes(&requestedAmount, 2);
  stream->WriteBytes(&alreadyQueuedFlag, 2);
}

// FUNCTION: IMPERIALISM 0x005ae5e0
void TCityTask::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&citySlotIndex, 2);
  stream->ReadBytes(&remainingAttempts, 2);
  stream->ReadBytes(&requestedAmount, 2);
  stream->ReadBytes(&alreadyQueuedFlag, 2);
}
