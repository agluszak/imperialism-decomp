#include "game/TNavyMgr.h"

#include "game/TAdmiral.h"
#include "game/TShip.h"
#include "game/TObject.h"

extern "C" TShip* g_pNavyPrimaryOrderListHead;
extern "C" TAdmiral* g_pNavySecondaryOrderListHead;
// SYNTHETIC: IMPERIALISM 0x00556530
// TNavyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00556570
// TNavyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyMgr, TObject)

TNavyMgr::TNavyMgr() : orderListHead04(0) {}

TNavyMgr::~TNavyMgr() {}

void TNavyMgr::Free() {}

void TNavyMgr::WriteTo(TStream* stream) {
  (void)stream;
}

void TNavyMgr::ReadFrom(TStream* stream) {
  (void)stream;
}

static void RemoveMatchingSecondaryOrders(short nationSlot) {
  int* node = reinterpret_cast<int*>(g_pNavySecondaryOrderListHead);
  while (node != 0) {
    int* nextNode = reinterpret_cast<int*>(node[5]);
    if (static_cast<short>(node[1]) == nationSlot) {
      reinterpret_cast<TObject*>(node)->Free();
    }
    node = nextNode;
  }
}

static void RemoveMatchingTaskForceOrders(TNavyMgr* navyManager, short nationSlot) {
  int* node = reinterpret_cast<int*>(navyManager->orderListHead04);
  while (node != 0) {
    int* nextNode = reinterpret_cast<int*>(node[0xb]);
    if (static_cast<short>(node[7]) == nationSlot) {
      reinterpret_cast<TObject*>(node)->Free();
    }
    node = nextNode;
  }
}

// FUNCTION: IMPERIALISM 0x00557170
short TNavyMgr::ComputeAggregateWeightedChildCostForMatchingType5NavyOrders(short nationSlot,
                                                                            void* cityRecordPtr,
                                                                            int filterValue) {
  int total = 0;
  int* node = reinterpret_cast<int*>(orderListHead04);
  while (node != 0) {
    if (static_cast<short>(node[7]) == nationSlot && node[2] == 5 &&
        node[3] == reinterpret_cast<int>(cityRecordPtr) &&
        (filterValue == 0 || node[6] == filterValue)) {
      int sum = 0;
      int* item = reinterpret_cast<int*>(node[4]);
      while (item != 0) {
        TShip* ship = reinterpret_cast<TShip*>(item[0]);
        short contribution = 0;
        if (ship->stockLevel1c > 0) {
          contribution = g_industryActionCostWeightResCode10[ship->resourceType04];
        }
        sum += contribution;
        item = reinterpret_cast<int*>(item[1]);
      }
      total += sum;
    }
    node = reinterpret_cast<int*>(node[0xb]);
  }
  return static_cast<short>(total);
}

// FUNCTION: IMPERIALISM 0x00557210
void TNavyMgr::RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot) {
  if (g_pNavyPrimaryOrderListHead != 0) {
    TShip* node = g_pNavyPrimaryOrderListHead;
    for (;;) {
      TShip* cursor = node;
      if (node->ownerNationSlot14 == nationSlot) {
        cursor = node->nextOlder24;
        node->Free();
        node = cursor;
        if (node != 0) {
          continue;
        }
      }
      if (cursor == 0 || (node = cursor->nextOlder24) == 0) {
        break;
      }
    }
  }

  RemoveMatchingSecondaryOrders(nationSlot);
  RemoveMatchingTaskForceOrders(this, nationSlot);
}
