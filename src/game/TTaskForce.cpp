#include <string.h>

#include "game/TTaskForce.h"
#include "game/TAdmiral.h"
#include "game/TAutoGreatPower.h"
#include "game/TMission.h"

#include "game/CIterator.h"
#include "game/CString.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x00536f70
void TMapOrderChildLinkNode::SetChainActiveFlag(unsigned char flag) {
  for (TMapOrderChildLinkNode* node = this; node != nullptr; node = node->next) {
    node->active = flag;
  }
}

// Sums the four per-category priority contributions (the same category-0..3 blend
// ComputeNavyOrderPriorityContributionPercentByCategory computes over this entry's
// aggression/nation/ingotTileIndex), each scaled by this profile's
// per-category weight row. The original inlines that per-category switch here (as the
// sibling TShip::GetBattleStrengthRating does) rather than calling the shared
// 0x54ff00 helper, so it is reproduced inline to match.

// FUNCTION: IMPERIALISM 0x00552510
TMapOrderChildLinkNode* TMapOrderChildLinkNode::FindNodeMatching(TObject* child_node) {
  if (this == 0) {
    return 0;
  }
  TMapOrderChildLinkNode* node = this;
  while (node->payload != child_node) {
    node = node->next;
    if (node == 0) {
      return 0;
    }
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x00552590
TMapOrderChildLinkNode* TMapOrderChildLinkNode::DeleteMapOrderChildLinkAndReturnNext() {
  TMapOrderChildLinkNode* next_node = this->next;
  if (next_node != 0) {
    next_node->prev = this->prev;
  }
  if (this->prev != 0) {
    this->prev->next = this->next;
  }

  delete this;
  return next_node;
}

// FUNCTION: IMPERIALISM 0x005525d0
TMapOrderChildLinkNode*
TMapOrderChildLinkNode::RemoveLinkedOrderNodeByValueRecursive(TObject* child_node) {
  if (this == 0) {
    return 0;
  }

  if (child_node == this->payload) {
    TMapOrderChildLinkNode* next_node = this->next;
    if (next_node != 0) {
      next_node->prev = this->prev;
    }
    if (this->prev != 0) {
      this->prev->next = this->next;
    }
    delete this;
    return next_node;
  }

  this->next->RemoveLinkedOrderNodeByValueRecursive(child_node);
  return this;
}

// FUNCTION: IMPERIALISM 0x00552650
TMapOrderChildLinkNode* TMapOrderChildLinkNode::CreateLinkedOrderNode(TObject* child_node) {
  TMapOrderChildLinkNode* new_node = new TMapOrderChildLinkNode(child_node, this);
  if (new_node == 0) {
    FailNilPointerWithAssert(s_SourcePathUNavy_006983C8, 0x64e);
  }
  return new_node;
}

// FUNCTION: IMPERIALISM 0x005526e0
TMapOrderChildLinkNode* TMapOrderChildLinkNode::PruneDefeatedMapOrderChildrenAndReturnHead() {
  TMapOrderChildLinkNode* head = this;
  while (head != 0) {
    TShip* child_node = static_cast<TShip*>(head->payload);
    unsigned char headDefeated = (child_node->strength <= 0);
    if (headDefeated != 0) {
      child_node->taskForce = 0;
      static_cast<TShip*>(head->payload)->Free();

      // Manual unlink (the original inlines the DeleteMapOrderChildLinkAndReturnNext
      // steps here rather than calling 0x552590).
      TMapOrderChildLinkNode* next_node = head->next;
      if (next_node != 0) {
        next_node->prev = head->prev;
      }
      if (head->prev != 0) {
        head->prev->next = head->next;
      }
      delete head;
      head = next_node;
    } else {
      // Surviving head: recursively prune the tail (nodes unlink themselves, so
      // the head stays valid) and return it.
      head->next->PruneDefeatedMapOrderChildrenAndReturnHead();
      return head;
    }
  }
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00552770
// TTaskForce::CreateObject

// SYNTHETIC: IMPERIALISM 0x005527e0
// TTaskForce::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTaskForce, TObject)

TTaskForce::TTaskForce()
    : aggression(1), shipOrders(0), target(), shipList(nullptr), flagship(nullptr),
      location(nullptr), nation(-1), previousForce(nullptr), nextForce(nullptr),
      ingotTileIndex(-1) {
  memset(shipCountsByToolbarSlot, 0, sizeof(shipCountsByToolbarSlot));
}

// FUNCTION: IMPERIALISM 0x00552800
TTaskForce::TTaskForce(TZone* locationArg, short nationArg)
    : aggression(1), shipOrders(0), target(), shipList(nullptr), flagship(nullptr),
      location(locationArg), nation(nationArg), previousForce(nullptr), nextForce(nullptr),
      ingotTileIndex(-1) {
  memset(shipCountsByToolbarSlot, 0, sizeof(shipCountsByToolbarSlot));
}

// SYNTHETIC: IMPERIALISM 0x00552870
// TTaskForce::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005528a0
TTaskForce::~TTaskForce() {}

// FUNCTION: IMPERIALISM 0x005528c0
void TTaskForce::ITaskForce() {}

// FUNCTION: IMPERIALISM 0x005528e0
void TTaskForce::LinkTo(TTaskForce* prev_node, TTaskForce* next_node) {
  TTaskForce* old_prev_node = previousForce;
  TTaskForce* old_next_node = nextForce;

  if (old_prev_node != 0) {
    old_prev_node->nextForce = old_next_node;
  }
  if (old_next_node != 0) {
    old_next_node->previousForce = old_prev_node;
  }

  previousForce = prev_node;
  nextForce = next_node;

  if (prev_node != 0) {
    prev_node->nextForce = this;
  }
  if (nextForce != 0) {
    nextForce->previousForce = this;
  }
}

// FUNCTION: IMPERIALISM 0x00552930
void TTaskForce::Free() {
  while (shipList != nullptr) {
    static_cast<TShip*>(shipList->payload)->taskForce = nullptr;

    TMapOrderChildLinkNode* next = shipList->next;
    if (next != nullptr) {
      next->prev = shipList->prev;
    }
    if (shipList->prev != nullptr) {
      shipList->prev->next = next;
    }
    delete shipList;
    shipList = next;
  }

  // Unlink from the global task-force queue (g_pNavyOrderManager->orderQueueHead).
  if (g_pNavyOrderManager->orderQueueHead == this) {
    g_pNavyOrderManager->orderQueueHead = nextForce;
  }
  if (previousForce != nullptr) {
    previousForce->nextForce = nextForce;
  }
  if (nextForce != nullptr) {
    nextForce->previousForce = previousForce;
  }
  previousForce = nullptr;
  nextForce = nullptr;

  g_pActiveMapOrderContext->ForgetForce(this);

  TGreatPower* nationState = g_apNationStates[nation];
  if (nationState != nullptr && nationState->IsKindOf(RUNTIME_CLASS(TAutoGreatPower))) {
    TAutoGreatPower* autoNation = static_cast<TAutoGreatPower*>(nationState);
    CIterator missionIter(autoNation->missionQueue);
    for (TMission* mission = static_cast<TMission*>(missionIter.Reset()); missionIter.More();
         mission = static_cast<TMission*>(missionIter.Advance())) {
      mission->ForgetTaskForce(this);
    }
  }

  delete this;
}

// Mac oracle: TTaskForce::RegainVirginity(int, TZone*).
// FUNCTION: IMPERIALISM 0x00552a70
void TTaskForce::RegainVirginity(int nationArg, TZone* contextZone) {
  while (shipList != 0) {
    Remove(static_cast<TShip*>(shipList->payload));
  }
  nation = static_cast<short>(nationArg);
  location = contextZone;
}

// FUNCTION: IMPERIALISM 0x00552b90
void TTaskForce::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&aggression, 4);
  stream->WriteBytesSlot78(&shipOrders, 4);

  short ownerOrdinal;
  if (shipOrders == 5) {
    short index = 0;
    while (&g_pGlobalMapState->cityScoreTable[index] != target.asProvince && index < 0x180) {
      ++index;
    }
    ownerOrdinal = index;
  } else {
    ownerOrdinal = target.asZone->GetContextOrdinalOrInvalid();
  }
  stream->WriteBytesSlot78(&ownerOrdinal, 2);

  short contextOrdinal = location->GetContextOrdinalOrInvalid();
  stream->WriteBytesSlot78(&contextOrdinal, 2);

  stream->WriteBytesSlot78(&nation, 2);
  stream->WriteBytesSlot78(&defeated, 1);
  stream->WriteBytesSlot78(&ingotTileIndex, 2);

  int childCount = 0;
  TMapOrderChildLinkNode* link = shipList;
  if (link != 0) {
    do {
      ++childCount;
      link = link->next;
    } while (link != 0);
  }
  stream->WriteBytesSlot78(&childCount, 2);

  link = shipList;
  while (link != 0) {
    short shipIndex = 0;
    TShip* candidate = g_pNavyPrimaryOrderListHead;
    TShip* target = static_cast<TShip*>(link->payload);
    if (candidate != 0) {
      while (candidate != target) {
        candidate = candidate->next;
        ++shipIndex;
        if (candidate == 0) {
          break;
        }
      }
    }
    stream->WriteBytesSlot78(&shipIndex, 2);
    short activeFlag = link->active;
    stream->WriteBytesSlot78(&activeFlag, 2);
    link = link->next;
  }
}

// FUNCTION: IMPERIALISM 0x00552d10
void TTaskForce::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&aggression, 4);
  stream->ReadBytes(&shipOrders, 4);

  short ownerOrdinal;
  stream->ReadBytes(&ownerOrdinal, 2);
  if (shipOrders == 5) {
    target.asProvince = &g_pGlobalMapState->cityScoreTable[ownerOrdinal];
  } else {
    target.asZone = FindMapActionContextByNodeId(ownerOrdinal);
  }

  short contextOrdinal;
  stream->ReadBytes(&contextOrdinal, 2);
  location = FindMapActionContextByNodeId(contextOrdinal);

  stream->ReadBytes(&nation, 2);
  stream->ReadBytes(&defeated, 1);
  stream->ReadBytes(&ingotTileIndex, 2);

  short childCount;
  stream->ReadBytes(&childCount, 2);
  for (short remaining = childCount; remaining != 0; --remaining) {
    short shipIndex;
    stream->ReadBytes(&shipIndex, 2);
    short activeByte;
    stream->ReadBytes(&activeByte, 2);

    TShip* ship = g_pNavyPrimaryOrderListHead;
    if (ship != 0) {
      for (short walk = shipIndex; walk != 0; --walk) {
        ship = ship->next;
        if (ship == 0) {
          break;
        }
      }
    }

    if (g_nSaveFormatVersion >= 0x11 || ship->taskForce == 0) {
      Add(ship);
      TMapOrderChildLinkNode* node = shipList;
      if (node != 0 && node->payload != ship) {
        node = node->next->FindNodeMatching(ship);
      }
      if (node != 0) {
        node->active = activeByte;
        if (activeByte != 0) {
          ship->selection = 0;
        }
      }
    }
  }

  bool isActiveNation = nation == g_pSimMgr->GetActiveNationId();
  if (ingotTileIndex == -1) {
    if (isActiveNation) {
      CreateIngot();
    }
    return;
  }

  bool tileActionClassNonNegative =
      g_pGlobalMapState->terrainStateTable[ingotTileIndex].tileActionState16 >= 0;
  if (!isActiveNation) {
    ingotTileIndex = -1;
    return;
  }
  if (!tileActionClassNonNegative) {
    CreateIngot();
  }
}

// FUNCTION: IMPERIALISM 0x00552f60
void TTaskForce::SetAggression(int value) {
  aggression = value;
}

// FUNCTION: IMPERIALISM 0x00552f80
void TTaskForce::OrderEvade() {
  shipOrders = 9;

  for (TMapOrderChildLinkNode* node = shipList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->taskForce = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->type].enabledFlagOrBucketOffset);
    short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
    --*bucketCounter;

    if (node == shipList) {
      shipList = node->next;
    }

    TMapOrderChildLinkNode* next = node->next;
    if (next != nullptr) {
      next->prev = node->prev;
    }
    if (node->prev != nullptr) {
      node->prev->next = next;
    }
    delete node;
    node = next;
  }

  ElectFlagship();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderQueueHead;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->nextForce) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = shipList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (previousForce != nullptr) {
      previousForce->nextForce = nextForce;
    }
    if (nextForce != nullptr) {
      nextForce->previousForce = previousForce;
    }
    previousForce = nullptr;
    nextForce = head;
    if (head != nullptr) {
      head->previousForce = this;
    }
    g_pNavyOrderManager->orderQueueHead = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// Sibling of OrderEvade for map-order kind 3/4 (see the header comment).
// FUNCTION: IMPERIALISM 0x005530f0
void TTaskForce::OrderPatrol(unsigned char useType4) {
  shipOrders = (useType4 != 0) ? 4 : 3;
  flagship = nullptr;

  for (TMapOrderChildLinkNode* node = shipList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->taskForce = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->type].enabledFlagOrBucketOffset);
    short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
    --*bucketCounter;

    if (node == shipList) {
      shipList = node->next;
    }

    TMapOrderChildLinkNode* next = node->next;
    if (next != nullptr) {
      next->prev = node->prev;
    }
    if (node->prev != nullptr) {
      node->prev->next = next;
    }
    delete node;
    node = next;
  }

  ElectFlagship();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderQueueHead;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->nextForce) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = shipList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (previousForce != nullptr) {
      previousForce->nextForce = nextForce;
    }
    if (nextForce != nullptr) {
      nextForce->previousForce = previousForce;
    }
    previousForce = nullptr;
    nextForce = head;
    if (head != nullptr) {
      head->previousForce = this;
    }
    g_pNavyOrderManager->orderQueueHead = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// FUNCTION: IMPERIALISM 0x005533f0
void TTaskForce::OrderSailTowards(TZone* pContextAnchor) {
  // Reseed the zone-graph BFS distance levels (TZone::distanceLevel44) from
  // pContextAnchor before using them below to steer the candidate-promotion
  // walk. level == -1 means "start a fresh search" (see
  // TZone::PropagateMapActionContextDistanceLevelsRecursive).
  pContextAnchor->PropagateMapActionContextDistanceLevelsRecursive(-1);

  // Minimum g_NavyOrderResourceDescriptorTable[ship->type].descriptorWeight
  // among *active* (active != 0) children, clamped to the 10000
  // sentinel (no active children).
  int minPriority = 10000;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short priority = g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                           .descriptorWeight;
      if (priority < minPriority) {
        minPriority = priority;
      }
    }
  }

  // This order kind (shipOrders 1) uses the zone member: seed it from the context zone,
  // then walk the zone neighbor graph one hop at a time toward pContextAnchor.
  target.asZone = location;

  int iterationBudget = (minPriority < 10000) ? minPriority : 0;
  for (int step = 0; step < iterationBudget; ++step) {
    // Re-read target.asZone each time it is dereferenced, matching the original's member
    // reload after each ensure-slot call.
    TZone* current = target.asZone;
    unsigned int index = 0;
    if (current->primaryNeighbors.Count() > 0) {
      do {
        TZone* candidate = current->primaryNeighbors[index];
        current = target.asZone;
        if (candidate->distanceLevel44 < current->distanceLevel44) {
          // Walk one hop closer to pContextAnchor: promote this neighbor to
          // be the new owner (re-fetches the slot, matching the original's
          // repeated ensure-slot call rather than reusing `candidate`).
          TZone* better = (index < static_cast<unsigned int>(current->primaryNeighbors.Count()))
                              ? current->primaryNeighbors[index]
                              : nullptr;
          target.asZone = better;
          break;
        }
        ++index;
      } while (index < static_cast<unsigned int>(current->primaryNeighbors.Count()));
    }
  }

  for (TMapOrderChildLinkNode* pruneNode = shipList; pruneNode != nullptr;) {
    if (pruneNode->active != 0) {
      pruneNode = pruneNode->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(pruneNode->payload);
    child->SetTaskForce(nullptr);

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->type].enabledFlagOrBucketOffset);
    short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
    --*bucketCounter;

    if (pruneNode == shipList) {
      shipList = pruneNode->next;
    }
    pruneNode = pruneNode->DeleteMapOrderChildLinkAndReturnNext();
  }

  ElectFlagship();

  AssertValid();

  if (g_pNavyOrderManager->CommitForce(this)) {
    g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
  }
}

// Sibling of OrderEvade for map-order kind 6 (see the header comment).
// FUNCTION: IMPERIALISM 0x005536c0
void TTaskForce::OrderBlockade(TZone* orderTarget) {
  target.asZone = orderTarget;
  shipOrders = 6;
  flagship = nullptr;

  for (TMapOrderChildLinkNode* node = shipList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->taskForce = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->type].enabledFlagOrBucketOffset);
    short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
    --*bucketCounter;

    if (node == shipList) {
      shipList = node->next;
    }

    TMapOrderChildLinkNode* next = node->next;
    if (next != nullptr) {
      next->prev = node->prev;
    }
    if (node->prev != nullptr) {
      node->prev->next = next;
    }
    delete node;
    node = next;
  }

  ElectFlagship();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderQueueHead;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->nextForce) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = shipList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (previousForce != nullptr) {
      previousForce->nextForce = nextForce;
    }
    if (nextForce != nullptr) {
      nextForce->previousForce = previousForce;
    }
    previousForce = nullptr;
    nextForce = head;
    if (head != nullptr) {
      head->previousForce = this;
    }
    g_pNavyOrderManager->orderQueueHead = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// Sibling of OrderBlockade for map-order kind 5 (see the header comment).
// FUNCTION: IMPERIALISM 0x00553840
void TTaskForce::OrderSendInTheMarines(Province* orderTarget) {
  target.asProvince = orderTarget;
  shipOrders = 5;
  flagship = nullptr;

  for (TMapOrderChildLinkNode* node = shipList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->taskForce = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->type].enabledFlagOrBucketOffset);
    short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
    --*bucketCounter;

    if (node == shipList) {
      shipList = node->next;
    }

    TMapOrderChildLinkNode* next = node->next;
    if (next != nullptr) {
      next->prev = node->prev;
    }
    if (node->prev != nullptr) {
      node->prev->next = next;
    }
    delete node;
    node = next;
  }

  ElectFlagship();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderQueueHead;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->nextForce) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = shipList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (previousForce != nullptr) {
      previousForce->nextForce = nextForce;
    }
    if (nextForce != nullptr) {
      nextForce->previousForce = previousForce;
    }
    previousForce = nullptr;
    nextForce = head;
    if (head != nullptr) {
      head->previousForce = this;
    }
    g_pNavyOrderManager->orderQueueHead = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// FUNCTION: IMPERIALISM 0x005539c0
void TTaskForce::MaxOut(unsigned char mode) {
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->next) {
    if (ship->location == location && ship->nation == nation && ship->taskForce == 0) {
      Add(ship);
    }
  }

  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    // Same node+0x34 overrun documented on Add.
    node->active = !(mode == 0 && static_cast<TShip*>(node->payload)->selection != 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553a50
void TTaskForce::DropShips(unsigned char reserveExtraSlot) {
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      // Same node+0x34 overrun documented on Add.
      static_cast<TShip*>(node->payload)->selection = (reserveExtraSlot != 0) ? 1u : 2u;
    }
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->next) {
    if (ship->location == location && ship->nation == nation && ship->taskForce == 0) {
      Add(ship);
    }
  }

  for (TMapOrderChildLinkNode* recheckNode = shipList; recheckNode != nullptr;
       recheckNode = recheckNode->next) {
    recheckNode->active = static_cast<TShip*>(recheckNode->payload)->selection == 0;
  }
}

// FUNCTION: IMPERIALISM 0x00553b10
bool TTaskForce::IsEmpty() const {
  if (this == nullptr) {
    return true;
  }
  return shipCountsByToolbarSlot[0] + shipCountsByToolbarSlot[1] + shipCountsByToolbarSlot[2] +
             shipCountsByToolbarSlot[3] ==
         0;
}

// FUNCTION: IMPERIALISM 0x00553b50
bool TTaskForce::NoSelection() const {
  if (this == nullptr || IsEmpty()) {
    return true;
  }
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00553bc0
void TTaskForce::Add(TShip* node) {
  TMapOrderChildLinkNode* head = shipList;
  TMapOrderChildLinkNode* existingLink;
  if (head == 0) {
    existingLink = 0;
  } else if (head->payload != node) {
    existingLink = head->next->FindNodeMatching(node);
  } else {
    existingLink = head;
  }
  if (existingLink != 0) {
    return;
  }

  // Find the priority-sorted insertion point: the first sibling whose own
  // enabledFlagOrBucketOffset priority is >= node's (table at g_NavyOrder-
  // ResourceDescriptorTable + 0x18, i.e. 0x698108 + 0x18 = 0x698120).
  TMapOrderChildLinkNode* nextLink = shipList;
  TMapOrderChildLinkNode* prevLink = 0;
  if (nextLink != 0) {
    short nodePriority = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[node->type].enabledFlagOrBucketOffset);
    do {
      if (static_cast<short>(
              g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(nextLink->payload)->type]
                  .enabledFlagOrBucketOffset) >= nodePriority) {
        break;
      }
      prevLink = nextLink;
      nextLink = nextLink->next;
    } while (nextLink != 0);
  }

  TMapOrderChildLinkNode* newLink = new TMapOrderChildLinkNode();
  if (newLink != 0) {
    newLink->payload = node;
    newLink->next = nextLink;
    newLink->prev = prevLink;
    newLink->active = 1;
    if (nextLink != 0) {
      nextLink->prev = newLink;
    }
    if (newLink->prev != 0) {
      newLink->prev->next = newLink;
    }
  } else {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUNavy_006983C8, 0x80f);
  }

  if (nextLink == shipList) {
    shipList = newLink;
  }

  flagship = node->Finest(flagship, 0);

  short bucketIndex =
      static_cast<short>(g_NavyOrderResourceDescriptorTable[node->type].enabledFlagOrBucketOffset);
  ++shipCountsByToolbarSlot[bucketIndex];

  node->taskForce = this;

  // Defensive null re-check on `this` (matches the original's own `test edi,edi`
  // before this tail, mirroring the null-safe style already used elsewhere in this
  // class -- e.g. IsEmpty).
  if (this != nullptr) {
    AssertValid();

    // Copies this entry's aggression dword and applies the
    // same ship-order-kind gate TShip::SetTaskForce applies, just
    // with `this` playing the role of that method's `newEntry` argument.
    node->aggression = aggression;

    short kind = static_cast<short>(shipOrders);
    if (kind != 0 && kind != 7 && kind != 8 && kind != 4) {
      node->selection = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00553e30
void TTaskForce::ElectFlagship() {
  flagship = nullptr;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    flagship = static_cast<TShip*>(node->payload)->Finest(flagship, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553f10
void TTaskForce::FreeAvailables() {
  flagship = nullptr;
  TMapOrderChildLinkNode* node = shipList;
  while (node != nullptr) {
    if (node->active == 0) {
      TShip* entry = static_cast<TShip*>(node->payload);
      entry->taskForce = nullptr;

      short bucketIndex = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[entry->type].enabledFlagOrBucketOffset);
      short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
      --*bucketCounter;

      if (node == shipList) {
        shipList = node->next;
      }
      TMapOrderChildLinkNode* next = node->next;
      if (next != nullptr) {
        next->prev = node->prev;
      }
      if (node->prev != nullptr) {
        node->prev->next = node->next;
      }
      delete node;
      node = next;
    } else {
      node = node->next;
    }
  }

  flagship = nullptr;
  for (node = shipList; node != nullptr; node = node->next) {
    flagship = static_cast<TShip*>(node->payload)->Finest(flagship, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553fe0
char TTaskForce::SinkOrSwimShips() {
  TMapOrderChildLinkNode* head = shipList;
  if (head != 0) {
    TShip* headChild = static_cast<TShip*>(head->payload);
    unsigned char headDefeated = (headChild->strength <= 0);
    if (headDefeated != 0) {
      headChild->taskForce = 0;
      static_cast<TShip*>(head->payload)->Free();

      // Unlink the head link node (inlined DeleteMapOrderChildLinkAndReturnNext,
      // same manual unlink TTaskForce::Free uses).
      TMapOrderChildLinkNode* next = head->next;
      if (next != 0) {
        next->prev = head->prev;
      }
      if (head->prev != 0) {
        head->prev->next = head->next;
      }
      delete head;

      head = next->PruneDefeatedMapOrderChildrenAndReturnHead();
    } else {
      head->next->PruneDefeatedMapOrderChildrenAndReturnHead();
    }
  }

  shipList = head;
  flagship = 0;
  TMapOrderChildLinkNode* node;
  for (node = head; node != 0; node = node->next) {
    flagship = static_cast<TShip*>(node->payload)->Finest(flagship, 0);
  }

  if (shipList == 0) {
    defeated = 1;
    return 1;
  }
  return 0;
}

// Mac oracle: TTaskForce::SubmitOrders(eShipOrders, void*). The second argument is
// stored in the shipOrders-keyed target union for order kinds that carry a context.
// FUNCTION: IMPERIALISM 0x005540b0
void TTaskForce::SubmitOrders(int orderType, void* orderContext) {
  switch (orderType) {
  case 1:
    shipOrders = 1;
    target.asZone = static_cast<TZone*>(orderContext);
    FreeAvailables();
    AssertValid();
    if (g_pNavyOrderManager->CommitForce(this)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
    }
    return;

  case 3:
    shipOrders = 3;
    FreeAvailables();
    AssertValid();
    if (g_pNavyOrderManager->CommitForce(this)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
    }
    return;

  case 5: {
    shipOrders = 5;
    target.asProvince = static_cast<Province*>(orderContext);
    FreeAvailables();
    AssertValid();

    TTaskForce* cursor;
    for (cursor = g_pNavyOrderManager->orderQueueHead; cursor != 0; cursor = cursor->nextForce) {
      if (cursor == this) {
        break;
      }
    }

    bool queued;
    if (cursor != 0) {
      queued = true;
    } else if (static_cast<short>(CountShips()) < 1) {
      Free();
      queued = false;
    } else {
      LinkTo(0, g_pNavyOrderManager->orderQueueHead);
      g_pNavyOrderManager->orderQueueHead = this;
      queued = true;
    }
    if (queued) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
    }
    return;
  }

  case 6:
    shipOrders = 6;
    target.asZone = static_cast<TZone*>(orderContext);
    FreeAvailables();
    AssertValid();
    if (g_pNavyOrderManager->CommitForce(this)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
    }
    return;

  case 7:
  case 8: {
    shipOrders = orderType;
    flagship = 0;
    TMapOrderChildLinkNode* link = shipList;
    while (link != 0) {
      if (link->active == 0) {
        TShip* ship = static_cast<TShip*>(link->payload);
        ship->SetTaskForce(0);
        short bucketIndex = static_cast<short>(
            g_NavyOrderResourceDescriptorTable[ship->type].enabledFlagOrBucketOffset);
        --shipCountsByToolbarSlot[bucketIndex];
        if (link == shipList) {
          shipList = link->next;
        }
        link = link->DeleteMapOrderChildLinkAndReturnNext();
      } else {
        link = link->next;
      }
    }
    ElectFlagship();
    AssertValid();
    if (g_pNavyOrderManager->CommitForce(this)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
    }
    return;
  }

  case 9:
    shipOrders = 9;
    FreeAvailables();
    AssertValid();
    if (g_pNavyOrderManager->CommitForce(this)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
    }
    return;
  }
}

// Resolves the action-context map-order command id from the entry's active order context
// (location, a TZone) and a candidate context zone. Returned ids map (in
// DoTileClick) to entry order types: 0x0C->type3, 0x0D->type1,
// 0x0E->type6, 0x0F->type1 (special queue path); 1 is the fallback.
// FUNCTION: IMPERIALISM 0x00554300
int TTaskForce::MouseCodeForTarget(TZone* candidate) const {
  TZone* activeContext = location;
  if (candidate == nullptr || activeContext == candidate) {
    return activeContext->QueryPortZoneCapability() ? 0x0c : 1;
  }
  if (!candidate->QueryPortZoneCapability()) {
    return candidate->QueryZoneCapabilityFlagA() ? 0x0f : 1;
  }
  if (candidate->QueryZoneCapabilityFlagD(g_pSimMgr->GetActiveNationId())) {
    return 0x0d;
  }
  if (candidate->QueryZoneCapabilityFlagE(g_pSimMgr->GetActiveNationId())) {
    if (candidate->primaryNeighbors[0] == activeContext) {
      return 0x0e;
    }
  }
  return 1;
}

// Resolves the province-context map-order command id: DoTileClick
// maps 0x10 -> order type 5, and 1 is the "no command" fallback. Asks the diplomacy
// manager whether this entry's nation and the province's owner nation
// (byte 0) have a stale pair-relation turn stamp.
// FUNCTION: IMPERIALISM 0x00554460
char TTaskForce::MouseCodeForTarget(Province* province) const {
  bool stale = g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
      nation, province->ownerNationCode00);
  return stale ? 0x10 : 1;
}

// True (returns the province's +0xa0 eligibility byte) only when this entry has a
// queued-children region AND an active child link; otherwise 0. Guards a province-context
// command before DoTileClick commits it.
// FUNCTION: IMPERIALISM 0x00554590
unsigned int TTaskForce::IsValidTarget(Province* province) {
  if (province == nullptr) {
    return 0;
  }
  bool noneQueued = (this == nullptr) || IsEmpty();
  if (!noneQueued) {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        return province->navyOrderReachableA0;
      }
    }
  }
  return 0;
}

// Drop every inactive child (returning it to a free agent), recompute the
// preferred active child, then re-insert this entry at the head of the global
// TNavyMgr order queue (freeing it instead when no children survive), and
// finalize it through the active map-order context.
// FUNCTION: IMPERIALISM 0x00554660
void TTaskForce::CommitToOrders() {
  flagship = 0;
  TMapOrderChildLinkNode* node = shipList;
  while (node != 0) {
    if (node->active != 0) {
      node = node->next;
    } else {
      static_cast<TShip*>(node->payload)->taskForce = 0;
      short bucketIndex = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
              .enabledFlagOrBucketOffset);
      short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
      --*bucketCounter;
      if (node == shipList) {
        shipList = node->next;
      }
      // The original open-codes DeleteMapOrderChildLinkAndReturnNext's unlink+free
      // here instead of calling 0x552590.
      TMapOrderChildLinkNode* following = node->next;
      if (following != 0) {
        following->prev = node->prev;
      }
      if (node->prev != 0) {
        node->prev->next = node->next;
      }
      delete node;
      node = following;
    }
  }

  flagship = 0;
  for (node = shipList; node != 0; node = node->next) {
    flagship = static_cast<TShip*>(node->payload)->Finest(flagship, 0);
  }
  AssertValid();

  TNavyMgr* manager = g_pNavyOrderManager;
  TTaskForce* oldHead = manager->orderQueueHead;
  TTaskForce* cursor = oldHead;
  while (cursor != 0) {
    if (cursor == this) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
      return;
    }
    cursor = cursor->nextForce;
  }

  short childCount;
  if (this == 0) {
    childCount = 0;
  } else {
    childCount = 0;
    for (TMapOrderChildLinkNode* countNode = shipList; countNode != 0;
         countNode = countNode->next) {
      ++childCount;
    }
  }
  if (childCount <= 0) {
    Free();
    return;
  }

  if (previousForce != 0) {
    previousForce->nextForce = nextForce;
  }
  if (nextForce != 0) {
    nextForce->previousForce = previousForce;
  }
  previousForce = 0;
  nextForce = oldHead;
  if (oldHead != 0) {
    oldHead->previousForce = this;
  }
  manager->orderQueueHead = this;
  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// Mac oracle: TTaskForce::CancelOrders(unsigned char).
// FUNCTION: IMPERIALISM 0x005547d0
void TTaskForce::CancelOrders(unsigned char cancellationMode) {
  (void)cancellationMode;
  bool cancelsBeachhead = shipOrders == 5;
  short cityIndex = cancelsBeachhead ? static_cast<short>(GetProvinceIndex(target.asProvince))
                                     : static_cast<short>(-1);

  if (g_pNavyOrderManager != 0 && g_pNavyOrderManager->orderQueueHead == this) {
    g_pNavyOrderManager->orderQueueHead = nextForce;
  }
  if (previousForce != 0) {
    previousForce->nextForce = nextForce;
  }
  if (nextForce != 0) {
    nextForce->previousForce = previousForce;
  }
  previousForce = 0;
  nextForce = 0;
  for (TMapOrderChildLinkNode* link = shipList; link != 0; link = link->next) {
    static_cast<TShip*>(link->payload)->taskForce = 0;
  }

  g_pActiveMapOrderContext->ForgetForce(this);
  TZone* previousContext = location;
  Free();

  // The original's beachhead-only tail also revalidates supporting land orders for
  // cityIndex. Cancellation itself must not depend on that secondary UI warning path.
  (void)cancelsBeachhead;
  (void)cityIndex;
  g_pUiRuntimeContext->mapUberPictureF0->SetActiveMapOrderEntry(previousContext);
}

// FUNCTION: IMPERIALISM 0x005548e0
void TTaskForce::DemocraticallyDetermineAggressionLevel() {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    // The original averages the complete cached order-type/strength dword rather
    // than treating the two packed shorts independently.
    sum += static_cast<TShip*>(node->payload)->aggression;
    ++count;
  }
  // The rounded average is written back as one 32-bit store spanning this entry's
  // aggression value (the original writes a dword at +0x04 in each branch).
  if (count != 0) {
    aggression = (count / 2 + sum) / count;
    return;
  }
  aggression = 0;
}

// FUNCTION: IMPERIALISM 0x00554930
void TTaskForce::Select(short toolbarSlot, unsigned char activeFlag) {
  TMapOrderChildLinkNode* node = shipList;
  if (node == nullptr) {
    return;
  }
  while (static_cast<short>(
             g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                 .enabledFlagOrBucketOffset) != toolbarSlot ||
         node->active == activeFlag) {
    node = node->next;
    if (node == nullptr) {
      return;
    }
  }
  node->active = activeFlag;
  if (activeFlag != 0) {
    static_cast<TShip*>(node->payload)->selection = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005549a0
void TTaskForce::Select(TShip* ship, unsigned char activeFlag) {
  TMapOrderChildLinkNode* node;
  if (shipList == nullptr) {
    node = nullptr;
  } else if (shipList->payload == ship) {
    node = shipList;
  } else {
    node = shipList->next->FindNodeMatching(ship);
  }
  if (node != nullptr) {
    node->active = activeFlag;
    if (activeFlag != 0) {
      ship->selection = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00554a30
int TTaskForce::GetSelected(short nationClass) const {
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (static_cast<short>(
            g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                .enabledFlagOrBucketOffset) == nationClass &&
        node->active != 0) {
      ++count;
    }
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x00554a80
unsigned int TTaskForce::GetWorstSpeed() const {
  unsigned int minWeight = 10000;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0 &&
        g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                .descriptorWeight < static_cast<int>(minWeight)) {
      minWeight = g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                      .descriptorWeight;
    }
  }
  return minWeight == 10000 ? 0 : minWeight;
}

// FUNCTION: IMPERIALISM 0x00554ad0
int TTaskForce::GetDeciSpeed() const {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                 .descriptorWeight;
      ++count;
    }
  }
  if (count == 0) {
    return 0;
  }
  return (sum * 10) / count;
}

// Mac oracle: TTaskForce::GetCompositionDescription(CStr255&) const.
// FUNCTION: IMPERIALISM 0x00554b20
void TTaskForce::GetCompositionDescription(CString* out) const {
  *out = g_szEmptyString;

  int counts[14];
  int i;
  for (i = 0; i < 14; ++i) {
    counts[i] = 0;
  }
  for (TMapOrderChildLinkNode* link = shipList; link != 0; link = link->next) {
    TShip* ship = static_cast<TShip*>(link->payload);
    ++counts[ship->type];
  }

  for (i = 0; i < 14; ++i) {
    if (counts[i] > 0) {
      CString label;
      FormatLocalizedCommodityCountLabelByIndex(&label, i, static_cast<short>(counts[i]));
      if (*out != g_szEmptyString) {
        *out += g_szListSeparator_00695760;
      }
      *out += label;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00554c90
void TTaskForce::GetSnooperDescription(CString* out) const {
  int childCount = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    ++childCount;
  }

  CString unitCountTemplate;
  CString terrainOwnerLabel;
  CString contextLabel;
  CString childCountText;
  CString orderKindLabel;

  // Singular/plural unit-count template ("1 <unit>" vs "N <unit>s").
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&unitCountTemplate, 0x2762,
                                                                  (childCount != 1) + 0x11);

  // Nation/terrain name for nation (reused here as a nation slot index; same
  // pattern as TNavyMgr.cpp and BuildMapOrderBattleSideSnapshot).
  g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&terrainOwnerLabel);

  // location is a real TZone* (see TTaskForce.h); slot 0x2c is
  // TZone::AssignZoneDisplayNameToOutputRef.
  location->AssignZoneDisplayNameToOutputRef(&contextLabel);

  childCountText.Format(g_szDecimalFormat, childCount);

  // Order-kind label. The original reads only the low 16 bits of `shipOrders` here
  // (a `movsx ax` load), so truncate through `short` to match exactly.
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
      &orderKindLabel, 0x2762, static_cast<short>(shipOrders) + 0x13);

  scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(unitCountTemplate),
                         static_cast<LPCSTR>(terrainOwnerLabel), static_cast<LPCSTR>(contextLabel),
                         static_cast<LPCSTR>(childCountText), static_cast<LPCSTR>(orderKindLabel));
}

// Mac oracle: TTaskForce::GetGeneralDescription(CStr255&) const.
// FUNCTION: IMPERIALISM 0x00554e70
void TTaskForce::GetGeneralDescription(CString* out) const {
  *out = g_szEmptyString;

  CString contextText;
  *out += " of ";

  int childCount = 0;
  for (TMapOrderChildLinkNode* link = shipList; link != 0; link = link->next) {
    ++childCount;
  }

  contextText.Format(g_szDecimalFormat, childCount);
  *out += contextText + s_szSpaceSeparator_00695794;
  contextText = g_szEmptyString;

  switch (static_cast<short>(shipOrders)) {
  case 1:
    *out += "sailing to ";
    target.asZone->AssignZoneDisplayNameToOutputRef(&contextText);
    break;
  case 3:
    *out += "patrolling";
    break;
  case 5:
    *out += "invading ";
    contextText = target.asProvince->cityNameA4;
    break;
  case 6:
    *out += "blockading";
    break;
  case 7:
    *out += "escorting";
    break;
  default:
    *out += "swabbing the decks";
    break;
  }
  *out += contextText;
}

// Tail-recursive nextForce walk (TNavyMgr::CarryOutOrders' rebuild-head
// pass): null-safe on `this`. An entry with no active children is always pruned
// (Free()'d) regardless of shipOrders. A live entry survives unless shipOrders is
// 0/1/4/7/8, or (shipOrders == 5) its target city's owner nation's diplomacy relation
// stamp with this entry's own nation is out of date -- in both prune cases the walk
// still recurses into nextForce first, then Free()s `this` and returns the recursive
// result (the new chain head with `this` spliced out); the survive case recurses but
// discards that result and returns `this` unchanged.
// FUNCTION: IMPERIALISM 0x00555090
TTaskForce* TTaskForce::RemoveStragglers() {
  if (this == nullptr) {
    return nullptr;
  }

  short childCount = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    ++childCount;
  }

  if (childCount < 1) {
    TTaskForce* result = nextForce->RemoveStragglers();
    Free();
    return result;
  }

  switch (shipOrders) {
  case 0:
  case 1:
  case 4:
  case 7:
  case 8: {
    TTaskForce* result = nextForce->RemoveStragglers();
    Free();
    return result;
  }
  case 5: {
    int cityIndex = GetProvinceIndex(target.asProvince);
    char ownerNation = g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00;
    if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nation, ownerNation) ==
        0) {
      TTaskForce* result = nextForce->RemoveStragglers();
      Free();
      return result;
    }
    break;
  }
  default:
    break;
  }

  {
    nextForce->RemoveStragglers();
    return this;
  }
}

// Mac oracle: TTaskForce::GetAuthority(CStr255&) const.
// FUNCTION: IMPERIALISM 0x005551d0
void TTaskForce::GetAuthority(CString* out) const {
  if (this == 0 || flagship == 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(out, 0x2762, 0xd);
    return;
  }

  CString authorityTemplate;
  CString shipName = flagship->name;
  if (flagship->admiral != 0) {
    CString admiralName = CString(s_szAdmiralPrefix_0069578c) + flagship->admiral->displayName;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&authorityTemplate, 0x2762,
                                                                    0xe);
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(authorityTemplate),
                           static_cast<LPCSTR>(admiralName), static_cast<LPCSTR>(shipName));
  } else {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&authorityTemplate, 0x2762,
                                                                    0xf);
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(authorityTemplate),
                           static_cast<LPCSTR>(shipName));
  }
}

namespace {
// Per-order-type priority weight used by both IsAfraidOf
// and Encounter; indexed by aggression (only 0-2 are
// meaningful -- the original indexes the same 3-entry stack array unconditionally, so an
// out-of-range aggression reads original stack garbage there too).
const int kOrderTypePriorityWeight[3] = {200, 100, 50};
} // namespace

// FUNCTION: IMPERIALISM 0x00555420
bool TTaskForce::Encounter(TTaskForce* other) {
  if (CountShips() == 0) {
    return 0;
  }
  if (other == nullptr || other->CountShips() == 0) {
    return 0;
  }

  bool shouldAttempt;
  if (shipOrders == 6 || other->shipOrders == 6 || other->shipOrders == 5) {
    shouldAttempt = true;
  } else {
    int sum = 0;
    int count = 0;
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                   .descriptorWeight;
        ++count;
      }
    }
    short thisAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);
    short otherAverage = static_cast<short>(other->GetDeciSpeed());
    short threshold = static_cast<short>(thisAverage - otherAverage + 0x32);
    int totalChildren = other->CountShips() + CountShips();
    if (totalChildren > 10) {
      threshold = static_cast<short>(threshold + (totalChildren - 10));
    }
    int roll = rand();
    shouldAttempt = (roll % 100) < threshold;
  }

  if (!shouldAttempt) {
    return 0;
  }

  int thisScore = GetBattleStrengthRating();
  int otherScore = other->GetBattleStrengthRating();
  bool resolved;
  if (thisScore * 100 < kOrderTypePriorityWeight[aggression] * otherScore) {
    int otherScore2 = other->GetBattleStrengthRating();
    int thisScore2 = GetBattleStrengthRating();
    if (otherScore2 * 100 < kOrderTypePriorityWeight[other->aggression] * thisScore2 ||
        other->defeated != 0) {
      resolved = false;
    } else {
      resolved = (AttemptToEvade(other) == 0);
    }
  } else if (other->IsAfraidOf(this) == 0) {
    resolved = true;
  } else {
    resolved = (other->AttemptToEvade(this) == 0);
  }

  if (!resolved) {
    return 0;
  }
  if (CountShips() == 0 || other->CountShips() == 0) {
    return 0;
  }

  if (g_pSimMgr->preferenceValues[3] != 0) {
    if (g_pSimMgr->GetActiveNationId() == nation ||
        g_pSimMgr->GetActiveNationId() == other->nation) {
      return 1;
    }
  }
  g_pNavyOrderManager->ResolveStrategicBattle(this, other);
  return 0;
}

// Standalone sibling of the identical inline "shouldAttempt" computation in
// Encounter: bails if either side has no active
// children; force-attempts for ship-order kinds 5/6; else rolls against a priority-gap
// threshold (childRating average delta + child-count overflow past 10).
// FUNCTION: IMPERIALISM 0x00555720
bool TTaskForce::TryToSpot(const TTaskForce* other) const {
  if (CountShips() == 0) {
    return 0;
  }
  if (other->CountShips() == 0) {
    return 0;
  }
  if (shipOrders == 6 || other->shipOrders == 6 || other->shipOrders == 5) {
    return 1;
  }

  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                 .descriptorWeight;
      ++count;
    }
  }
  short thisAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);
  short otherAverage = static_cast<short>(other->GetDeciSpeed());
  short threshold = static_cast<short>(thisAverage - otherAverage + 0x32);
  int totalChildren = other->CountShips() + CountShips();
  if (totalChildren > 10) {
    threshold = static_cast<short>(threshold + (totalChildren - 10));
  }
  int roll = rand();
  return (roll % 100) < threshold;
}

// FUNCTION: IMPERIALISM 0x00555920
bool TTaskForce::ResolveEncounterWith(TTaskForce* other) {
  int thisTotal = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    thisTotal += static_cast<TShip*>(node->payload)->GetBattleStrengthRating();
  }
  int otherTotal = 0;
  for (TMapOrderChildLinkNode* otherNode = other->shipList; otherNode != nullptr;
       otherNode = otherNode->next) {
    otherTotal += static_cast<TShip*>(otherNode->payload)->GetBattleStrengthRating();
  }

  if (thisTotal * 100 < kOrderTypePriorityWeight[aggression] * otherTotal) {
    int thisAggregateScore = GetBattleStrengthRating();
    if (otherTotal * 100 < kOrderTypePriorityWeight[other->aggression] * thisAggregateScore ||
        other->defeated != 0) {
      return 0;
    }

    unsigned int minWeight = GetWorstSpeed();
    int threshold = static_cast<int>(minWeight + 5) * 10 - other->GetDeciSpeed();
    if (rand() % 100 < threshold) {
      defeated = 1;
      return 0;
    }
    return 1;
  }

  if (otherTotal * 100 < kOrderTypePriorityWeight[other->aggression] * thisTotal) {
    unsigned int minWeight = other->GetWorstSpeed();
    int threshold = static_cast<int>(minWeight + 5) * 10 - GetDeciSpeed();
    if (rand() % 100 < threshold) {
      other->defeated = 1;
      return 0;
    }
    return 1;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00555c20
bool TTaskForce::AttemptToEvade(const TTaskForce* other) {
  unsigned short minDescriptorWeight = 10000;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short weight = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
              .descriptorWeight);
      if (weight < static_cast<short>(minDescriptorWeight)) {
        minDescriptorWeight = static_cast<unsigned short>(weight);
      }
    }
  }

  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* otherNode = other->shipList; otherNode != nullptr;
       otherNode = otherNode->next) {
    if (otherNode->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(otherNode->payload)->type]
                 .descriptorWeight;
      ++count;
    }
  }
  short otherAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);

  int roll = rand();
  short threshold = static_cast<short>(
      ((minDescriptorWeight != 10000 ? minDescriptorWeight : 0) + 5) * 10 - otherAverage);
  if (threshold <= roll % 100) {
    return 0;
  }
  defeated = 1;
  return 1;
}

// FUNCTION: IMPERIALISM 0x00555d10
bool TTaskForce::BattleWith(TTaskForce* other, TTaskForce*& unresolvedForce) {
  if (CountShips() == 0) {
    return 0;
  }
  if (other->CountShips() == 0) {
    return 0;
  }
  if (g_pSimMgr->preferenceValues[3] != 0) {
    if (g_pSimMgr->GetActiveNationId() == nation ||
        g_pSimMgr->GetActiveNationId() == other->nation) {
      return 1;
    }
  }
  g_pNavyOrderManager->ResolveStrategicBattle(this, other);
  unresolvedForce = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00555de0
bool TTaskForce::IsAfraidOf(TTaskForce* other) const {
  int thisSum = GetBattleStrengthRating();
  int otherSum = other->GetBattleStrengthRating();
  return thisSum * 100 < kOrderTypePriorityWeight[aggression] * otherSum;
}

// FUNCTION: IMPERIALISM 0x00556010
int TTaskForce::GetBattleStrengthRating() const {
  int total = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    short resourceType = ship->type;
    short strengthBucket = static_cast<short>(ship->experience / 100);
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[resourceType];
    int navyPriorityScore = strengthBucket + descriptor.navyPriorityWeight * 10 + 5;
    short navyPriorityBucket = static_cast<short>(navyPriorityScore / 10);
    int resolveScore = strengthBucket + descriptor.resolveWeight * 10 + 5;
    short resolveBucket = static_cast<short>(resolveScore / 10);
    total +=
        ((navyPriorityBucket + descriptor.calculateWeight) * 100 + resolveBucket + ship->strength) /
        descriptor.taskForceWeight;
  }
  return total;
}

// Immediate/deferred execution effects for a resolved queue entry (ResolveMapOrderChains-
// ForTurnPhase's tail passes): no-op once already eliminated. Type 1 (target-assignment)
// propagates target.asZone (the context TZone*) into every active child's own location. Type 5
// (province-target) reads target.asProvince and sets the target city's owner-flag bit for its nation
// (nation) and, in single-player mode, invalidates that city's redraw. Type 8
// (progression) advances every active child's strength by a quarter-step toward
// its resource-type's stockCap, clamping at the cap. Any other type asserts (once) that
// g_UnknownMapOrderExecutionGuard_006a3ee0 is set, then falls through like the others to
// mark this entry processed -- except type 1, which returns before that (the original
// never sets defeated on that path).
// FUNCTION: IMPERIALISM 0x00556100
void TTaskForce::CarryOutOrders() {
  if (defeated != 0) {
    return;
  }
  switch (shipOrders) {
  case 1: {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      static_cast<TShip*>(node->payload)->location = target.asZone;
    }
    return;
  }
  case 5: {
    Province* cityRecord = target.asProvince;
    cityRecord->exploredByNationMaskA1 |= static_cast<unsigned char>(1 << nation);
    if (g_pSimMgr->multiplayerSessionRole == 1) {
      int cityIndex = GetProvinceIndex(cityRecord);
      g_pGameFlowState->DispatchCityRedrawInvalidateEvent(static_cast<short>(cityIndex));
    }
    break;
  }
  case 8: {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      TShip* child = static_cast<TShip*>(node->payload);
      short cap = static_cast<short>(g_NavyOrderResourceDescriptorTable[child->type].stockCap);
      child->strength = static_cast<s16>(child->strength + cap / 4);
      if (cap < child->strength) {
        child->strength = cap;
      }
    }
    break;
  }
  default:
    if (g_UnknownMapOrderExecutionGuard_006a3ee0 == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UNavy.cpp", 0xb78);
    }
    break;
  }
  defeated = 1;
}

// FUNCTION: IMPERIALISM 0x005562c0
short TTaskForce::CountShips() const {
  if (this == nullptr) {
    return 0;
  }
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    ++count;
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x005563d0
int TTaskForce::GetNationalIndex() const {
  if (this == nullptr) {
    return -1;
  }
  int rank = 0;
  for (TTaskForce* node = g_pNavyOrderManager->orderQueueHead; node != nullptr;
       node = node->nextForce) {
    if (this == node) {
      return rank;
    }
    if (node->nation == nation) {
      ++rank;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00556410
void TTaskForce::CreateIngot() {
  int markerType = -1;
  // Clear the tile this entry previously marked (same body as DestroyIngot,
  // inlined by the original rather than called).
  if (ingotTileIndex != -1) {
    SetMapTileStateByteAndNotifyObserver(ingotTileIndex, -1);
    ingotTileIndex = -1;
  }
  // `shipOrders` (+0x08) is the order kind; each kind marks a different tile with a
  // different state byte. In these map-order contexts `target`/`location` are the
  // order's zone -- the disassembly dispatches through TZone's tile-search virtuals
  // (FindNearestActiveSeaContextTileFromOffset216 slot 0x4c,
  // FindBestCoastalTileForContextAndCityStateByHeuristic slot 0x54).
  switch (shipOrders) {
  case 1:
    markerType = 4;
    ingotTileIndex = target.asZone->FindNearestActiveSeaContextTileFromOffset216();
    break;
  case 3:
    markerType = 5;
    ingotTileIndex = location->FindNearestActiveSeaContextTileFromOffset216();
    break;
  case 5:
    markerType = 6;
    ingotTileIndex = static_cast<short>(
        location->FindBestCoastalTileForContextAndCityStateByHeuristic(target.asProvince));
    break;
  case 6:
    markerType = 2;
    ingotTileIndex = target.asZone->FindNearestActiveSeaContextTileFromOffset216();
    break;
  default:
    break;
  }
  if (markerType != -1) {
    SetMapTileStateByteAndNotifyObserver(ingotTileIndex, markerType);
  }
}

// FUNCTION: IMPERIALISM 0x005564f0
void TTaskForce::DestroyIngot() {
  if (ingotTileIndex != -1) {
    SetMapTileStateByteAndNotifyObserver(ingotTileIndex, -1);
    ingotTileIndex = -1;
  }
}

// FUNCTION: IMPERIALISM 0x00556820
void TTaskForce::FreeAll() {
  if (this == nullptr) {
    return;
  }
  nextForce->FreeAll();
  Free();
}

// FUNCTION: IMPERIALISM 0x00557870
void TTaskForce::RechargeAll() {
  for (TTaskForce* node = this; node != nullptr; node = node->nextForce) {
    node->defeated = 0;
  }
}
