#include <string.h>

#include "game/navy/TTaskForce.h"
#include "game/navy/TAdmiral.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/map/TMission.h"

#include "game/ui_core/CIterator.h"
#include "game/core/CString.h"
#include "game/military/TArmyMgr.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/gfx/TResourceMgr.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/map/TZone.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/gfx/ui_invalidation_guard.h"

// Navy order priority uses four category weights over the current entry's
// aggression, nation, and map marker state.

IMPLEMENT_DYNCREATE(TTaskForce, TObject)
// FUNCTION: IMPERIALISM 0x00552800
TTaskForce::TTaskForce(TZone* locationArg, short nationArg)
    : aggression(1), shipOrders(0), target(nullptr), shipList(nullptr), flagship(nullptr),
      location(locationArg), nation(nationArg), previousForce(nullptr), nextForce(nullptr),
      ingotTileIndex(-1) {
  memset(shipCountsByToolbarSlot, 0, sizeof(shipCountsByToolbarSlot));
}

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
    shipList->payload->taskForce = nullptr;
    shipList = shipList->DeleteMapOrderChildLinkAndReturnNext();
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
    Remove(shipList->payload);
  }
  nation = static_cast<short>(nationArg);
  location = contextZone;
}

// FUNCTION: IMPERIALISM 0x00552b90
void TTaskForce::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&aggression, 4);
  stream->WriteBytes(&shipOrders, 4);

  short ownerOrdinal;
  if (shipOrders == 5) {
    short index = 0;
    while (&g_pGlobalMapState->cityScoreTable[index] != static_cast<Province*>(target) &&
           index < 0x180) {
      ++index;
    }
    ownerOrdinal = index;
  } else {
    ownerOrdinal = static_cast<TZone*>(target)->GetContextOrdinalOrInvalid();
  }
  stream->WriteBytes(&ownerOrdinal, 2);

  short contextOrdinal = location->GetContextOrdinalOrInvalid();
  stream->WriteBytes(&contextOrdinal, 2);

  stream->WriteBytes(&nation, 2);
  stream->WriteBytes(&defeated, 1);
  stream->WriteBytes(&ingotTileIndex, 2);

  int childCount = 0;
  TMapOrderChildLinkNode* link = shipList;
  if (link != 0) {
    do {
      ++childCount;
      link = link->next;
    } while (link != 0);
  }
  stream->WriteBytes(&childCount, 2);

  link = shipList;
  while (link != 0) {
    short shipIndex = 0;
    TShip* candidate = g_pNavyPrimaryOrderListHead;
    TShip* target = link->payload;
    if (candidate != 0) {
      while (candidate != target) {
        candidate = candidate->next;
        ++shipIndex;
        if (candidate == 0) {
          break;
        }
      }
    }
    stream->WriteBytes(&shipIndex, 2);
    short activeFlag = link->active;
    stream->WriteBytes(&activeFlag, 2);
    link = link->next;
  }
}

// FUNCTION: IMPERIALISM 0x00552d10
void TTaskForce::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&aggression, 4);
  stream->ReadBytes(&shipOrders, 4);

  short ordinal;
  stream->ReadBytes(&ordinal, 2);
  if (shipOrders == 5) {
    target = &g_pGlobalMapState->cityScoreTable[ordinal];
  } else {
    target = FindMapActionContextByNodeId(ordinal);
  }

  stream->ReadBytes(&ordinal, 2);
  location = FindMapActionContextByNodeId(ordinal);

  stream->ReadBytes(&nation, 2);
  stream->ReadBytes(&defeated, 1);
  stream->ReadBytes(&ingotTileIndex, 2);

  stream->ReadBytes(&ordinal, 2);
  while (ordinal-- != 0) {
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

  bool isActiveNation = nation == g_pSimMgr->GetPlayerCountry();
  if (ingotTileIndex == -1) {
    if (isActiveNation) {
      CreateIngot();
    }
    return;
  }

  bool tileActionClassNonNegative =
      g_pGlobalMapState->terrainStateTable[ingotTileIndex].tileActionState >= 0;
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

  FreeAvailables();

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
void TTaskForce::OrderPatrol(bool useType4) {
  shipOrders = useType4 ? 4 : 3;
  FreeAvailables();

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

// FUNCTION: IMPERIALISM 0x00553270
void TTaskForce::OrderSail(TZone* orderTarget) {
  target = orderTarget;
  shipOrders = 1;
  FreeAvailables();

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
  pContextAnchor->PropagateMapActionContextDistanceLevelsRecursive(-1);

  int minPriority = 10000;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short priority = g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
      if (priority < minPriority) {
        minPriority = priority;
      }
    }
  }

  target = location;

  int iterationBudget = (minPriority < 10000) ? minPriority : 0;
  for (int step = 0; step < iterationBudget; ++step) {
    TZone* current = static_cast<TZone*>(target);
    unsigned int index = 0;
    if (current->primaryNeighbors.Count() > 0) {
      do {
        TZone* candidate = current->primaryNeighbors[index];
        current = static_cast<TZone*>(target);
        if (candidate->distanceLevel < current->distanceLevel) {
          TZone* better = (index < static_cast<unsigned int>(current->primaryNeighbors.Count()))
                              ? current->primaryNeighbors[index]
                              : nullptr;
          target = better;
          break;
        }
        ++index;
      } while (index < static_cast<unsigned int>(current->primaryNeighbors.Count()));
    }
  }

  shipOrders = 1;
  flagship = nullptr;

  for (TMapOrderChildLinkNode* pruneNode = shipList; pruneNode != nullptr;) {
    if (pruneNode->active != 0) {
      pruneNode = pruneNode->next;
      continue;
    }

    TShip* child = pruneNode->payload;
    child->SetTaskForce(nullptr);

    short bucketIndex =
        static_cast<short>(g_NavyOrderResourceDescriptorTable[child->type].ToolbarSlot());
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
  target = orderTarget;
  shipOrders = 6;
  FreeAvailables();

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
  target = orderTarget;
  shipOrders = 5;
  FreeAvailables();

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
    node->active = !(mode == 0 && node->payload->selection != 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553a50
void TTaskForce::DropShips(bool reserveExtraSlot) {
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      // Same node+0x34 overrun documented on Add.
      node->payload->selection = reserveExtraSlot ? 1u : 2u;
    }
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->next) {
    if (ship->location == location && ship->nation == nation && ship->taskForce == 0) {
      Add(ship);
    }
  }

  for (TMapOrderChildLinkNode* recheckNode = shipList; recheckNode != nullptr;
       recheckNode = recheckNode->next) {
    recheckNode->active = recheckNode->payload->selection == 0;
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
  if (this == nullptr || shipCountsByToolbarSlot[0] + shipCountsByToolbarSlot[1] +
                                 shipCountsByToolbarSlot[2] + shipCountsByToolbarSlot[3] ==
                             0) {
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

  TMapOrderChildLinkNode* nextLink = shipList;
  TMapOrderChildLinkNode* prevLink = 0;
  if (nextLink != 0) {
    short nodePriority =
        static_cast<short>(g_NavyOrderResourceDescriptorTable[node->type].ToolbarSlot());
    do {
      if (static_cast<short>(
              g_NavyOrderResourceDescriptorTable[nextLink->payload->type].ToolbarSlot()) >=
          nodePriority) {
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
    FailNilPointerWithAssert(s_SourcePathUNavy, 0x80f);
  }

  if (nextLink == shipList) {
    shipList = newLink;
  }

  flagship = node->Finest(flagship, false);

  short bucketIndex =
      static_cast<short>(g_NavyOrderResourceDescriptorTable[node->type].ToolbarSlot());
  ++shipCountsByToolbarSlot[bucketIndex];

  node->taskForce = this;

  if (this != nullptr) {
    AssertValid();

    node->aggression = aggression;

    short kind = static_cast<short>(shipOrders);
    if (kind != 0 && kind != 7 && kind != 8 && kind != 4) {
      node->selection = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00553d40
void TTaskForce::Remove(TShip* ship) {
  TMapOrderChildLinkNode* matchingLink;
  if (shipList == 0) {
    matchingLink = 0;
  } else if (shipList->payload != ship) {
    matchingLink = shipList->next->FindNodeMatching(ship);
  } else {
    matchingLink = shipList;
  }

  if (matchingLink != 0) {
    if (shipList != 0) {
      if (shipList->payload == ship) {
        shipList = shipList->DeleteMapOrderChildLinkAndReturnNext();
      } else {
        shipList->next->RemoveLinkedOrderNodeByValueRecursive(ship);
      }
    }
    short bucketIndex =
        static_cast<short>(g_NavyOrderResourceDescriptorTable[ship->type].ToolbarSlot());
    --shipCountsByToolbarSlot[bucketIndex];
  }

  if (ship == flagship) {
    ElectFlagship();
  }
  ship->taskForce = 0;
}

// FUNCTION: IMPERIALISM 0x00553e30
void TTaskForce::ElectFlagship() {
  flagship = nullptr;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    flagship = node->payload->Finest(flagship, false);
  }
}

// FUNCTION: IMPERIALISM 0x00553e70
void TTaskForce::Victory(int experienceGain) {
  short shipCount = 0;
  if (this != nullptr) {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      ++shipCount;
    }
  }
  int perShipGain = experienceGain * 3 / shipCount;

  TAdmiral* admiral = nullptr;
  if (this != nullptr && flagship != nullptr) {
    admiral = flagship->admiral;
  }
  if (admiral != nullptr) {
    admiral->Victory(static_cast<short>(experienceGain));
  }

  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    node->payload->Victory(static_cast<short>(perShipGain));
  }
}

// FUNCTION: IMPERIALISM 0x00553f10
void TTaskForce::FreeAvailables() {
  flagship = nullptr;
  TMapOrderChildLinkNode* node = shipList;
  while (node != nullptr) {
    if (node->active == 0) {
      TShip* entry = node->payload;
      entry->taskForce = nullptr;

      short bucketIndex =
          static_cast<short>(g_NavyOrderResourceDescriptorTable[entry->type].ToolbarSlot());
      short* bucketCounter = &shipCountsByToolbarSlot[bucketIndex];
      --*bucketCounter;

      if (node == shipList) {
        shipList = node->next;
      }
      node = node->DeleteMapOrderChildLinkAndReturnNext();
    } else {
      node = node->next;
    }
  }

  flagship = nullptr;
  for (node = shipList; node != nullptr; node = node->next) {
    flagship = node->payload->Finest(flagship, false);
  }
}

// FUNCTION: IMPERIALISM 0x00553fe0
bool TTaskForce::SinkOrSwimShips() {
  TMapOrderChildLinkNode* head = shipList;
  if (head != 0) {
    TShip* headChild = head->payload;
    bool headDefeated = (headChild->strength <= 0);
    if (headDefeated) {
      headChild->taskForce = 0;
      head->payload->Free();

      head = head->DeleteMapOrderChildLinkAndReturnNext();
      head = head->PruneDefeatedMapOrderChildrenAndReturnHead();
    } else {
      head->next->PruneDefeatedMapOrderChildrenAndReturnHead();
    }
  }

  shipList = head;
  flagship = 0;
  TMapOrderChildLinkNode* node;
  for (node = head; node != 0; node = node->next) {
    flagship = node->payload->Finest(flagship, false);
  }

  if (shipList == 0) {
    defeated = 1;
    return true;
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005540b0
void TTaskForce::SubmitOrders(int orderType, void* orderContext) {
  switch (orderType) {
  case 1:
    shipOrders = 1;
    target = orderContext;
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
    target = orderContext;
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
    target = orderContext;
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
        TShip* ship = link->payload;
        ship->SetTaskForce(0);
        short bucketIndex =
            static_cast<short>(g_NavyOrderResourceDescriptorTable[ship->type].ToolbarSlot());
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

// FUNCTION: IMPERIALISM 0x00554300
int TTaskForce::MouseCodeForTarget(TZone* candidate) const {
  TZone* activeContext = location;
  if (candidate == nullptr || activeContext == candidate) {
    return activeContext->QueryPortZoneCapability() ? 0x0c : 1;
  }
  if (!candidate->QueryPortZoneCapability()) {
    return candidate->QueryZoneCapabilityFlagA() ? 0x0f : 1;
  }
  if (candidate->QueryZoneCapabilityFlagD(g_pSimMgr->GetPlayerCountry())) {
    return 0x0d;
  }
  if (candidate->QueryZoneCapabilityFlagE(g_pSimMgr->GetPlayerCountry())) {
    if (candidate->primaryNeighbors[0] == activeContext) {
      return 0x0e;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00554460
char TTaskForce::MouseCodeForTarget(Province* province) const {
  bool stale = g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
      nation, province->ownerNationCode);
  return stale ? 0x10 : 1;
}

// FUNCTION: IMPERIALISM 0x005544a0
bool TTaskForce::IsValidTarget(TZone* candidate) {
  if (candidate == nullptr) {
    return false;
  }

  bool noSelection = (this == nullptr) || shipCountsByToolbarSlot[0] + shipCountsByToolbarSlot[3] +
                                                  shipCountsByToolbarSlot[1] +
                                                  shipCountsByToolbarSlot[2] ==
                                              0;
  if (!noSelection) {
    noSelection = true;
    TMapOrderChildLinkNode* node = shipList;
    while (node != nullptr) {
      if (node->active != 0) {
        noSelection = false;
        break;
      }
      node = node->next;
    }
  }
  if (noSelection) {
    return false;
  }

  unsigned short worstSpeed = 10000;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short speed = g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
      if (speed < static_cast<short>(worstSpeed)) {
        worstSpeed = speed;
      }
    }
  }

  short distance = location->GetCachedMapActionContextDistanceOrRecompute(candidate);
  short movementLimit = worstSpeed != 10000 ? static_cast<short>(worstSpeed) : 0;
  return distance <= movementLimit;
}

// FUNCTION: IMPERIALISM 0x00554590
unsigned int TTaskForce::IsValidTarget(Province* province) {
  if (province == nullptr) {
    return 0;
  }
  bool noneQueued = (this == nullptr) || shipCountsByToolbarSlot[0] + shipCountsByToolbarSlot[1] +
                                                 shipCountsByToolbarSlot[2] +
                                                 shipCountsByToolbarSlot[3] ==
                                             0;
  if (!noneQueued) {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        return province->navyOrderReachable;
      }
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00554620
int TTaskForce::IsPassingThroughPort(TZone* port) const {
  bool isSailOrder = shipOrders == 1;
  return isSailOrder && (location == port || target == port);
}

// FUNCTION: IMPERIALISM 0x00554660
void TTaskForce::CommitToOrders() {
  FreeAvailables();
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
  bool cancelsBeachhead = shipOrders == 5;
  short cityIndex = cancelsBeachhead
                        ? static_cast<short>(static_cast<Province*>(target)->GetIndex())
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
    link->payload->taskForce = 0;
  }

  g_pActiveMapOrderContext->ForgetForce(this);
  TZone* previousContext = location;
  Free();

  if (cancelsBeachhead) {
    g_pMapContextActionManager->ReassessLanding(g_pSimMgr->GetPlayerCountry(), cityIndex);
  }
  g_pViewMgr->mapUberPicture->SetActiveMapOrderEntry(previousContext);
}

// FUNCTION: IMPERIALISM 0x005548e0
void TTaskForce::DemocraticallyDetermineAggressionLevel() {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    sum += node->payload->aggression;
    ++count;
  }
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
  while (
      static_cast<short>(g_NavyOrderResourceDescriptorTable[node->payload->type].ToolbarSlot()) !=
          toolbarSlot ||
      node->active == activeFlag) {
    node = node->next;
    if (node == nullptr) {
      return;
    }
  }
  node->active = activeFlag;
  if (activeFlag != 0) {
    node->payload->selection = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005549a0
void TTaskForce::Select(TShip* ship, bool activeFlag) {
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
    if (activeFlag) {
      ship->selection = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005549f0
int TTaskForce::GetInvasionCapacity() const {
  int capacity = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != 0; node = node->next) {
    TShip* ship = node->payload;
    capacity += ship->strength > 0 ? g_industryActionCostWeightResCode10[ship->type] : 0;
  }
  return capacity;
}

// FUNCTION: IMPERIALISM 0x00554a30
int TTaskForce::GetSelected(short nationClass) const {
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (static_cast<short>(g_NavyOrderResourceDescriptorTable[node->payload->type].ToolbarSlot()) ==
            nationClass &&
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
        g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed() <
            static_cast<int>(minWeight)) {
      minWeight = g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
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
      sum += g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
      ++count;
    }
  }
  if (count != 0) {
    return (sum * 10) / count;
  }
  return 0;
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
    TShip* ship = link->payload;
    ++counts[ship->type];
  }

  for (i = 0; i < 14; ++i) {
    if (counts[i] > 0) {
      CString label;
      FormatLocalizedCommodityCountLabelByIndex(&label, i, static_cast<short>(counts[i]));
      if (*out != g_szEmptyString) {
        *out += g_szListSeparator;
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
  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&unitCountTemplate, 0x2762,
                                                      (childCount != 1) + 0x11);

  g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&terrainOwnerLabel);

  location->AssignZoneDisplayNameToOutputRef(&contextLabel);

  childCountText.Format(g_szDecimalFormat, childCount);

  g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&orderKindLabel, 0x2762,
                                                      static_cast<short>(shipOrders) + 0x13);

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
  *out += contextText + s_szSpaceSeparator;
  contextText = g_szEmptyString;

  switch (static_cast<short>(shipOrders)) {
  case 1:
    *out += "sailing to ";
    static_cast<TZone*>(target)->AssignZoneDisplayNameToOutputRef(&contextText);
    break;
  case 3:
    *out += "patrolling";
    break;
  case 5:
    *out += "invading ";
    contextText = static_cast<Province*>(target)->cityName;
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
    int cityIndex = static_cast<Province*>(target)->GetIndex();
    char ownerNation = g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode;
    if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nation,
                                                                              ownerNation)) {
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

// FUNCTION: IMPERIALISM 0x005551a0
TAdmiral* TTaskForce::GetSeniorOfficer() const {
  if (this != 0 && flagship != 0) {
    return flagship->admiral;
  }
  return 0;
}

// Mac oracle: TTaskForce::GetAuthority(CStr255&) const.
// FUNCTION: IMPERIALISM 0x005551d0
void TTaskForce::GetAuthority(CString* out) const {
  if (this == 0 || flagship == 0) {
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(out, 0x2762, 0xd);
    return;
  }

  CString authorityTemplate;
  CString shipName = flagship->name;
  if (flagship->admiral != 0) {
    CString admiralName = CString(s_szAdmiralPrefix) + flagship->admiral->displayName;
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&authorityTemplate, 0x2762, 0xe);
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(authorityTemplate),
                           static_cast<LPCSTR>(admiralName), static_cast<LPCSTR>(shipName));
  } else {
    g_pResourceMgr->LoadUiStringResourceByGroupAndIndex(&authorityTemplate, 0x2762, 0xf);
    scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(authorityTemplate),
                           static_cast<LPCSTR>(shipName));
  }
}

// FUNCTION: IMPERIALISM 0x00555420
bool TTaskForce::Encounter(TTaskForce* other) {
  const int priorityWeight[3] = {200, 100, 50};
  if (CountShips() == 0) {
    return false;
  }
  if (other == nullptr || other->CountShips() == 0) {
    return false;
  }

  bool shouldAttempt;
  if (shipOrders == 6 || other->shipOrders == 6 || other->shipOrders == 5) {
    shouldAttempt = true;
  } else {
    int sum = 0;
    int count = 0;
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        sum += g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
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
    return false;
  }

  int thisScore = GetBattleStrengthRating();
  int otherScore = other->GetBattleStrengthRating();
  bool resolved;
  if (static_cast<int>(static_cast<short>(thisScore)) * 100 <
      priorityWeight[aggression] * static_cast<int>(static_cast<short>(otherScore))) {
    int otherScore2 = other->GetBattleStrengthRating();
    int thisScore2 = GetBattleStrengthRating();
    if (static_cast<int>(static_cast<short>(otherScore2)) * 100 <
            priorityWeight[other->aggression] * static_cast<int>(static_cast<short>(thisScore2)) ||
        other->defeated != 0) {
      resolved = false;
    } else {
      resolved = (!AttemptToEvade(other));
    }
  } else if (!other->IsAfraidOf(this)) {
    resolved = true;
  } else {
    resolved = (!other->AttemptToEvade(this));
  }

  if (!resolved) {
    return false;
  }
  if (CountShips() == 0 || other->CountShips() == 0) {
    return false;
  }

  if (g_pSimMgr->preferenceValues[1] != 0) {
    if (g_pSimMgr->GetPlayerCountry() == nation || g_pSimMgr->GetPlayerCountry() == other->nation) {
      return true;
    }
  }
  g_pNavyOrderManager->ResolveStrategicBattle(this, other);
  return false;
}

// FUNCTION: IMPERIALISM 0x00555720
bool TTaskForce::TryToSpot(const TTaskForce* other) const {
  short thisShipCount = 0;
  for (TMapOrderChildLinkNode* countNode = shipList; countNode != nullptr;
       countNode = countNode->next) {
    ++thisShipCount;
  }
  if (thisShipCount == 0) {
    return false;
  }
  if (other == nullptr) {
    return false;
  }
  short otherShipCount = 0;
  for (TMapOrderChildLinkNode* otherCountNode = other->shipList; otherCountNode != nullptr;
       otherCountNode = otherCountNode->next) {
    ++otherShipCount;
  }
  if (otherShipCount == 0) {
    return false;
  }
  if (shipOrders == 6 || other->shipOrders == 6 || other->shipOrders == 5) {
    return true;
  }

  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
      ++count;
    }
  }
  short thisAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);
  int otherSum = 0;
  int otherCount = 0;
  for (TMapOrderChildLinkNode* otherNode = other->shipList; otherNode != nullptr;
       otherNode = otherNode->next) {
    if (otherNode->active != 0) {
      otherSum += g_NavyOrderResourceDescriptorTable[otherNode->payload->type].SailingSpeed();
      ++otherCount;
    }
  }
  short otherAverage = (otherCount == 0) ? 0 : static_cast<short>((otherSum * 10) / otherCount);
  short threshold = static_cast<short>(thisAverage - otherAverage + 0x32);
  thisShipCount = 0;
  for (TMapOrderChildLinkNode* recountNode = shipList; recountNode != nullptr;
       recountNode = recountNode->next) {
    ++thisShipCount;
  }
  otherShipCount = 0;
  for (TMapOrderChildLinkNode* otherRecountNode = other->shipList; otherRecountNode != nullptr;
       otherRecountNode = otherRecountNode->next) {
    ++otherShipCount;
  }
  int totalChildren = otherShipCount + thisShipCount;
  if (totalChildren > 10) {
    threshold = static_cast<short>(threshold + (totalChildren - 10));
  }
  int roll = rand();
  return (roll % 100) < threshold;
}

// FUNCTION: IMPERIALISM 0x00555920
bool TTaskForce::ResolveEncounterWith(TTaskForce* other) {
  const int priorityWeight[3] = {200, 100, 50};
  int thisTotal = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    thisTotal += node->payload->GetBattleStrengthRating();
  }
  int otherTotal = 0;
  for (TMapOrderChildLinkNode* otherNode = other->shipList; otherNode != nullptr;
       otherNode = otherNode->next) {
    otherTotal += otherNode->payload->GetBattleStrengthRating();
  }

  if (static_cast<int>(static_cast<short>(thisTotal)) * 100 <
      priorityWeight[aggression] * static_cast<int>(static_cast<short>(otherTotal))) {
    int refreshedOtherTotal = 0;
    for (TMapOrderChildLinkNode* refreshedOtherNodeA = other->shipList;
         refreshedOtherNodeA != nullptr; refreshedOtherNodeA = refreshedOtherNodeA->next) {
      refreshedOtherTotal += refreshedOtherNodeA->payload->GetBattleStrengthRating();
    }
    int thisAggregateScore = GetBattleStrengthRating();
    if (static_cast<int>(static_cast<short>(refreshedOtherTotal)) * 100 <
            priorityWeight[other->aggression] *
                static_cast<int>(static_cast<short>(thisAggregateScore)) ||
        other->defeated != 0) {
      return false;
    }

    unsigned int minWeight = 10000;
    for (TMapOrderChildLinkNode* speedNode = shipList; speedNode != nullptr;
         speedNode = speedNode->next) {
      if (speedNode->active != 0 &&
          g_NavyOrderResourceDescriptorTable[speedNode->payload->type].SailingSpeed() <
              static_cast<int>(minWeight)) {
        minWeight = g_NavyOrderResourceDescriptorTable[speedNode->payload->type].SailingSpeed();
      }
    }
    if (minWeight == 10000) {
      minWeight = 0;
    }
    int threshold = static_cast<int>(minWeight + 5) * 10 - other->GetDeciSpeed();
    if (rand() % 100 < threshold) {
      defeated = 1;
      return false;
    }
    return true;
  }

  int refreshedOtherTotal = 0;
  for (TMapOrderChildLinkNode* refreshedOtherNodeB = other->shipList;
       refreshedOtherNodeB != nullptr; refreshedOtherNodeB = refreshedOtherNodeB->next) {
    refreshedOtherTotal += refreshedOtherNodeB->payload->GetBattleStrengthRating();
  }
  int refreshedThisTotal = 0;
  for (TMapOrderChildLinkNode* refreshedThisNode = shipList; refreshedThisNode != nullptr;
       refreshedThisNode = refreshedThisNode->next) {
    refreshedThisTotal += refreshedThisNode->payload->GetBattleStrengthRating();
  }
  if (static_cast<int>(static_cast<short>(refreshedOtherTotal)) * 100 <
      priorityWeight[other->aggression] *
          static_cast<int>(static_cast<short>(refreshedThisTotal))) {
    unsigned int minWeight = other->GetWorstSpeed();
    int threshold = static_cast<int>(minWeight + 5) * 10 - GetDeciSpeed();
    if (rand() % 100 < threshold) {
      other->defeated = 1;
      return false;
    }
    return true;
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00555c20
bool TTaskForce::AttemptToEvade(const TTaskForce* other) {
  unsigned short minDescriptorWeight = 10000;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short weight = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed());
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
      sum += g_NavyOrderResourceDescriptorTable[otherNode->payload->type].SailingSpeed();
      ++count;
    }
  }
  short otherAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);

  int roll = rand();
  short threshold = static_cast<short>(
      ((minDescriptorWeight != 10000 ? minDescriptorWeight : 0) + 5) * 10 - otherAverage);
  if (threshold <= roll % 100) {
    return false;
  }
  defeated = 1;
  return true;
}

// FUNCTION: IMPERIALISM 0x00555d10
bool TTaskForce::BattleWith(TTaskForce* other, TTaskForce*& unresolvedForce) {
  short thisShipCount = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    ++thisShipCount;
  }
  if (thisShipCount == 0) {
    return false;
  }
  short otherShipCount = 0;
  if (other != nullptr) {
    for (TMapOrderChildLinkNode* otherNode = other->shipList; otherNode != nullptr;
         otherNode = otherNode->next) {
      ++otherShipCount;
    }
  }
  if (otherShipCount == 0) {
    return false;
  }
  if (g_pSimMgr->preferenceValues[1] != 0) {
    if (g_pSimMgr->GetPlayerCountry() == nation || g_pSimMgr->GetPlayerCountry() == other->nation) {
      return true;
    }
  }
  g_pNavyOrderManager->ResolveStrategicBattle(this, other);
  unresolvedForce = 0;
  return false;
}

// FUNCTION: IMPERIALISM 0x00555de0
bool TTaskForce::IsAfraidOf(TTaskForce* other) const {
  const int priorityWeight[3] = {200, 100, 50};
  int thisSum = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    short resourceType = ship->type;
    short strengthBucket = static_cast<short>(ship->experience / 100);
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[resourceType];
    int navyPriorityScore = strengthBucket + descriptor.BattleSpeedDword() * 10 + 5;
    short navyPriorityBucket = static_cast<short>(navyPriorityScore / 10);
    int resolveScore = strengthBucket + descriptor.FirepowerDword() * 10 + 5;
    short resolveBucket = static_cast<short>(resolveScore / 10);
    thisSum +=
        ((navyPriorityBucket + descriptor.BattleRange()) * 100 + resolveBucket + ship->strength) /
        descriptor.Armor();
  }

  int otherSum = 0;
  for (TMapOrderChildLinkNode* otherNode = other->shipList; otherNode != nullptr;
       otherNode = otherNode->next) {
    TShip* ship = otherNode->payload;
    short resourceType = ship->type;
    short strengthBucket = static_cast<short>(ship->experience / 100);
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[resourceType];
    int navyPriorityScore = strengthBucket + descriptor.BattleSpeedDword() * 10 + 5;
    short navyPriorityBucket = static_cast<short>(navyPriorityScore / 10);
    int resolveScore = strengthBucket + descriptor.FirepowerDword() * 10 + 5;
    short resolveBucket = static_cast<short>(resolveScore / 10);
    otherSum +=
        ((navyPriorityBucket + descriptor.BattleRange()) * 100 + resolveBucket + ship->strength) /
        descriptor.Armor();
  }
  return static_cast<int>(static_cast<short>(thisSum)) * 100 <
         priorityWeight[aggression] * static_cast<int>(static_cast<short>(otherSum));
}

// FUNCTION: IMPERIALISM 0x00556010
int TTaskForce::GetBattleStrengthRating() const {
  int total = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    short resourceType = ship->type;
    short strengthBucket = static_cast<short>(ship->experience / 100);
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[resourceType];
    int navyPriorityScore = strengthBucket + descriptor.BattleSpeedDword() * 10 + 5;
    short navyPriorityBucket = static_cast<short>(navyPriorityScore / 10);
    int resolveScore = strengthBucket + descriptor.FirepowerDword() * 10 + 5;
    short resolveBucket = static_cast<short>(resolveScore / 10);
    total +=
        ((navyPriorityBucket + descriptor.BattleRange()) * 100 + resolveBucket + ship->strength) /
        descriptor.Armor();
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00556100
void TTaskForce::CarryOutOrders() {
  if (defeated != 0) {
    return;
  }
  switch (shipOrders) {
  case 1: {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      node->payload->location = static_cast<TZone*>(target);
    }
    return;
  }
  case 5: {
    Province* cityRecord = static_cast<Province*>(target);
    cityRecord->exploredByNationMask |= static_cast<unsigned char>(1 << nation);
    if (g_pSimMgr->multiplayerSessionRole == kSessionRoleHost) {
      int cityIndex = cityRecord->GetIndex();
      g_pGameFlowState->DispatchCityRedrawInvalidateEvent(static_cast<short>(cityIndex));
    }
    break;
  }
  case 8: {
    for (TMapOrderChildLinkNode* node = shipList; node != nullptr; node = node->next) {
      TShip* child = node->payload;
      child->strength = static_cast<s16>(
          child->strength + g_NavyOrderResourceDescriptorTable[child->type].HullPoints() / 4);
      short cap = static_cast<short>(g_NavyOrderResourceDescriptorTable[child->type].HullPoints());
      if (cap < child->strength) {
        child->strength = cap;
      }
    }
    break;
  }
  default:
    if (g_UnknownMapOrderExecutionGuard == 0) {
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUNavy, 0xb78);
    }
    break;
  }
  defeated = 1;
}

// FUNCTION: IMPERIALISM 0x00556240
short TTaskForce::CountSelectedShips() const {
  if (this == 0) {
    return 0;
  }
  short count = 0;
  for (TMapOrderChildLinkNode* node = shipList; node != 0; node = node->next) {
    if (node->active != 0) {
      ++count;
    }
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x00556280
bool TTaskForce::AllShipsSelected() const {
  if (this == 0) {
    return true;
  }
  for (TMapOrderChildLinkNode* node = shipList; node != 0; node = node->next) {
    bool selected = node->payload->selection != 0;
    if (!selected) {
      return false;
    }
  }
  return true;
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

// FUNCTION: IMPERIALISM 0x005562f0
short TTaskForce::CountForcesFromHere() const {
  if (this == 0) {
    return 0;
  }
  int count = 0;
  const TTaskForce* force = this;
  do {
    force = force->nextForce;
    ++count;
  } while (force != 0);
  return static_cast<short>(count);
}

// FUNCTION: IMPERIALISM 0x00556340
TTaskForce* TTaskForce::GetNth(short index) {
  if (index < 0) {
    return 0;
  }
  TTaskForce* force = this;
  while (force != 0 && index != 0) {
    force = force->nextForce;
    --index;
  }
  return force;
}

// FUNCTION: IMPERIALISM 0x00556380
TTaskForce* TTaskForce::GetNationalNth(short nth, short nation) {
  if (nth == -1) {
    return nullptr;
  }

  int nationalIndex = 0;
  for (TTaskForce* force = g_pNavyOrderManager->orderQueueHead; force != nullptr;
       force = force->nextForce) {
    if (force->nation == nation) {
      if (nationalIndex == nth) {
        return force;
      }
      ++nationalIndex;
    }
  }
  return nullptr;
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
  DestroyIngot();
  switch (shipOrders) {
  case 1:
    markerType = 4;
    ingotTileIndex = static_cast<TZone*>(target)->FindNearestActiveSeaContextTileFromOffset216();
    break;
  case 3:
    markerType = 5;
    ingotTileIndex = location->FindNearestActiveSeaContextTileFromOffset216();
    break;
  case 5:
    markerType = 6;
    ingotTileIndex =
        static_cast<short>(location->FindBestCoastalTileForContextAndCityStateByHeuristic(
            static_cast<Province*>(target)));
    break;
  case 6:
    markerType = 2;
    ingotTileIndex = static_cast<TZone*>(target)->FindNearestActiveSeaContextTileFromOffset216();
    break;
  default:
    break;
  }
  if (markerType != -1) {
    g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(ingotTileIndex, markerType);
  }
}

// FUNCTION: IMPERIALISM 0x005564f0
void TTaskForce::DestroyIngot() {
  if (ingotTileIndex != -1) {
    g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(ingotTileIndex, -1);
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
