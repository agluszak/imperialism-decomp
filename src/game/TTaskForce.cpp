#include <stdlib.h>

#include "game/TTaskForce.h"
#include "game/TMission.h"

#include "game/CString.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMapMgr.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TMultiplayerMgr.h"
#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/localization_text_helpers.h"
#include "game/ui_invalidation_guard.h"

extern "C" int __cdecl rand(void);

namespace {

// Reproduces TZonePrimaryNeighborStretch::EnsureSlotAllocatedAndReturnPointer's
// (0x00558860) grow-on-access body -- same capacity-doubling realloc primitive
// TZone.cpp's own EnsureSlotAllocatedAndReturnPointer/EnsureCapacityAtLeast use.
// PromoteMapOrderChainAndQueue's candidate-promotion loop below inlines this same
// primitive at its two call sites (verified against the raw listing: two separate
// runs of the doubling-realloc sequence, not a CALL to 0x558860); since that call
// site lives in a different translation unit than TZone.cpp's definition, the
// inline expansion has to be reproduced locally here to match the emitted code.
inline TZone** EnsurePrimaryNeighborSlot(TZonePrimaryNeighborStretch& neighbors,
                                         unsigned int index) {
  if (static_cast<unsigned int>(neighbors.Capacity()) <= index) {
    int wanted = static_cast<int>(index) + 1;
    unsigned int doubledCapacity = static_cast<unsigned int>(wanted * 2);
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grownBuffer = realloc(neighbors.Data(), wanted * 8);
    if (grownBuffer == 0) {
      neighbors.Data() = static_cast<TZone**>(realloc(neighbors.Data(), wanted * 4));
      neighbors.Capacity() = wanted;
    } else {
      neighbors.Data() = static_cast<TZone**>(grownBuffer);
      neighbors.Capacity() = static_cast<int>(doubledCapacity);
    }
  }
  if (static_cast<unsigned int>(neighbors.Count()) <= index) {
    neighbors.Count() = static_cast<int>(index) + 1;
  }
  return neighbors.Data() + index;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00536f70
void TMapOrderChildLinkNode::SetChainActiveFlag(unsigned char flag) {
  for (TMapOrderChildLinkNode* node = this; node != nullptr; node = node->next) {
    node->active = flag;
  }
}

// Sums the four per-category priority contributions (the same category-0..3 blend
// ComputeNavyOrderPriorityContributionPercentByCategory computes over this entry's
// order_type/required_count/tiebreak_strength), each scaled by this profile's
// per-category weight row. The original inlines that per-category switch here (as the
// sibling ComputeMapOrderEntryHeuristicScore does) rather than calling the shared
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
    unsigned char headDefeated = (child_node->stockLevel1c <= 0);
    if (headDefeated != 0) {
      child_node->ownerOrderEntry0c = 0;
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
    : order_type(1), order_strength(0), attachment(0), owner(nullptr), childOrderList(nullptr),
      activeChildEntry(nullptr), contextAnchor(0), required_count(-1), attached_entity(0),
      queue_prev(nullptr), queue_next(nullptr), tiebreak_strength(-1) {}

// FUNCTION: IMPERIALISM 0x00552800
TTaskForce::TTaskForce(int contextAnchorArg, short requiredCountArg)
    : order_type(1), order_strength(0), attachment(0), owner(nullptr), childOrderList(nullptr),
      activeChildEntry(nullptr), contextAnchor(contextAnchorArg), required_count(requiredCountArg),
      attached_entity(0), queue_prev(nullptr), queue_next(nullptr), tiebreak_strength(-1) {}

// SYNTHETIC: IMPERIALISM 0x00552870
// TTaskForce::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005528a0
TTaskForce::~TTaskForce() {}

// FUNCTION: IMPERIALISM 0x005528c0
void TTaskForce::NoOpTaskForceInitSlot() {}

// FUNCTION: IMPERIALISM 0x005528e0
void TTaskForce::RelinkMapOrderQueueNodeBetween(TTaskForce* prev_node, TTaskForce* next_node) {
  TTaskForce* old_prev_node = queue_prev;
  TTaskForce* old_next_node = queue_next;

  if (old_prev_node != 0) {
    old_prev_node->queue_next = old_next_node;
  }
  if (old_next_node != 0) {
    old_next_node->queue_prev = old_prev_node;
  }

  queue_prev = prev_node;
  queue_next = next_node;

  if (prev_node != 0) {
    prev_node->queue_next = this;
  }
  if (queue_next != 0) {
    queue_next->queue_prev = this;
  }
}

// FUNCTION: IMPERIALISM 0x00552930
void TTaskForce::Free() {
  while (childOrderList != nullptr) {
    static_cast<TShip*>(childOrderList->payload)->ownerOrderEntry0c = nullptr;

    TMapOrderChildLinkNode* next = childOrderList->next;
    if (next != nullptr) {
      next->prev = childOrderList->prev;
    }
    if (childOrderList->prev != nullptr) {
      childOrderList->prev->next = next;
    }
    delete childOrderList;
    childOrderList = next;
  }

  // Unlink from the global task-force queue (g_pNavyOrderManager->orderListHead04).
  if (g_pNavyOrderManager->orderListHead04 == this) {
    g_pNavyOrderManager->orderListHead04 = queue_next;
  }
  if (queue_prev != nullptr) {
    queue_prev->queue_next = queue_next;
  }
  if (queue_next != nullptr) {
    queue_next->queue_prev = queue_prev;
  }
  queue_prev = nullptr;
  queue_next = nullptr;

  // TODO: promote body -- 0x5529a8-0x552a18 notifies g_pActiveMapOrderContext
  // (TOcean) and then walks a CObList/CPtrList of observers keyed by an
  // unrecovered global array indexed by required_count (IsKindOf-gated
  // dispatch through a vtable slot 0x90 call); not yet recovered, see bd
  // 1uj.16 follow-up notes.

  delete this;
}

// FUNCTION: IMPERIALISM 0x00552a70
void TTaskForce::RemoveTaskForceOrderNodesByNationAndClearSelectionState(int nation,
                                                                         TZone* contextZone) {
  (void)nation;
  (void)contextZone;
}

// FUNCTION: IMPERIALISM 0x00552b90
void TTaskForce::WriteTo(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00552d10
void TTaskForce::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x00552f60
void TTaskForce::ResetOrderTypeAndStrengthDword(int packedValue) {
  *reinterpret_cast<int*>(&order_type) = packedValue;
}

// FUNCTION: IMPERIALISM 0x00552f80
void TTaskForce::SetMapOrderType9AndQueue() {
  attachment = 9;

  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->ownerOrderEntry0c = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->resourceType04].enabledFlagOrBucketOffset);
    short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
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

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderListHead04;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->queue_next) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = childOrderList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (queue_prev != nullptr) {
      queue_prev->queue_next = queue_next;
    }
    if (queue_next != nullptr) {
      queue_next->queue_prev = queue_prev;
    }
    queue_prev = nullptr;
    queue_next = head;
    if (head != nullptr) {
      head->queue_prev = this;
    }
    g_pNavyOrderManager->orderListHead04 = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// Sibling of SetMapOrderType9AndQueue for map-order kind 3/4 (see the header comment).
// FUNCTION: IMPERIALISM 0x005530f0
void TTaskForce::SetMapOrderType3Or4AndQueue(char fUseType4) {
  attachment = (fUseType4 != 0) ? 4 : 3;
  activeChildEntry = nullptr;

  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->ownerOrderEntry0c = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->resourceType04].enabledFlagOrBucketOffset);
    short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
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

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderListHead04;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->queue_next) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = childOrderList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (queue_prev != nullptr) {
      queue_prev->queue_next = queue_next;
    }
    if (queue_next != nullptr) {
      queue_next->queue_prev = queue_prev;
    }
    queue_prev = nullptr;
    queue_next = head;
    if (head != nullptr) {
      head->queue_prev = this;
    }
    g_pNavyOrderManager->orderListHead04 = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// FUNCTION: IMPERIALISM 0x005533f0
void TTaskForce::PromoteMapOrderChainAndQueue(TZone* pContextAnchor) {
  // Reseed the zone-graph BFS distance levels (TZone::distanceLevel44) from
  // pContextAnchor before using them below to steer the candidate-promotion
  // walk. level == -1 means "start a fresh search" (see
  // TZone::PropagateMapActionContextDistanceLevelsRecursive).
  pContextAnchor->PropagateMapActionContextDistanceLevelsRecursive(-1);

  // Minimum g_NavyOrderResourceDescriptorTable[order_type].descriptorWeight
  // among *active* (active != 0) children, clamped to the 10000
  // sentinel (no active children).
  int minPriority = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short priority =
          g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
              .descriptorWeight;
      if (priority < minPriority) {
        minPriority = priority;
      }
    }
  }

  owner = reinterpret_cast<TTaskForce*>(contextAnchor);

  int iterationBudget = (minPriority < 10000) ? minPriority : 0;
  for (int step = 0; step < iterationBudget; ++step) {
    // `owner` is TTaskForce* (its declared field type -- genuinely polymorphic
    // per call site, see the owner field comment in TTaskForce.h), but here it
    // is TZone* shaped (bd 1uj.47.2 evidence); read fresh each time it is
    // dereferenced below, matching the original's member reload after each
    // ensure-slot call.
    TZone* current = reinterpret_cast<TZone*>(owner);
    unsigned int index = 0;
    if (current->primaryNeighbors.Count() > 0) {
      do {
        TZone* candidate = *EnsurePrimaryNeighborSlot(current->primaryNeighbors, index);
        current = reinterpret_cast<TZone*>(owner);
        if (candidate->distanceLevel44 < current->distanceLevel44) {
          // Walk one hop closer to pContextAnchor: promote this neighbor to
          // be the new owner (re-fetches the slot, matching the original's
          // repeated ensure-slot call rather than reusing `candidate`).
          TZone* better = (index < static_cast<unsigned int>(current->primaryNeighbors.Count()))
                              ? *EnsurePrimaryNeighborSlot(current->primaryNeighbors, index)
                              : nullptr;
          owner = reinterpret_cast<TTaskForce*>(better);
          break;
        }
        ++index;
      } while (index < static_cast<unsigned int>(current->primaryNeighbors.Count()));
    }
  }

  for (TMapOrderChildLinkNode* pruneNode = childOrderList; pruneNode != nullptr;) {
    if (pruneNode->active != 0) {
      pruneNode = pruneNode->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(pruneNode->payload);
    child->SetOwnerOrderEntryAndCacheType(nullptr);

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->resourceType04].enabledFlagOrBucketOffset);
    short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
    --*bucketCounter;

    if (pruneNode == childOrderList) {
      childOrderList = pruneNode->next;
    }
    pruneNode = pruneNode->DeleteMapOrderChildLinkAndReturnNext();
  }

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(this)) {
    g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
  }
}

// Sibling of SetMapOrderType9AndQueue for map-order kind 6 (see the header comment).
// FUNCTION: IMPERIALISM 0x005536c0
void TTaskForce::SetMapOrderType6AndQueue(int nOrderTarget) {
  owner = reinterpret_cast<TTaskForce*>(nOrderTarget);
  attachment = 6;
  activeChildEntry = nullptr;

  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->ownerOrderEntry0c = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->resourceType04].enabledFlagOrBucketOffset);
    short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
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

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderListHead04;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->queue_next) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = childOrderList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (queue_prev != nullptr) {
      queue_prev->queue_next = queue_next;
    }
    if (queue_next != nullptr) {
      queue_next->queue_prev = queue_prev;
    }
    queue_prev = nullptr;
    queue_next = head;
    if (head != nullptr) {
      head->queue_prev = this;
    }
    g_pNavyOrderManager->orderListHead04 = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// Sibling of SetMapOrderType6AndQueue for map-order kind 5 (see the header comment).
// FUNCTION: IMPERIALISM 0x00553840
void TTaskForce::SetMapOrderType5AndQueue(int nOrderTarget) {
  owner = reinterpret_cast<TTaskForce*>(nOrderTarget);
  attachment = 5;
  activeChildEntry = nullptr;

  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr;) {
    if (node->active != 0) {
      node = node->next;
      continue;
    }

    TShip* child = static_cast<TShip*>(node->payload);
    child->ownerOrderEntry0c = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->resourceType04].enabledFlagOrBucketOffset);
    short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
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

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  TTaskForce* head = g_pNavyOrderManager->orderListHead04;
  bool alreadyQueued = false;
  for (TTaskForce* queuedEntry = head; queuedEntry != nullptr;
       queuedEntry = queuedEntry->queue_next) {
    if (queuedEntry == this) {
      alreadyQueued = true;
      break;
    }
  }

  if (!alreadyQueued) {
    int childCount = 0;
    for (TMapOrderChildLinkNode* countNode = childOrderList; countNode != nullptr;
         countNode = countNode->next) {
      ++childCount;
    }

    if (childCount <= 0) {
      Free();
      return;
    }

    if (queue_prev != nullptr) {
      queue_prev->queue_next = queue_next;
    }
    if (queue_next != nullptr) {
      queue_next->queue_prev = queue_prev;
    }
    queue_prev = nullptr;
    queue_next = head;
    if (head != nullptr) {
      head->queue_prev = this;
    }
    g_pNavyOrderManager->orderListHead04 = this;
  }

  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// TODO: port body @ 0x005539c0 (recomputes this task force's per-order selection flags
// for the active nation's current orders).

// FUNCTION: IMPERIALISM 0x005539c0
void TTaskForce::RefreshTaskForceSelectionFlagsForCurrentNationOrders(int mode) {
  (void)mode;
}

// FUNCTION: IMPERIALISM 0x00553a50
void TTaskForce::ApplyTaskForceSelectionModeForCurrentNationOrders(char reserveExtraSlot) {
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      // Same node+0x34 overrun documented on FindOrCreateChildOrderLink.
      static_cast<TShip*>(node->payload)->field34 = (reserveExtraSlot != 0) ? 1u : 2u;
    }
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->nextOlder24) {
    if (reinterpret_cast<int>(ship->field08) == contextAnchor &&
        ship->ownerNationSlot14 == required_count && ship->ownerOrderEntry0c == 0) {
      FindOrCreateChildOrderLink(ship);
    }
  }

  for (TMapOrderChildLinkNode* recheckNode = childOrderList; recheckNode != nullptr;
       recheckNode = recheckNode->next) {
    recheckNode->active = static_cast<TShip*>(recheckNode->payload)->field34 == 0;
  }
}

// FUNCTION: IMPERIALISM 0x00553b10
bool TTaskForce::HasNoMapOrderEntryChildrenQueued() {
  if (this == nullptr) {
    return true;
  }
  const short* words = reinterpret_cast<const short*>(reinterpret_cast<const char*>(this) + 0x1e);
  return (words[0] + words[1] + words[2] + words[3]) == 0;
}

// FUNCTION: IMPERIALISM 0x00553b50
unsigned int TTaskForce::HasActiveMapOrderEntryChildren() {
  if (this != nullptr) {
    const short* words = reinterpret_cast<const short*>(reinterpret_cast<const char*>(this) + 0x1e);
    if (words[0] + words[1] + words[2] + words[3] != 0) {
      for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
        if (node->active != 0) {
          return reinterpret_cast<unsigned int>(node) & 0xffffff00u;
        }
      }
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00553bc0
void TTaskForce::FindOrCreateChildOrderLink(TShip* node) {
  TMapOrderChildLinkNode* head = childOrderList;
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
  TMapOrderChildLinkNode* nextLink = childOrderList;
  TMapOrderChildLinkNode* prevLink = 0;
  if (nextLink != 0) {
    short nodePriority = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[node->resourceType04].enabledFlagOrBucketOffset);
    do {
      if (static_cast<short>(
              g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(nextLink->payload)
                                                     ->resourceType04]
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

  if (nextLink == childOrderList) {
    childOrderList = newLink;
  }

  activeChildEntry = node->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);

  short bucketIndex = static_cast<short>(
      g_NavyOrderResourceDescriptorTable[node->resourceType04].enabledFlagOrBucketOffset);
  ++*(reinterpret_cast<short*>(pad_1e) + bucketIndex);

  node->ownerOrderEntry0c = this;

  // Defensive null re-check on `this` (matches the original's own `test edi,edi`
  // before this tail, mirroring the null-safe style already used elsewhere in this
  // class -- e.g. HasNoMapOrderEntryChildrenQueued).
  if (this != nullptr) {
    AssertValid();

    // Copies this entry's own packed order_type/order_strength dword and applies the
    // same attachment-kind gate TShip::SetOwnerOrderEntryAndCacheType applies, just
    // with `this` playing the role of that method's `newEntry` argument.
    node->quantityFlag10 = *reinterpret_cast<int*>(&order_type);

    short kind = static_cast<short>(attachment);
    if (kind != 0 && kind != 7 && kind != 8 && kind != 4) {
      node->field34 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00553e30
void TTaskForce::RecomputeMapOrderChildAggregateMetric() {
  activeChildEntry = nullptr;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    activeChildEntry = static_cast<TShip*>(node->payload)
                           ->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553f10
void TTaskForce::RebuildMapOrderEntryChildren() {
  activeChildEntry = nullptr;
  TMapOrderChildLinkNode* node = childOrderList;
  while (node != nullptr) {
    if (node->active == 0) {
      TShip* entry = static_cast<TShip*>(node->payload);
      entry->ownerOrderEntry0c = nullptr;

      short bucketIndex = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[entry->resourceType04].enabledFlagOrBucketOffset);
      short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
      --*bucketCounter;

      if (node == childOrderList) {
        childOrderList = node->next;
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

  activeChildEntry = nullptr;
  for (node = childOrderList; node != nullptr; node = node->next) {
    activeChildEntry = static_cast<TShip*>(node->payload)
                           ->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553fe0
char TTaskForce::PruneInactiveTaskForceOrderHead() {
  TMapOrderChildLinkNode* head = childOrderList;
  if (head != 0) {
    TShip* headChild = static_cast<TShip*>(head->payload);
    unsigned char headDefeated = (headChild->stockLevel1c <= 0);
    if (headDefeated != 0) {
      headChild->ownerOrderEntry0c = 0;
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

  childOrderList = head;
  activeChildEntry = 0;
  TMapOrderChildLinkNode* node;
  for (node = head; node != 0; node = node->next) {
    activeChildEntry = static_cast<TShip*>(node->payload)
                           ->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }

  if (childOrderList == 0) {
    eliminatedFlag26 = 1;
    return 1;
  }
  return 0;
}

// Resolves the action-context map-order command id from the entry's active order context
// (contextAnchor, a TZone) and a candidate context zone. Returned ids map (in
// TryQueueMapOrderFromTileAction) to entry order types: 0x0C->type3, 0x0D->type1,
// 0x0E->type6, 0x0F->type1 (special queue path); 1 is the fallback.
// FUNCTION: IMPERIALISM 0x00554300
int TTaskForce::ResolveMapOrderCommandFromActionContext(TZone* candidate) {
  TZone* activeContext = reinterpret_cast<TZone*>(contextAnchor);
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
    // Ensure the candidate's primaryNeighbors stretch has one allocated slot (double-or-
    // fallback grow, matching the original's inline realloc), then bump count to 1.
    if (candidate->primaryNeighbors.Capacity() == 0) {
      void* grown = realloc(candidate->primaryNeighbors.Data(), 8);
      if (grown == 0) {
        candidate->primaryNeighbors.Data() =
            static_cast<TZone**>(realloc(candidate->primaryNeighbors.Data(), 4));
        candidate->primaryNeighbors.Capacity() = 1;
      } else {
        candidate->primaryNeighbors.Data() = static_cast<TZone**>(grown);
        candidate->primaryNeighbors.Capacity() = 2;
      }
    }
    if (candidate->primaryNeighbors.Count() == 0) {
      candidate->primaryNeighbors.Count() = 1;
    }
    if (*reinterpret_cast<int*>(candidate->primaryNeighbors.Data()) ==
        reinterpret_cast<int>(activeContext)) {
      return 0x0e;
    }
  }
  return 1;
}

// Resolves the province-context map-order command id: TryQueueMapOrderFromTileAction
// maps 0x10 -> order type 5, and 1 is the "no command" fallback. Asks the diplomacy
// manager whether this entry's required_count nation and the province's owner-nation
// (byte 0) have a stale pair-relation turn stamp.
// FUNCTION: IMPERIALISM 0x00554460
char TTaskForce::ResolveMapOrderCommandFromProvinceContext(void* province) {
  char stale = g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
      required_count, *reinterpret_cast<signed char*>(province));
  return stale ? 0x10 : 1;
}

// True (returns the province's +0xa0 eligibility byte) only when this entry has a
// queued-children region AND an active child link; otherwise 0. Guards a province-context
// command before TryQueueMapOrderFromTileAction commits it.
// FUNCTION: IMPERIALISM 0x00554590
unsigned int TTaskForce::CanQueueMapOrderForProvinceContext(void* province) {
  if (province == nullptr) {
    return 0;
  }
  const short* words = reinterpret_cast<const short*>(reinterpret_cast<const char*>(this) + 0x1e);
  bool noneQueued = (this == nullptr) || (words[0] + words[1] + words[2] + words[3]) == 0;
  if (!noneQueued) {
    for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        return *(reinterpret_cast<unsigned char*>(province) + 0xa0);
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
void TTaskForce::RequeueMapOrderEntry() {
  activeChildEntry = 0;
  TMapOrderChildLinkNode* node = childOrderList;
  while (node != 0) {
    if (node->active != 0) {
      node = node->next;
    } else {
      static_cast<TShip*>(node->payload)->ownerOrderEntry0c = 0;
      short bucketIndex = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
              .enabledFlagOrBucketOffset);
      short* bucketCounter = reinterpret_cast<short*>(pad_1e) + bucketIndex;
      --*bucketCounter;
      if (node == childOrderList) {
        childOrderList = node->next;
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

  activeChildEntry = 0;
  for (node = childOrderList; node != 0; node = node->next) {
    activeChildEntry = static_cast<TShip*>(node->payload)
                           ->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }
  AssertValid();

  TNavyMgr* manager = g_pNavyOrderManager;
  TTaskForce* oldHead = manager->orderListHead04;
  TTaskForce* cursor = oldHead;
  while (cursor != 0) {
    if (cursor == this) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
      return;
    }
    cursor = cursor->queue_next;
  }

  short childCount;
  if (this == 0) {
    childCount = 0;
  } else {
    childCount = 0;
    for (TMapOrderChildLinkNode* countNode = childOrderList; countNode != 0;
         countNode = countNode->next) {
      ++childCount;
    }
  }
  if (childCount <= 0) {
    Free();
    return;
  }

  if (queue_prev != 0) {
    queue_prev->queue_next = queue_next;
  }
  if (queue_next != 0) {
    queue_next->queue_prev = queue_prev;
  }
  queue_prev = 0;
  queue_next = oldHead;
  if (oldHead != 0) {
    oldHead->queue_prev = this;
  }
  manager->orderListHead04 = this;
  g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
}

// FUNCTION: IMPERIALISM 0x005548e0
void TTaskForce::RecomputeTaskForceAverageOrderScore() {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    // Each child entry's +0x10 slot read as a flat aggregate (same opaque order-node
    // internals SelectPreferredMapOrderEntryByPriorityRules reaches via raw casts).
    sum += static_cast<TShip*>(node->payload)->quantityFlag10;
    ++count;
  }
  // The rounded average is written back as one 32-bit store spanning this entry's
  // order_type/order_strength pair (the original writes a dword at +0x04 in each branch).
  if (count != 0) {
    *reinterpret_cast<int*>(&order_type) = (count / 2 + sum) / count;
    return;
  }
  *reinterpret_cast<int*>(&order_type) = 0;
}

// FUNCTION: IMPERIALISM 0x00554930
void TTaskForce::SetTaskForceOrderSelectionByNationClassAndFlag(short nationClass,
                                                                char activeFlag) {
  TMapOrderChildLinkNode* node = childOrderList;
  if (node == nullptr) {
    return;
  }
  while (static_cast<short>(
             g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                 .enabledFlagOrBucketOffset) != nationClass ||
         node->active == activeFlag) {
    node = node->next;
    if (node == nullptr) {
      return;
    }
  }
  node->active = activeFlag;
  if (activeFlag != 0) {
    static_cast<TShip*>(node->payload)->field34 = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005549a0
void TTaskForce::SetTaskForceOrderSelectionByNodeId(TTaskForce* targetOrderObject,
                                                    char activeFlag) {
  TMapOrderChildLinkNode* node;
  if (childOrderList == nullptr) {
    node = nullptr;
  } else if (childOrderList->payload == targetOrderObject) {
    node = childOrderList;
  } else {
    node = childOrderList->next->FindNodeMatching(targetOrderObject);
  }
  if (node != nullptr) {
    node->active = activeFlag;
    if (activeFlag != 0) {
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(targetOrderObject) + 0x34) = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00554a30
int TTaskForce::CountTaskForceSelectedOrdersByNationClass(short nationClass) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (static_cast<short>(
            g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                .enabledFlagOrBucketOffset) == nationClass &&
        node->active != 0) {
      ++count;
    }
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x00554a80
unsigned int TTaskForce::GetMinActionThresholdFromEntryChildren() {
  unsigned int minWeight = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active != 0 &&
        g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                .descriptorWeight < static_cast<int>(minWeight)) {
      minWeight =
          g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
              .descriptorWeight;
    }
  }
  return minWeight == 10000 ? 0 : minWeight;
}

// FUNCTION: IMPERIALISM 0x00554ad0
int TTaskForce::CalculateMapOrderEntryAverageChildRatingX10() {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                 .descriptorWeight;
      ++count;
    }
  }
  if (count == 0) {
    return 0;
  }
  return (sum * 10) / count;
}

namespace {
// Per-order-type priority weight used by both IsTaskForceOrderMixWithinPriorityThresholds
// and ResolveTaskForceOrderConflictAndPickCandidate; indexed by order_type (only 0-2 are
// meaningful -- the original indexes the same 3-entry stack array unconditionally, so an
// out-of-range order_type reads original stack garbage there too).
const int kOrderTypePriorityWeight[3] = {200, 100, 50};
} // namespace

// FUNCTION: IMPERIALISM 0x00554c90
void TTaskForce::BuildTaskForceSelectionOverlayLabelText(CString* out) {
  int childCount = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
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

  // Nation/terrain name for required_count (reused here as a nation slot index; same
  // pattern as TNavyMgr.cpp and BuildMapOrderBattleSideSnapshot).
  g_apTerrainTypeDescriptorTable[required_count]->FormatOverlayTerrainLabelText(&terrainOwnerLabel);

  // `owner`/`contextAnchor` resolved to real TZone* for this call site (see the
  // TMapOrderEntryOwnerContext note in TTaskForce.h / bd 1uj.47.2-3): slot 0x2c is
  // TZone::AssignZoneDisplayNameToOutputRef.
  reinterpret_cast<TZone*>(contextAnchor)->AssignZoneDisplayNameToOutputRef(&contextLabel);

  childCountText.Format(g_szDecimalFormat, childCount);

  // Order-kind label. The original reads only the low 16 bits of `attachment` here
  // (a `movsx ax` load), so truncate through `short` to match exactly.
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
      &orderKindLabel, 0x2762, static_cast<short>(attachment) + 0x13);

  scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(unitCountTemplate),
                         static_cast<LPCSTR>(terrainOwnerLabel), static_cast<LPCSTR>(contextLabel),
                         static_cast<LPCSTR>(childCountText), static_cast<LPCSTR>(orderKindLabel));
}

// Tail-recursive queue_next walk (ResolveMapOrderChainsForTurnPhase's rebuild-head
// pass): null-safe on `this`. An entry with no active children is always pruned
// (Free()'d) regardless of order_type. A live entry survives unless order_type is
// 0/1/4/7/8, or (order_type == 5) its target city's owner nation's diplomacy relation
// stamp with this entry's own nation is out of date -- in both prune cases the walk
// still recurses into queue_next first, then Free()s `this` and returns the recursive
// result (the new chain head with `this` spliced out); the survive case recurses but
// discards that result and returns `this` unchanged.
// FUNCTION: IMPERIALISM 0x00555090
TTaskForce* TTaskForce::PruneNavyOrderIfUnserviceableOrNoChildren() {
  if (this == nullptr) {
    return nullptr;
  }

  int childCount = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    ++childCount;
  }

  bool keepAlive;
  if (childCount < 1) {
    keepAlive = false;
  } else {
    switch (order_type) {
    case 0:
    case 1:
    case 4:
    case 7:
    case 8:
      keepAlive = false;
      break;
    case 5: {
      int cityIndex = GetCityIndexFromCityStatePointer(
          reinterpret_cast<TGlobalMapCityScoreRecord*>(attachment));
      // Byte at cityScoreTable[cityIndex]+0x10 -- not yet a named field on
      // TGlobalMapCityScoreRecord (same raw-offset read TInvadeMission::Call30 uses).
      const char* recordBytes =
          reinterpret_cast<const char*>(&g_pGlobalMapState->cityScoreTable[cityIndex]);
      char ownerByte = recordBytes[0x10];
      keepAlive = g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                      required_count, ownerByte) != 0;
      break;
    }
    default:
      keepAlive = true;
      break;
    }
  }

  if (keepAlive) {
    queue_next->PruneNavyOrderIfUnserviceableOrNoChildren();
    return this;
  }
  TTaskForce* result = queue_next->PruneNavyOrderIfUnserviceableOrNoChildren();
  Free();
  return result;
}

// FUNCTION: IMPERIALISM 0x00555420
char TTaskForce::ResolveTaskForceOrderConflictAndPickCandidate(TTaskForce* other) {
  if (GetMapOrderEntryChildCount() == 0) {
    return 0;
  }
  if (other == nullptr || other->GetMapOrderEntryChildCount() == 0) {
    return 0;
  }

  bool shouldAttempt;
  if (attachment == 6 || other->attachment == 6 || other->attachment == 5) {
    shouldAttempt = true;
  } else {
    int sum = 0;
    int count = 0;
    for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        sum +=
            g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                .descriptorWeight;
        ++count;
      }
    }
    short thisAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);
    short otherAverage = static_cast<short>(other->CalculateMapOrderEntryAverageChildRatingX10());
    short threshold = static_cast<short>(thisAverage - otherAverage + 0x32);
    int totalChildren = other->GetMapOrderEntryChildCount() + GetMapOrderEntryChildCount();
    if (totalChildren > 10) {
      threshold = static_cast<short>(threshold + (totalChildren - 10));
    }
    int roll = rand();
    shouldAttempt = (roll % 100) < threshold;
  }

  if (!shouldAttempt) {
    return 0;
  }

  int thisScore = ComputeTaskForceOrderAggregateScore();
  int otherScore = other->ComputeTaskForceOrderAggregateScore();
  bool resolved;
  if (thisScore * 100 < kOrderTypePriorityWeight[order_type] * otherScore) {
    int otherScore2 = other->ComputeTaskForceOrderAggregateScore();
    int thisScore2 = ComputeTaskForceOrderAggregateScore();
    if (otherScore2 * 100 < kOrderTypePriorityWeight[other->order_type] * thisScore2 ||
        other->eliminatedFlag26 != 0) {
      resolved = false;
    } else {
      resolved = (ComputeTaskForceOrderTieBreakScore(other) == 0);
    }
  } else if (other->IsTaskForceOrderMixWithinPriorityThresholds(this) == 0) {
    resolved = true;
  } else {
    resolved = (other->ComputeTaskForceOrderTieBreakScore(this) == 0);
  }

  if (!resolved) {
    return 0;
  }
  if (GetMapOrderEntryChildCount() == 0 || other->GetMapOrderEntryChildCount() == 0) {
    return 0;
  }

  if (g_pSimMgr->preferenceValues[3] != 0) {
    if (g_pSimMgr->GetActiveNationId() == required_count ||
        g_pSimMgr->GetActiveNationId() == other->required_count) {
      return 1;
    }
  }
  g_pNavyOrderManager->ResolveMapOrderPairConflictStep(this, other);
  return 0;
}

// Standalone sibling of the identical inline "shouldAttempt" computation in
// ResolveTaskForceOrderConflictAndPickCandidate: bails if either side has no active
// children; force-attempts for type-5/6 attachments; else rolls against a priority-gap
// threshold (childRating average delta + child-count overflow past 10).
// FUNCTION: IMPERIALISM 0x00555720
char TTaskForce::ShouldAttemptMapOrderPairResolution(TTaskForce* other) {
  if (GetMapOrderEntryChildCount() == 0) {
    return 0;
  }
  if (other->GetMapOrderEntryChildCount() == 0) {
    return 0;
  }
  if (attachment == 6 || other->attachment == 6 || other->attachment == 5) {
    return 1;
  }

  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                 .descriptorWeight;
      ++count;
    }
  }
  short thisAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);
  short otherAverage = static_cast<short>(other->CalculateMapOrderEntryAverageChildRatingX10());
  short threshold = static_cast<short>(thisAverage - otherAverage + 0x32);
  int totalChildren = other->GetMapOrderEntryChildCount() + GetMapOrderEntryChildCount();
  if (totalChildren > 10) {
    threshold = static_cast<short>(threshold + (totalChildren - 10));
  }
  int roll = rand();
  return (roll % 100) < threshold;
}

// FUNCTION: IMPERIALISM 0x00555920
char TTaskForce::TryMarkLosingMapOrderEntryFromForceBalance(TTaskForce* other) {
  int thisTotal = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    thisTotal += static_cast<TShip*>(node->payload)->ComputeMapOrderEntryHeuristicScore();
  }
  int otherTotal = 0;
  for (TMapOrderChildLinkNode* otherNode = other->childOrderList; otherNode != nullptr;
       otherNode = otherNode->next) {
    otherTotal += static_cast<TShip*>(otherNode->payload)->ComputeMapOrderEntryHeuristicScore();
  }

  if (thisTotal * 100 < kOrderTypePriorityWeight[order_type] * otherTotal) {
    int thisAggregateScore = ComputeTaskForceOrderAggregateScore();
    if (otherTotal * 100 < kOrderTypePriorityWeight[other->order_type] * thisAggregateScore ||
        other->eliminatedFlag26 != 0) {
      return 0;
    }

    unsigned int minWeight = GetMinActionThresholdFromEntryChildren();
    int threshold =
        static_cast<int>(minWeight + 5) * 10 - other->CalculateMapOrderEntryAverageChildRatingX10();
    if (rand() % 100 < threshold) {
      eliminatedFlag26 = 1;
      return 0;
    }
    return 1;
  }

  if (otherTotal * 100 < kOrderTypePriorityWeight[other->order_type] * thisTotal) {
    unsigned int minWeight = other->GetMinActionThresholdFromEntryChildren();
    int threshold =
        static_cast<int>(minWeight + 5) * 10 - CalculateMapOrderEntryAverageChildRatingX10();
    if (rand() % 100 < threshold) {
      other->eliminatedFlag26 = 1;
      return 0;
    }
    return 1;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00555c20
char TTaskForce::ComputeTaskForceOrderTieBreakScore(TTaskForce* other) {
  unsigned short minDescriptorWeight = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active != 0) {
      short weight = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
              .descriptorWeight);
      if (weight < static_cast<short>(minDescriptorWeight)) {
        minDescriptorWeight = static_cast<unsigned short>(weight);
      }
    }
  }

  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* otherNode = other->childOrderList; otherNode != nullptr;
       otherNode = otherNode->next) {
    if (otherNode->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(otherNode->payload)
                                                    ->resourceType04]
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
  eliminatedFlag26 = 1;
  return 1;
}

// FUNCTION: IMPERIALISM 0x00555d10
char TTaskForce::TryResolveMapOrderEntryPairExecution(TTaskForce* other, int* pResolvedFlag) {
  if (GetMapOrderEntryChildCount() == 0) {
    return 0;
  }
  if (other->GetMapOrderEntryChildCount() == 0) {
    return 0;
  }
  if (g_pSimMgr->preferenceValues[3] != 0) {
    if (g_pSimMgr->GetActiveNationId() == required_count ||
        g_pSimMgr->GetActiveNationId() == other->required_count) {
      return 1;
    }
  }
  g_pNavyOrderManager->ResolveMapOrderPairConflictStep(this, other);
  *pResolvedFlag = 0;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00555de0
char TTaskForce::IsTaskForceOrderMixWithinPriorityThresholds(TTaskForce* other) {
  int thisSum = ComputeTaskForceOrderAggregateScore();
  int otherSum = other->ComputeTaskForceOrderAggregateScore();
  return thisSum * 100 < kOrderTypePriorityWeight[order_type] * otherSum;
}

// FUNCTION: IMPERIALISM 0x00556010
int TTaskForce::ComputeTaskForceOrderAggregateScore() {
  int total = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    total += static_cast<TShip*>(node->payload)->ComputeMapOrderEntryHeuristicScore();
  }
  return total;
}

// Immediate/deferred execution effects for a resolved queue entry (ResolveMapOrderChains-
// ForTurnPhase's tail passes): no-op once already eliminated. Type 1 (target-assignment)
// propagates `owner` -- reused here as a raw assignment-target value, not the real
// parent-chain pointer -- into every active child's own attachment field. Type 5
// (province-target) sets the target city's owner-flag bit for this entry's nation
// (required_count) and, in single-player mode, invalidates that city's redraw. Type 8
// (progression) advances every active child's required_count by a quarter-step toward
// its resource-type's stockCap, clamping at the cap. Any other type asserts (once) that
// g_UnknownMapOrderExecutionGuard_006a3ee0 is set, then falls through like the others to
// mark this entry processed -- except type 1, which returns before that (the original
// never sets eliminatedFlag26 on that path).
// FUNCTION: IMPERIALISM 0x00556100
void TTaskForce::ApplyMapOrderTypeExecutionEffects() {
  if (eliminatedFlag26 != 0) {
    return;
  }
  switch (attachment) {
  case 1: {
    for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
      static_cast<TShip*>(node->payload)->field08 = reinterpret_cast<TZone*>(owner);
    }
    return;
  }
  case 5: {
    TGlobalMapCityScoreRecord* cityRecord = reinterpret_cast<TGlobalMapCityScoreRecord*>(owner);
    reinterpret_cast<unsigned char*>(cityRecord)[0xa1] |=
        static_cast<unsigned char>(1 << required_count);
    if (g_pSimMgr->field44 == 1) {
      int cityIndex = GetCityIndexFromCityStatePointer(cityRecord);
      g_pGameFlowState->DispatchCityRedrawInvalidateEvent(static_cast<short>(cityIndex));
    }
    break;
  }
  case 8: {
    for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
      TShip* child = static_cast<TShip*>(node->payload);
      short cap =
          static_cast<short>(g_NavyOrderResourceDescriptorTable[child->resourceType04].stockCap);
      child->stockLevel1c = static_cast<s16>(child->stockLevel1c + cap / 4);
      if (cap < child->stockLevel1c) {
        child->stockLevel1c = cap;
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
  eliminatedFlag26 = 1;
}

// FUNCTION: IMPERIALISM 0x005562c0
int TTaskForce::GetMapOrderEntryChildCount() {
  if (this == nullptr) {
    return 0;
  }
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    ++count;
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x005563d0
int TTaskForce::GetNavyOrderRankWithinNationBucket() {
  if (this == nullptr) {
    return -1;
  }
  int rank = 0;
  for (TTaskForce* node = g_pNavyOrderManager->orderListHead04; node != nullptr;
       node = node->queue_next) {
    if (this == node) {
      return rank;
    }
    if (node->required_count == required_count) {
      ++rank;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00556410
void TTaskForce::UpdateNavyOrderMapMarkerByOrderType() {
  int markerType = -1;
  // Clear the tile this entry previously marked (same body as ClearNavyOrderMapMarker,
  // inlined by the original rather than called).
  if (tiebreak_strength != -1) {
    SetMapTileStateByteAndNotifyObserver(tiebreak_strength, -1);
    tiebreak_strength = -1;
  }
  // `attachment` (+0x08) is the order kind; each kind marks a different tile with a
  // different state byte. In these map-order contexts `owner`/`contextAnchor` are the
  // order's zone -- the disassembly dispatches through TZone's tile-search virtuals
  // (FindNearestActiveSeaContextTileFromOffset216 slot 0x4c,
  // FindBestCoastalTileForContextAndCityStateByHeuristic slot 0x54).
  switch (attachment) {
  case 1:
    markerType = 4;
    tiebreak_strength =
        reinterpret_cast<TZone*>(owner)->FindNearestActiveSeaContextTileFromOffset216();
    break;
  case 3:
    markerType = 5;
    tiebreak_strength =
        reinterpret_cast<TZone*>(contextAnchor)->FindNearestActiveSeaContextTileFromOffset216();
    break;
  case 5:
    markerType = 6;
    tiebreak_strength = static_cast<short>(
        reinterpret_cast<TZone*>(contextAnchor)
            ->FindBestCoastalTileForContextAndCityStateByHeuristic(reinterpret_cast<int>(owner)));
    break;
  case 6:
    markerType = 2;
    tiebreak_strength =
        reinterpret_cast<TZone*>(owner)->FindNearestActiveSeaContextTileFromOffset216();
    break;
  default:
    break;
  }
  if (markerType != -1) {
    SetMapTileStateByteAndNotifyObserver(tiebreak_strength, markerType);
  }
}

// FUNCTION: IMPERIALISM 0x005564f0
void TTaskForce::ClearNavyOrderMapMarker() {
  if (tiebreak_strength != -1) {
    SetMapTileStateByteAndNotifyObserver(tiebreak_strength, -1);
    tiebreak_strength = -1;
  }
}

// FUNCTION: IMPERIALISM 0x00556820
void TTaskForce::DestroyNavyOrderAndChildren() {
  if (this == nullptr) {
    return;
  }
  queue_next->DestroyNavyOrderAndChildren();
  Free();
}

// FUNCTION: IMPERIALISM 0x00557870
void TTaskForce::ClearMapOrderProcessedFlagsChain() {
  for (TTaskForce* node = this; node != nullptr; node = node->queue_next) {
    node->eliminatedFlag26 = 0;
  }
}
