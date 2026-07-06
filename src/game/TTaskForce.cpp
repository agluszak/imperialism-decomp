#include "game/TTaskForce.h"

#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"

extern undefined4 GenerateThreadLocalRandom15(void);

// FUNCTION: IMPERIALISM 0x00550510
short TTaskForce::GetOrderNodeDescriptorWord20ByResourceType() {
  return static_cast<short>(
      g_NavyOrderResourceDescriptorTable[order_type].enabledFlagOrBucketOffset);
}

// FUNCTION: IMPERIALISM 0x00550670
TTaskForce* TTaskForce::SelectPreferredMapOrderEntryByPriorityRules(TTaskForce* candidate,
                                                                    int compareAttachedFlag) {
  if ((char)compareAttachedFlag != '\0') {
    if (attachment != 0) {
      return candidate;
    }
    if (candidate == 0) {
      return this;
    }
    if (candidate->attached_entity != 0) {
      return this;
    }
  }
  if (candidate == 0) {
    return this;
  }
  if (this != 0) {
    int selfAttachment = attachment;
    int candidateAttachment = candidate->attached_entity;
    bool preferSelf = false;
    if (selfAttachment == 0) {
      preferSelf = false;
    } else if (candidateAttachment == 0) {
      preferSelf = true;
    } else {
      preferSelf = *reinterpret_cast<short*>(candidateAttachment + 0x10) <
                   *reinterpret_cast<short*>(selfAttachment + 0x10);
    }
    if (preferSelf) {
      return this;
    }

    bool preferCandidate = false;
    if (candidateAttachment == 0) {
      preferCandidate = false;
    } else if (selfAttachment == 0) {
      preferCandidate = true;
    } else {
      preferCandidate = *reinterpret_cast<short*>(selfAttachment + 0x10) <
                        *reinterpret_cast<short*>(candidateAttachment + 0x10);
    }
    if (!preferCandidate) {
      if (order_type != candidate->order_type) {
        if (candidate->order_type <= order_type) {
          return this;
        }
        return candidate;
      }
      short selfBucket =
          (order_strength / 100 + (order_strength >> 15)) -
          static_cast<short>(
              (static_cast<__int64>(static_cast<int>(order_strength)) * 0x51eb851f) >> 63);
      short candidateBucket =
          (candidate->tiebreak_strength / 100 + (candidate->tiebreak_strength >> 15)) -
          static_cast<short>(
              (static_cast<__int64>(static_cast<int>(candidate->tiebreak_strength)) * 0x51eb851f) >>
              63);
      if (selfBucket != candidateBucket) {
        if (candidateBucket <= selfBucket) {
          return this;
        }
        return candidate;
      }
      if (candidate->required_count < required_count) {
        return this;
      }
    }
  }
  return candidate;
}

// FUNCTION: IMPERIALISM 0x00550820
short TTaskForce::GetOrderNodeDescriptorWord0CByResourceType() {
  return g_NavyOrderResourceDescriptorTable[order_type].calculateWeight;
}

// FUNCTION: IMPERIALISM 0x00550aa0
int TTaskForce::ComputeMapOrderEntryHeuristicScore() {
  short strengthBucket = static_cast<short>(tiebreak_strength / 100);

  const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[order_type];
  int navyPriorityScore = strengthBucket + 5 + desc.navyPriorityWeight * 10;
  int resolveScore = strengthBucket + 5 + desc.resolveWeight * 10;

  short resolveBucket = static_cast<short>(resolveScore / 10);
  short navyPriorityBucket = static_cast<short>(navyPriorityScore / 10);

  return ((resolveBucket + navyPriorityBucket + desc.calculateWeight) * 100 + required_count) /
         desc.taskForceWeight;
}

// FUNCTION: IMPERIALISM 0x00550f80
void TTaskForce::DecrementRequiredCount(short decrement) {
  required_count = static_cast<s16>(required_count - decrement);
}

// FUNCTION: IMPERIALISM 0x00550ff0
void TTaskForce::RemoveNode(int self) {
  TMapOrderEntryOwnerContext* owner_ctx = owner;
  if (owner_ctx != 0) {
    TMapOrderChildLinkNode* list_head = owner_ctx->head;

    if ((list_head != 0) && (this != list_head->object_ptr)) {
      list_head = FindMissionOrderNodeById(list_head->next, this);
    }

    if (list_head != 0) {
      list_head = owner_ctx->head;
      if (list_head != 0) {
        if (this == list_head->object_ptr) {
          list_head = DeleteMapOrderChildLinkAndReturnNext(list_head);
        } else {
          RemoveLinkedOrderNodeByValueRecursive(list_head->next, this);
        }
      }

      owner_ctx->head = list_head;

      // Low 16 bits of the shared per-order-type descriptor's enabled-flag
      // dword (see TNavyOrderResourceDescriptor in global_data_tables.h),
      // reused here as a bucket-count array index.
      short bucket_offset = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[order_type].enabledFlagOrBucketOffset);
      short* bucket_counter =
          reinterpret_cast<short*>(reinterpret_cast<char*>(owner_ctx) + 0x18 + bucket_offset * 2);
      *bucket_counter = *bucket_counter - 1;
    }

    if (this == owner_ctx->active_node) {
      list_head = owner_ctx->head;
      owner_ctx->active_node = 0;
      for (; list_head != 0; list_head = list_head->next) {
        owner_ctx->active_node = list_head->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(
            owner_ctx->active_node, 0);
      }
    }

    owner = 0;
  }

  if (self != 0) {
    // `self` is the RemoveNode caller's own owner-context pointer punned to
    // int (same pun this class already uses for `owner`/`contextAnchor`; see
    // TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink for the register
    // evidence that the real callee is __thiscall on that receiver).
    reinterpret_cast<TMapOrderEntryOwnerContext*>(self)->FindOrCreateChildOrderLink(this);
  }
}

// FUNCTION: IMPERIALISM 0x00551220
void TTaskForce::SetMapOrderActiveChildEntry(TTaskForce* newEntry) {
  owner = reinterpret_cast<TMapOrderEntryOwnerContext*>(newEntry);
  if (newEntry == nullptr) {
    return;
  }
  // TODO: promote body -- 0x55122f-0x551257 (only reached with a non-null
  // newEntry, which none of the bd 1uj.16 target-cluster callers exercise);
  // see bd 1uj.16 follow-up notes.
  newEntry->AssertValid();
}

// FUNCTION: IMPERIALISM 0x00552510
TMapOrderChildLinkNode* TTaskForce::FindMissionOrderNodeById(TMapOrderChildLinkNode* node,
                                                             TTaskForce* child_node) {
  while (node != 0) {
    if (node->object_ptr == child_node) {
      return node;
    }
    node = node->next;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00552590
TMapOrderChildLinkNode*
TTaskForce::DeleteMapOrderChildLinkAndReturnNext(TMapOrderChildLinkNode* child_link_node) {
  TMapOrderChildLinkNode* next_node = child_link_node->next;
  if (next_node != 0) {
    next_node->prev_link = child_link_node->prev_link;
  }
  if (child_link_node->prev_link != 0) {
    child_link_node->prev_link->next = child_link_node->next;
  }

  delete child_link_node;
  return next_node;
}

// FUNCTION: IMPERIALISM 0x005525d0
void TTaskForce::RemoveLinkedOrderNodeByValueRecursive(TMapOrderChildLinkNode* node,
                                                       TTaskForce* child_node) {
  if (node == 0) {
    return;
  }

  if (node->object_ptr == child_node) {
    if (node->next != 0) {
      node->next->prev_link = node->prev_link;
    }
    if (node->prev_link != 0) {
      node->prev_link->next = node->next;
    }
    delete node;
    return;
  }

  RemoveLinkedOrderNodeByValueRecursive(node->next, child_node);
}

// FUNCTION: IMPERIALISM 0x00552650
TMapOrderChildLinkNode* TTaskForce::CreateLinkedOrderNode(TMapOrderChildLinkNode* next_node,
                                                          TTaskForce* child_node) {
  TMapOrderChildLinkNode* new_node = new TMapOrderChildLinkNode();
  if (new_node == 0) {
    return 0;
  }

  new_node->object_ptr = child_node;
  new_node->next = next_node;
  new_node->prev_link = 0;
  new_node->active_flag = 1;
  new_node->pad_0d = 0;
  new_node->pad_0e = 0;
  new_node->pad_0f = 0;

  if (next_node != 0) {
    next_node->prev_link = new_node;
  }
  if (new_node->prev_link != 0) {
    new_node->prev_link->next = new_node;
  }
  return new_node;
}

// FUNCTION: IMPERIALISM 0x005526e0
TMapOrderChildLinkNode*
TTaskForce::PruneDefeatedMapOrderChildrenAndReturnHead(TMapOrderChildLinkNode* child_link_head) {
  while (true) {
    if (child_link_head == 0) {
      return 0;
    }

    TTaskForce* child_node = child_link_head->object_ptr;
    if (0 < child_node->required_count) {
      break;
    }

    child_node->owner = 0;
    child_node->Free();
    child_link_head = DeleteMapOrderChildLinkAndReturnNext(child_link_head);
  }

  PruneDefeatedMapOrderChildrenAndReturnHead(child_link_head->next);
  return child_link_head;
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

TTaskForce::~TTaskForce() {}

void TTaskForce::WriteTo(TStream* stream) {
  (void)stream;
}

void TTaskForce::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005528c0
void __cdecl NoOpTaskForceVtableSlot(void) {
  return;
}

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
    childOrderList->object_ptr->owner = nullptr;

    TMapOrderChildLinkNode* next = childOrderList->next;
    if (next != nullptr) {
      next->prev_link = childOrderList->prev_link;
    }
    if (childOrderList->prev_link != nullptr) {
      childOrderList->prev_link->next = next;
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

// FUNCTION: IMPERIALISM 0x00552f80
void TTaskForce::SetMapOrderType9AndQueue() {
  attachment = 9;

  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr;) {
    if (node->active_flag != 0) {
      node = node->next;
      continue;
    }

    TTaskForce* child = node->object_ptr;
    child->owner = nullptr;

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->order_type].enabledFlagOrBucketOffset);
    short* bucketCounter =
        reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1e + bucketIndex * 2);
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
    }

    TMapOrderChildLinkNode* next = node->next;
    if (next != nullptr) {
      next->prev_link = node->prev_link;
    }
    if (node->prev_link != nullptr) {
      node->prev_link->next = next;
    }
    delete node;
    node = next;
  }

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  // MSVC500 keeps `for`-loop control variables in function scope, so this
  // reuses `node`'s declaration slot rather than shadowing/redeclaring it
  // with a new type -- a fresh TTaskForce* variable is used here instead.
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
    for (node = childOrderList; node != nullptr; node = node->next) {
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
void TTaskForce::PromoteMapOrderChainAndQueue(void* pContextAnchor) {
  // TODO: promote body -- 0x553403's opening call (thunk 0x4081cf) on
  // pContextAnchor is not yet recovered; see bd 1uj.16 follow-up notes.
  (void)pContextAnchor;

  // Minimum g_NavyOrderResourceDescriptorTable[order_type].descriptorWeight
  // among *active* (active_flag != 0) children, clamped to the 10000
  // sentinel (no active children).
  int minPriority = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active_flag != 0) {
      short priority =
          g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight;
      if (priority < minPriority) {
        minPriority = priority;
      }
    }
  }

  owner = reinterpret_cast<TMapOrderEntryOwnerContext*>(contextAnchor);

  int iterationBudget = (minPriority < 10000) ? minPriority : 0;
  if (iterationBudget > 0) {
    // TODO: promote body -- 0x55345f-0x553590's candidate-promotion loop
    // over `owner`'s still-uncharted growable-array region (data/capacity/
    // count at +0x28/+0x2c/+0x30, compared via a short field at +0x44); see
    // the TMapOrderEntryOwnerContext note in TTaskForce.h and bd 1uj.16
    // follow-up notes.
  }

  // MSVC500 keeps `for`-loop control variables in function scope; reuse
  // `node`'s declaration slot from the loop above rather than redeclaring it.
  for (node = childOrderList; node != nullptr;) {
    if (node->active_flag != 0) {
      node = node->next;
      continue;
    }

    TTaskForce* child = node->object_ptr;
    child->SetMapOrderActiveChildEntry(nullptr);

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->order_type].enabledFlagOrBucketOffset);
    short* bucketCounter =
        reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1e + bucketIndex * 2);
    --*bucketCounter;

    if (node == childOrderList) {
      childOrderList = node->next;
    }
    node = DeleteMapOrderChildLinkAndReturnNext(node);
  }

  RecomputeMapOrderChildAggregateMetric();

  AssertValid();

  if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(this)) {
    g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(this);
  }
}

// FUNCTION: IMPERIALISM 0x00553a50
void TTaskForce::ApplyTaskForceSelectionModeForCurrentNationOrders(char reserveExtraSlot) {
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active_flag != 0) {
      // Same node+0x34 overrun documented on
      // TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink.
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(node->object_ptr) + 0x34) =
          (reserveExtraSlot != 0) ? 1u : 2u;
    }
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->nextOlder24) {
    if (reinterpret_cast<int>(ship->field08) == contextAnchor &&
        ship->ownerNationSlot14 == required_count && ship->field0c == 0) {
      // Same `this`-as-owner-context reinterpretation RemoveNode's tail uses; the node
      // argument here is a TShip* (the primary navy order list's own element type), not
      // a TTaskForce* -- FindOrCreateChildOrderLink's own body is still unported
      // (`// TODO: promote body`), so its real, evidenced parameter type is unresolved.
      reinterpret_cast<TMapOrderEntryOwnerContext*>(this)->FindOrCreateChildOrderLink(
          reinterpret_cast<TTaskForce*>(ship));
    }
  }

  for (TMapOrderChildLinkNode* recheckNode = childOrderList; recheckNode != nullptr;
       recheckNode = recheckNode->next) {
    recheckNode->active_flag =
        *reinterpret_cast<int*>(reinterpret_cast<char*>(recheckNode->object_ptr) + 0x34) == 0;
  }
}

// FUNCTION: IMPERIALISM 0x00553bc0
void TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink(TTaskForce* node) {
  // TODO: promote body -- searches `head` for an existing link to `node` (via
  // a sub-call at 0x40635c, not yet resolved); if none exists, allocates
  // (operator new, 0x606f73) and inserts a new TMapOrderChildLinkNode in
  // priority-sorted order (lookup table at 0x698120), bumps a bucket counter
  // at this+0x1e, sets node->owner = this, then makes a virtual dispatch
  // through this receiver's own (still-uncharted) vtable slot 0xc/4 whose
  // consequences -- including a conditional write at node+0x34, past
  // TTaskForce's own 0x34-byte size -- are not yet understood. See the
  // TMapOrderEntryOwnerContext::FindOrCreateChildOrderLink declaration
  // comment and bd 1uj.16 follow-up notes.
  (void)node;
}

// FUNCTION: IMPERIALISM 0x00553e30
void TTaskForce::RecomputeMapOrderChildAggregateMetric() {
  activeChildEntry = nullptr;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    activeChildEntry =
        node->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00554930
void TTaskForce::SetTaskForceOrderSelectionByNationClassAndFlag(short nationClass,
                                                                char activeFlag) {
  TMapOrderChildLinkNode* node = childOrderList;
  if (node == nullptr) {
    return;
  }
  while (static_cast<short>(g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type]
                                .enabledFlagOrBucketOffset) != nationClass ||
         node->active_flag == activeFlag) {
    node = node->next;
    if (node == nullptr) {
      return;
    }
  }
  node->active_flag = activeFlag;
  if (activeFlag != 0) {
    *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(node->object_ptr) + 0x34) = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00554ad0
int TTaskForce::CalculateMapOrderEntryAverageChildRatingX10() {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active_flag != 0) {
      sum += g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight;
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
      if (node->active_flag != 0) {
        sum += g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight;
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
    int roll = GenerateThreadLocalRandom15();
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
  g_pNavyOrderManager->ResolveMapOrderPairConflictStep(other, this);
  return 0;
}

// FUNCTION: IMPERIALISM 0x00555c20
char TTaskForce::ComputeTaskForceOrderTieBreakScore(TTaskForce* other) {
  unsigned short minDescriptorWeight = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active_flag != 0) {
      short weight = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight);
      if (weight < static_cast<short>(minDescriptorWeight)) {
        minDescriptorWeight = static_cast<unsigned short>(weight);
      }
    }
  }

  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* otherNode = other->childOrderList; otherNode != nullptr;
       otherNode = otherNode->next) {
    if (otherNode->active_flag != 0) {
      sum += g_NavyOrderResourceDescriptorTable[otherNode->object_ptr->order_type].descriptorWeight;
      ++count;
    }
  }
  short otherAverage = (count == 0) ? 0 : static_cast<short>((sum * 10) / count);

  int roll = GenerateThreadLocalRandom15();
  short threshold = static_cast<short>(
      ((minDescriptorWeight != 10000 ? minDescriptorWeight : 0) + 5) * 10 - otherAverage);
  if (threshold <= roll % 100) {
    return 0;
  }
  eliminatedFlag26 = 1;
  return 1;
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
    total += node->object_ptr->ComputeMapOrderEntryHeuristicScore();
  }
  return total;
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

// FUNCTION: IMPERIALISM 0x00556820
void TTaskForce::DestroyNavyOrderAndChildren() {
  if (this == nullptr) {
    return;
  }
  queue_next->DestroyNavyOrderAndChildren();
  Free();
}
