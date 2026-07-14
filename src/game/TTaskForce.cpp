#include "game/TTaskForce.h"
#include "game/TMission.h"

#include "game/CString.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TNavyMgr.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/TSimMgr.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/localization_text_helpers.h"
#include "game/ui_invalidation_guard.h"

extern undefined4 GenerateThreadLocalRandom15(void);
extern undefined4 ReallocateHeapBlockWithAllocatorTracking(void);

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
    void* grownBuffer = reinterpret_cast<void*(__cdecl*)(void*, int)>(
        ReallocateHeapBlockWithAllocatorTracking)(neighbors.Data(), wanted * 8);
    if (grownBuffer == 0) {
      neighbors.Data() = static_cast<TZone**>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
          ReallocateHeapBlockWithAllocatorTracking)(neighbors.Data(), wanted * 4));
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
    node->active_flag = flag;
  }
}

// Sums the four per-category priority contributions (the same category-0..3 blend
// ComputeNavyOrderPriorityContributionPercentByCategory computes over this entry's
// order_type/required_count/tiebreak_strength), each scaled by this profile's
// per-category weight row. The original inlines that per-category switch here (as the
// sibling ComputeMapOrderEntryHeuristicScore does) rather than calling the shared
// 0x54ff00 helper, so it is reproduced inline to match.
// FUNCTION: IMPERIALISM 0x005501b0
int TTaskForce::CalculateMissionOrderPriorityScore(int nScoreProfileId) {
  int total = 0;
  for (int category = 0; category < 4; category++) {
    int divisor = g_aCategoryMetricBaselineAverage[category];
    const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[order_type];
    short contribution;
    switch (category) {
    case 0: {
      int quantityTerm = static_cast<short>(tiebreak_strength / 100) + 5 + desc.resolveWeight * 10;
      int weight = desc.calculateWeight;
      contribution = static_cast<short>(
          (static_cast<short>(quantityTerm / 10) * weight * weight * 100) / divisor);
      break;
    }
    case 1: {
      int weight = desc.calculateWeight;
      contribution = static_cast<short>((weight * static_cast<int>(required_count) * 10000) /
                                        (desc.taskForceWeight * divisor));
      break;
    }
    case 2:
      contribution = static_cast<short>((static_cast<int>(desc.descriptorWeight) * 100) / divisor);
      break;
    case 3:
      if (required_count < 1) {
        contribution = static_cast<short>(0 / divisor);
      } else {
        contribution = static_cast<short>(
            (static_cast<int>(GetIndustryActionCostWeightByResourceType(order_type)) * 100) /
            divisor);
      }
      break;
    default:
      contribution = 0;
    }
    total +=
        static_cast<int>(static_cast<short>(
            g_Populate_Beachhead_Mission_LookupTable_00697958[nScoreProfileId * 4 + category])) *
        static_cast<int>(contribution);
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00550370
void TTaskForce::AdjustMapOrderNodeStatCapped499(short delta) {
  tiebreak_strength = static_cast<short>(tiebreak_strength + delta);
  if (tiebreak_strength > 499) {
    tiebreak_strength = 499;
  }
}

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

// FUNCTION: IMPERIALISM 0x00550840
int TTaskForce::ComputeOrderNodeDerivedScoreFromQuantityAndWord18() {
  const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[order_type];
  short strengthBucket = static_cast<short>(tiebreak_strength / 100);
  return (strengthBucket + 5 + desc.navyPriorityWeight * 10) / 10;
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
void TTaskForce::RemoveNode(TTaskForce* self) {
  TTaskForce* owner_ctx = owner;
  if (owner_ctx != 0) {
    TMapOrderChildLinkNode* list_head = owner_ctx->childOrderList;

    if ((list_head != 0) && (this != list_head->object_ptr)) {
      list_head = list_head->next->FindNodeMatching(this);
    }

    if (list_head != 0) {
      list_head = owner_ctx->childOrderList;
      if (list_head != 0) {
        if (this == list_head->object_ptr) {
          list_head = DeleteMapOrderChildLinkAndReturnNext(list_head);
        } else {
          RemoveLinkedOrderNodeByValueRecursive(list_head->next, this);
        }
      }

      owner_ctx->childOrderList = list_head;

      // Low 16 bits of the shared per-order-type descriptor's enabled-flag
      // dword (see TNavyOrderResourceDescriptor in global_data_tables.h),
      // reused here as a bucket-count array index into the SAME +0x1e-based
      // short[] region ApplyTaskForceSelectionModeForCurrentNationOrders /
      // PruneInactiveTaskForceOrderHead use on `this` (0x551066 disassembly:
      // `dec word ptr [edi + eax*2 + 0x1e]` -- confirmed +0x1e, not +0x18).
      short bucket_offset = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[order_type].enabledFlagOrBucketOffset);
      short* bucket_counter =
          reinterpret_cast<short*>(reinterpret_cast<char*>(owner_ctx) + 0x1e + bucket_offset * 2);
      *bucket_counter = *bucket_counter - 1;
    }

    if (this == owner_ctx->activeChildEntry) {
      list_head = owner_ctx->childOrderList;
      owner_ctx->activeChildEntry = 0;
      for (; list_head != 0; list_head = list_head->next) {
        owner_ctx->activeChildEntry =
            list_head->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(
                owner_ctx->activeChildEntry, 0);
      }
    }

    owner = 0;
  }

  if (self != 0) {
    self->FindOrCreateChildOrderLink(this);
  }
}

// FUNCTION: IMPERIALISM 0x00551100
void TTaskForce::ReassignOrderNodeNationAndRebindParentCounters(short nation) {
  TTaskForce* parent = owner;
  if (parent != 0 && parent->required_count != nation) {
    TMapOrderChildLinkNode* link = parent->childOrderList;
    if (link != 0 && this != link->object_ptr) {
      link = link->next->FindNodeMatching(this);
    }
    if (link != 0) {
      TMapOrderChildLinkNode* head = parent->childOrderList;
      if (head != 0) {
        if (this == head->object_ptr) {
          head = DeleteMapOrderChildLinkAndReturnNext(head);
        } else {
          RemoveLinkedOrderNodeByValueRecursive(head->next, this);
        }
      }
      parent->childOrderList = head;

      short bucketIndex = static_cast<short>(
          g_NavyOrderResourceDescriptorTable[order_type].enabledFlagOrBucketOffset);
      short* bucketCounter =
          reinterpret_cast<short*>(reinterpret_cast<char*>(parent) + 0x1e + bucketIndex * 2);
      --*bucketCounter;
    }

    if (this == parent->activeChildEntry) {
      parent->activeChildEntry = 0;
      TMapOrderChildLinkNode* node;
      for (node = parent->childOrderList; node != 0; node = node->next) {
        parent->activeChildEntry = node->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(
            parent->activeChildEntry, 0);
      }
    }

    owner = 0;
  }

  // Same node+0x2c TMission* backpointer TNavyMission::NoOpSlot84/NoOpSlot8C read and
  // write (these child order nodes carry a mission backref where TTaskForce's own
  // model has other fields -- TShip-shaped node evidence, bd 1uj.16).
  TMission* missionBackref = *reinterpret_cast<TMission**>(reinterpret_cast<char*>(this) + 0x2c);
  if (missionBackref != 0 && missionBackref->nationId04 != nation) {
    missionBackref->NoOpSlot8C(reinterpret_cast<int>(this), 1);
  }

  // Same node+0x14 nation-word slot the TShip reading calls ownerNationSlot14.
  *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x14) = nation;
}

// FUNCTION: IMPERIALISM 0x00551220
void TTaskForce::SetMapOrderActiveChildEntry(TTaskForce* newEntry) {
  owner = newEntry;
  if (newEntry == nullptr) {
    return;
  }
  newEntry->AssertValid();

  // The +0x10 slot (childOrderList in this class's primary role) is reused here
  // as raw storage for newEntry's packed order_type/order_strength dword -- the
  // dual-purpose +0x10 region documented in the header (bd 1uj.16).
  *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x10) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(newEntry) + 4);

  short kind = static_cast<short>(newEntry->attachment);
  if (kind != 0 && kind != 7 && kind != 8 && kind != 4) {
    // Same node+0x34 overrun documented on FindOrCreateChildOrderLink (past
    // TTaskForce's own 0x34-byte size).
    *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(this) + 0x34) = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00552510
TMapOrderChildLinkNode* TMapOrderChildLinkNode::FindNodeMatching(TTaskForce* child_node) {
  if (this == 0) {
    return 0;
  }
  TMapOrderChildLinkNode* node = this;
  while (node->object_ptr != child_node) {
    node = node->next;
    if (node == 0) {
      return 0;
    }
  }
  return node;
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

// SYNTHETIC: IMPERIALISM 0x00552870
// TTaskForce::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005528a0
TTaskForce::~TTaskForce() {}

void TTaskForce::WriteTo(TStream* stream) {
  (void)stream;
}

void TTaskForce::ReadFrom(TStream* stream) {
  (void)stream;
}

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

// FUNCTION: IMPERIALISM 0x00552a70
void TTaskForce::RemoveTaskForceOrderNodesByNationAndClearSelectionState(int nation,
                                                                         TZone* contextZone) {
  (void)nation;
  (void)contextZone;
}

// FUNCTION: IMPERIALISM 0x00552f60
void TTaskForce::ResetOrderTypeAndStrengthDword(int packedValue) {
  *reinterpret_cast<int*>(&order_type) = packedValue;
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
  // Reseed the zone-graph BFS distance levels (TZone::field44) from
  // pContextAnchor before using them below to steer the candidate-promotion
  // walk. level == -1 means "start a fresh search" (see
  // TZone::PropagateMapActionContextDistanceLevelsRecursive).
  pContextAnchor->PropagateMapActionContextDistanceLevelsRecursive(-1);

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
        if (candidate->field44 < current->field44) {
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
    if (pruneNode->active_flag != 0) {
      pruneNode = pruneNode->next;
      continue;
    }

    TTaskForce* child = pruneNode->object_ptr;
    child->SetMapOrderActiveChildEntry(nullptr);

    short bucketIndex = static_cast<short>(
        g_NavyOrderResourceDescriptorTable[child->order_type].enabledFlagOrBucketOffset);
    short* bucketCounter =
        reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1e + bucketIndex * 2);
    --*bucketCounter;

    if (pruneNode == childOrderList) {
      childOrderList = pruneNode->next;
    }
    pruneNode = DeleteMapOrderChildLinkAndReturnNext(pruneNode);
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
    if (node->active_flag != 0) {
      // Same node+0x34 overrun documented on FindOrCreateChildOrderLink.
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(node->object_ptr) + 0x34) =
          (reserveExtraSlot != 0) ? 1u : 2u;
    }
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->nextOlder24) {
    if (reinterpret_cast<int>(ship->field08) == contextAnchor &&
        ship->ownerNationSlot14 == required_count && ship->field0c == 0) {
      // The node argument here is a TShip* (the primary navy order list's own element
      // type), not a genuine TTaskForce -- FindOrCreateChildOrderLink's body only
      // touches the shared node-prefix fields (owner/+0x10 raw dword/+0x34 overrun)
      // TShip and TTaskForce both carry at these offsets, so this reinterpret_cast is
      // the one confirmed cross-type pun (bd 1uj.16), not a mismodeled receiver.
      FindOrCreateChildOrderLink(reinterpret_cast<TTaskForce*>(ship));
    }
  }

  for (TMapOrderChildLinkNode* recheckNode = childOrderList; recheckNode != nullptr;
       recheckNode = recheckNode->next) {
    recheckNode->active_flag =
        *reinterpret_cast<int*>(reinterpret_cast<char*>(recheckNode->object_ptr) + 0x34) == 0;
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
        if (node->active_flag != 0) {
          return reinterpret_cast<unsigned int>(node) & 0xffffff00u;
        }
      }
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00553bc0
void TTaskForce::FindOrCreateChildOrderLink(TTaskForce* node) {
  TMapOrderChildLinkNode* head = childOrderList;
  TMapOrderChildLinkNode* existingLink;
  if (head == 0) {
    existingLink = 0;
  } else if (head->object_ptr != node) {
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
        g_NavyOrderResourceDescriptorTable[node->order_type].enabledFlagOrBucketOffset);
    do {
      if (static_cast<short>(g_NavyOrderResourceDescriptorTable[nextLink->object_ptr->order_type]
                                 .enabledFlagOrBucketOffset) >= nodePriority) {
        break;
      }
      prevLink = nextLink;
      nextLink = nextLink->next;
    } while (nextLink != 0);
  }

  TMapOrderChildLinkNode* newLink = new TMapOrderChildLinkNode();
  if (newLink != 0) {
    newLink->object_ptr = node;
    newLink->next = nextLink;
    newLink->prev_link = prevLink;
    newLink->active_flag = 1;
    if (nextLink != 0) {
      nextLink->prev_link = newLink;
    }
    if (newLink->prev_link != 0) {
      newLink->prev_link->next = newLink;
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
      g_NavyOrderResourceDescriptorTable[node->order_type].enabledFlagOrBucketOffset);
  ++*reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x1e + bucketIndex * 2);

  node->owner = this;

  // Defensive null re-check on `this` (matches the original's own `test edi,edi`
  // before this tail, mirroring the null-safe style already used elsewhere in this
  // class -- e.g. HasNoMapOrderEntryChildrenQueued).
  if (this != nullptr) {
    AssertValid();

    // Copies this entry's own packed order_type/order_strength dword and applies the
    // same attachment-kind gate SetMapOrderActiveChildEntry applies, just with `this`
    // playing the role of that method's `newEntry` argument (see the header comment).
    *reinterpret_cast<int*>(reinterpret_cast<char*>(node) + 0x10) =
        *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 4);

    short kind = static_cast<short>(attachment);
    if (kind != 0 && kind != 7 && kind != 8 && kind != 4) {
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(node) + 0x34) = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00553e30
void TTaskForce::RecomputeMapOrderChildAggregateMetric() {
  activeChildEntry = nullptr;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    activeChildEntry =
        node->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00553fe0
char TTaskForce::PruneInactiveTaskForceOrderHead() {
  TMapOrderChildLinkNode* head = childOrderList;
  if (head != 0) {
    TTaskForce* headChild = head->object_ptr;
    unsigned char headDefeated = (headChild->required_count <= 0);
    if (headDefeated != 0) {
      headChild->owner = 0;
      head->object_ptr->Free();

      // Unlink the head link node (inlined DeleteMapOrderChildLinkAndReturnNext,
      // same manual unlink TTaskForce::Free uses).
      TMapOrderChildLinkNode* next = head->next;
      if (next != 0) {
        next->prev_link = head->prev_link;
      }
      if (head->prev_link != 0) {
        head->prev_link->next = head->next;
      }
      delete head;

      head = PruneDefeatedMapOrderChildrenAndReturnHead(next);
    } else {
      PruneDefeatedMapOrderChildrenAndReturnHead(head->next);
    }
  }

  childOrderList = head;
  activeChildEntry = 0;
  TMapOrderChildLinkNode* node;
  for (node = head; node != 0; node = node->next) {
    activeChildEntry =
        node->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(activeChildEntry, 0);
  }

  if (childOrderList == 0) {
    eliminatedFlag26 = 1;
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005548e0
void TTaskForce::RecomputeTaskForceAverageOrderScore() {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    // Each child entry's +0x10 slot read as a flat aggregate (same opaque order-node
    // internals SelectPreferredMapOrderEntryByPriorityRules reaches via raw casts).
    sum += *reinterpret_cast<int*>(reinterpret_cast<char*>(node->object_ptr) + 0x10);
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

// FUNCTION: IMPERIALISM 0x005549a0
void TTaskForce::SetTaskForceOrderSelectionByNodeId(TTaskForce* targetOrderObject,
                                                    char activeFlag) {
  TMapOrderChildLinkNode* node;
  if (childOrderList == nullptr) {
    node = nullptr;
  } else if (childOrderList->object_ptr == targetOrderObject) {
    node = childOrderList;
  } else {
    node = childOrderList->next->FindNodeMatching(targetOrderObject);
  }
  if (node != nullptr) {
    node->active_flag = activeFlag;
    if (activeFlag != 0) {
      *reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(targetOrderObject) + 0x34) = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00554a30
int TTaskForce::CountTaskForceSelectedOrdersByNationClass(short nationClass) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (static_cast<short>(g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type]
                               .enabledFlagOrBucketOffset) == nationClass &&
        node->active_flag != 0) {
      ++count;
    }
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x00554a80
unsigned int TTaskForce::GetMinActionThresholdFromEntryChildren() {
  unsigned int minWeight = 10000;
  for (TMapOrderChildLinkNode* node = childOrderList; node != nullptr; node = node->next) {
    if (node->active_flag != 0 &&
        g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight <
            static_cast<int>(minWeight)) {
      minWeight = g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight;
    }
  }
  return minWeight == 10000 ? 0 : minWeight;
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
  g_pNavyOrderManager->ResolveMapOrderPairConflictStep(this, other);
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
