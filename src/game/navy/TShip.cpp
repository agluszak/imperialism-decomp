#include <mbstring.h>
#include "game/navy/TShip.h"
#include "game/navy_order.h"

#include "game/navy/TAdmiral.h"
#include "game/nation/TGreatPower.h"
#include "game/navy/TTaskForce.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/map/TZone.h"
#include "game/core/TStream.h"
#include "game/GameAssert.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/core/CString.h"

#include <new>

static __inline short SignedDiv10(int value) {
  return static_cast<short>(value / 10);
}

// 0x004e0460 / 0x004e04b0 (SumNavyOrderPriorityForNation[AndNodeType]) are real
// TGreatPower __thiscall methods; bodies live in TGreatPower.cpp.

// FUNCTION: IMPERIALISM 0x0053b800
float ComputeNavyOrderDistributionScoreForNation(short nation) {
  float categoryVector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
    if (ship->nation == nation && ship->IsInHomePort() &&
        ship->GetMaxStrength() <= ship->strength) {
      float stockRatio = static_cast<float>(ship->strength / ship->GetMaxStrength());
      categoryVector[0] =
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
              stockRatio +
          categoryVector[0];
      categoryVector[1] =
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
              stockRatio +
          categoryVector[1];
      categoryVector[2] =
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
              stockRatio +
          categoryVector[2];
      categoryVector[3] =
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3)) +
          categoryVector[3];
    }
  }
  float total = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float* component = categoryVector;
  for (int remaining = 4; remaining != 0; --remaining) {
    total += *component++;
  }
  if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  const short* targetWeight = g_NavyOrderDistributionCategoryWeights_00697978;
  component = categoryVector;
  while (targetWeight < g_NavyOrderDistributionCategoryWeights_00697978 + 4) {
    float diff =
        *component / total - static_cast<float>(*targetWeight) *
                                 static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    diffSum += diff;
    ++targetWeight;
    ++component;
  }
  return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                  diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}
// SYNTHETIC: IMPERIALISM 0x0054f460
// TShip::CreateObject

// SYNTHETIC: IMPERIALISM 0x0054f4e0
// TShip::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShip, TObject)

// FUNCTION: IMPERIALISM 0x0054f500
TShip::TShip()
    : TObject(), type(0), pad06(0), location(0), taskForce(0), aggression(1),
      nation(static_cast<short>(-1)), name(), strength(0), pad1e(0), admiral(0),
      next(g_pNavyPrimaryOrderListHead), previous(0), mission(0), experience(0), selection(0) {
  g_pNavyPrimaryOrderListHead = this;
  if (next != 0) {
    next->previous = this;
  }
}

// SYNTHETIC: IMPERIALISM 0x0054f5c0
// TShip::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0054f5f0
TShip::~TShip() {}

// FUNCTION: IMPERIALISM 0x0054f640
void TShip::Free() {
  if (g_pNavyPrimaryOrderListHead == this) {
    g_pNavyPrimaryOrderListHead = this->next;
  }
  if (this->next != 0) {
    this->next->previous = this->previous;
  }
  if (this->previous != 0) {
    this->previous->next = this->next;
  }
  if (mission != 0) {
    mission->RejectConstituent(this, 1);
  }
  if (taskForce != 0) {
    taskForce->Remove(this);
  }
  if (admiral != 0) {
    admiral->Free();
  }
  delete this;
}

// Mac oracle: IShip.
// FUNCTION: IMPERIALISM 0x0054f7b0
void TShip::IShip(short shipType, TZone* zone, short nationArg, const char* nameOverride) {
  type = shipType;
  location = zone;
  nation = nationArg;

  if (nameOverride == 0) {
    // The owning country names the ship; if that name collides with an existing
    // ship's, the name is re-rolled until unique. The casts below are the CRT's
    // signature (_mbscmp takes const unsigned char*), not a model shortcut.
    g_apTerrainTypeDescriptorTable[nation]->GenerateEthnicName(&name);
    for (TShip* other = g_pNavyPrimaryOrderListHead; other != 0; other = other->next) {
      if (other != this &&
          _mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(other->name)),
                  reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(name))) == 0) {
        NameThyself();
        break;
      }
    }
  } else {
    // A real named CString local, not an unnamed temp: the original carries an EH
    // frame (push -1 / __ehhandler) for exactly this object's unwind.
    CString suppliedName(nameOverride);
    name = suppliedName;
  }

  strength = g_NavyOrderResourceDescriptorTable[shipType].StockCap();
  if (location != 0) {
    location->HandleKeyDown(nation);
  }
}

// FUNCTION: IMPERIALISM 0x0054fab0
void TShip::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&type, 2);
  stream->WriteBytes(&aggression, 4);
  stream->WriteBytes(&nation, 2);
  stream->WriteSharedString(&name);
  stream->WriteBytes(&strength, 2);
  stream->WriteBytes(&selection, 4);
  stream->WriteBytes(&experience, 2);
  short zoneIndex = location->GetContextOrdinalOrInvalid();
  stream->WriteBytes(&zoneIndex, 2);
}

// FUNCTION: IMPERIALISM 0x0054fb50
void TShip::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&type, 2);
  stream->ReadBytes(&aggression, 4);
  stream->ReadBytes(&nation, 2);
  // 0x54fb8b dispatches slot 0x70 (ReadSharedString), the mirror of WriteTo's
  // WriteSharedString -- not a raw 0x20-byte block read. The port's ReadBytes both
  // desynced the stream (a shared string is a 2-byte length plus its bytes) and wrote
  // 0x20 bytes over the CString handle and the six fields that follow it.
  stream->ReadSharedString(&name, 0x20);
  stream->ReadBytes(&strength, 2);
  stream->ReadBytes(&selection, 4);
  stream->ReadBytes(&experience, 2);
  short zoneIndex;
  stream->ReadBytes(&zoneIndex, 2);
  location = FindMapActionContextByNodeId(zoneIndex);
}

// FUNCTION: IMPERIALISM 0x0054fbf0
void TShip::NameThyself() {
  do {
    g_apTerrainTypeDescriptorTable[nation]->GenerateEthnicName(&name);
    for (TShip* existing = g_pNavyPrimaryOrderListHead; existing != 0; existing = existing->next) {
      if (existing == this) {
        continue;
      }
      unsigned char duplicate =
          (_mbscmp(reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(existing->name)),
                   reinterpret_cast<const unsigned char*>(static_cast<LPCSTR>(name))) == 0);
      if (duplicate != 0) {
        goto retry;
      }
    }
    return;
  retry:;
  } while (1);
}

// FUNCTION: IMPERIALISM 0x0054fc60
void TShip::SetLocation(TZone* zone) {
  location = zone;
}

// FUNCTION: IMPERIALISM 0x0054fd50
void RecomputeGlobalCapabilityAverages(void) {
  if (g_pTechMgr == 0) {
    return;
  }
  g_aCategoryMetricBaselineAverage[0] = 0;
  g_aCategoryMetricBaselineAverage[1] = 0;
  g_aCategoryMetricBaselineAverage[2] = 0;
  g_aCategoryMetricBaselineAverage[3] = 0;

  int enabledCount = 0;
  // Dual induction, matching the original: an int index (strength-reduced by the
  // compiler into a marching record pointer with a signed bound) carries the enabled
  // gate, while the separate short counter indexes the flag array and the per-case
  // table reads (its short-ness is what keeps those accesses movsx-indexed instead
  // of strength-reduced pointers).
  short type = 1;
  int i;
  for (i = 1; i < 14; ++i) {
    // The enabled gate tests the record's first column as a DWORD, while the case-0
    // blend reads its low word. The descriptor accessors preserve both widths without
    // overlapping storage declarations.
    if (0 < g_NavyOrderResourceDescriptorTable[i].ResolveWeightDword() &&
        g_pTechMgr->resourceTypeEnabled19d[type] != 0) {
      ++enabledCount;
      int category;
      for (category = 0; category < 4; ++category) {
        int contribution;
        switch (category) {
        case 0: {
          short calc = g_NavyOrderResourceDescriptorTable[type].CalculateWeight();
          contribution = g_NavyOrderResourceDescriptorTable[type].ResolveWeight() * calc * calc;
          break;
        }
        case 1:
          contribution = (g_NavyOrderResourceDescriptorTable[type].CalculateWeight() *
                          g_NavyOrderResourceDescriptorTable[type].StockCap() * 100) /
                         g_NavyOrderResourceDescriptorTable[type].TaskForceWeight();
          break;
        case 2:
          contribution = g_NavyOrderResourceDescriptorTable[type].NavyPriorityWeight();
          break;
        case 3:
          contribution = g_industryActionCostWeightResCode10[type];
          break;
        default:
          contribution = 0;
          break;
        }
        g_aCategoryMetricBaselineAverage[category] += contribution;
      }
    }
    ++type;
  }

  int half = enabledCount / 2;
  int category;
  for (category = 0; category < 4; ++category) {
    g_aCategoryMetricBaselineAverage[category] =
        (g_aCategoryMetricBaselineAverage[category] + half) / enabledCount;
  }
}

// FUNCTION: IMPERIALISM 0x0054fee0
int GetNavyOrderCategoryBaseline(int category) {
  return g_aCategoryMetricBaselineAverage[category];
}

// Receiver-agnostic: also called directly on a TTaskForce's own
// aggression/nation/ingotTileIndex fields (TNavyMission::AccumulateLack),
// which happen to share these same 3 offsets with TShip -- see the header comment.

// FUNCTION: IMPERIALISM 0x0054ff00
short TShip::ComputeNavyOrderPriorityContributionPercentByCategory(int category) {
  int divisor = g_aCategoryMetricBaselineAverage[category];

  switch (category) {
  case 0: {
    const TNavyOrderResourceDescriptor& descriptor = g_NavyOrderResourceDescriptorTable[type];
    int weight = descriptor.CalculateWeight();
    int quantityTerm = experience / 100 + descriptor.ResolveWeightDword() * 10 + 5;
    return (SignedDiv10(quantityTerm) * weight * weight * 100) / divisor;
  }
  case 1: {
    const TNavyOrderResourceDescriptor& descriptor = g_NavyOrderResourceDescriptorTable[type];
    int weight = descriptor.CalculateWeight();
    return (weight * static_cast<int>(strength) * 10000) / (descriptor.TaskForceWeight() * divisor);
  }
  case 2:
    return (static_cast<int>(g_NavyOrderResourceDescriptorTable[type].DescriptorWeight()) * 100) /
           divisor;
  case 3:
    if (strength < 1) {
      return 0;
    }
    return (static_cast<int>(g_industryActionCostWeightResCode10[type]) * 100) / divisor;
  default:
    return 0;
  }
}

// Per-category normalized cost percent for a resource type, used by the AI
// city/industry development selectors (0x4eb45a, 0x535d8e/0x535e26). Same
// category-0..3 divisor table (g_aCategoryMetricBaselineAverage) and resource-descriptor
// table as ComputeNavyOrderPriorityContributionPercentByCategory, but a distinct blend per
// category; the original inlines the descriptor-field reads, so they are reproduced
// inline here.

// FUNCTION: IMPERIALISM 0x00550090
int GetNormalizedIndustryActionResourceCostPercent(int nCategory, short nResourceType) {
  int divisor = g_aCategoryMetricBaselineAverage[nCategory];
  const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[nResourceType];
  switch (nCategory) {
  case 0:
    return (static_cast<int>(desc.ResolveWeight()) * static_cast<int>(desc.CalculateWeight()) *
            static_cast<int>(desc.CalculateWeight()) * 100) /
           divisor;
  case 1:
    return (((static_cast<int>(desc.CalculateWeight()) * static_cast<int>(desc.StockCap()) * 100) /
             static_cast<int>(desc.TaskForceWeight())) *
            100) /
           divisor;
  case 2:
    return (desc.NavyPriorityWeight() * 100) / divisor;
  case 3:
    return (g_industryActionCostWeightResCode10[nResourceType] * 100) / divisor;
  default:
    return 0 / divisor;
  }
}

// FUNCTION: IMPERIALISM 0x005501b0
int TShip::ComputeValueForMission(int missionType) const {
  int total = 0;
  for (int category = 0; category < 4; category++) {
    int divisor = g_aCategoryMetricBaselineAverage[category];
    short contribution;
    switch (category) {
    case 0: {
      int quantityTerm = static_cast<short>(experience / 100) + 5 +
                         g_NavyOrderResourceDescriptorTable[type].ResolveWeightDword() * 10;
      int weight = g_NavyOrderResourceDescriptorTable[type].CalculateWeight();
      contribution = static_cast<short>(
          (static_cast<short>(quantityTerm / 10) * weight * weight * 100) / divisor);
      break;
    }
    case 1: {
      int requiredCountValue = strength;
      int weight = g_NavyOrderResourceDescriptorTable[type].CalculateWeight();
      contribution = static_cast<short>(
          (weight * requiredCountValue * 10000) /
          (g_NavyOrderResourceDescriptorTable[type].TaskForceWeight() * divisor));
      break;
    }
    case 2:
      contribution = static_cast<short>(
          (static_cast<int>(g_NavyOrderResourceDescriptorTable[type].DescriptorWeight()) * 100) /
          divisor);
      break;
    case 3: {
      short industryCost = 0;
      if (strength > 0) {
        industryCost = g_industryActionCostWeightResCode10[type];
      }
      contribution = static_cast<short>((static_cast<int>(industryCost) * 100) / divisor);
      break;
    }
    default:
      contribution = 0;
    }
    total += static_cast<short>(
                 g_Populate_Beachhead_Mission_LookupTable_00697958[missionType * 4 + category]) *
             static_cast<int>(contribution);
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00550370
void TShip::Victory(short experienceGain) {
  experience = static_cast<short>(experience + experienceGain);
  if (experience >= 500) {
    experience = 499;
  }
}

// FUNCTION: IMPERIALISM 0x005503a0
TTaskForce* TShip::DemandExclusiveTaskForce() {
  TTaskForce* owner_ctx = taskForce;
  if (owner_ctx != nullptr) {
    owner_ctx->AssertValid();

    short childCount = 0;
    TMapOrderChildLinkNode* head = owner_ctx->shipList;
    for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
      ++childCount;
    }

    if (childCount > 1) {
      TMapOrderChildLinkNode* found;
      if (head == nullptr) {
        found = nullptr;
      } else if (head->payload == this) {
        found = head;
      } else {
        found = head->next->FindNodeMatching(this);
      }
      if (found != nullptr) {
        owner_ctx->shipList = head->RemoveLinkedOrderNodeByValueRecursive(this);

        short bucketIndex =
            static_cast<short>(g_NavyOrderResourceDescriptorTable[type].ToolbarBucketIndex());
        --owner_ctx->shipCountsByToolbarSlot[bucketIndex];
      }
      if (this == owner_ctx->flagship) {
        owner_ctx->ElectFlagship();
      }
      SetTaskForce(nullptr);
      owner_ctx = nullptr;
    }

    if (owner_ctx != nullptr) {
      return owner_ctx;
    }
  }

  // Real construction (TTaskForce::TTaskForce(TZone*, short), 0x552800). The original
  // compiles this one call site's construction as inlined field stores rather than a
  // call to that ctor (likely a disabled-ICF duplicate, matching TArmyMission-style
  // per-callsite reproduction elsewhere in this codebase); that inlining is not
  // reproducible from C++ source without a manual vtable write, which construction
  // Hard Rule 2 forbids outside quarantined runtime files. `new T()` is the correct
  // model here even though it costs some match percentage at this address.
  // The entry's zone context comes from this ship's port zone.
  TTaskForce* entry = new TTaskForce(location, nation);
  if (entry == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UNavy.cpp", 0x306);
  }
  entry->Add(this);
  return entry;
}

// FUNCTION: IMPERIALISM 0x00550510
short TShip::GetToolbarSlot() const {
  return static_cast<short>(g_NavyOrderResourceDescriptorTable[type].ToolbarBucketIndex());
}

// FUNCTION: IMPERIALISM 0x00550550
short TShip::GetTurnDistanceTo(TZone* otherZone) const {
  short hopDistance = location->GetCachedMapActionContextDistanceOrRecompute(otherZone);
  short descriptorWeight = g_NavyOrderResourceDescriptorTable[type].DescriptorWeight();
  return static_cast<short>((descriptorWeight - 1 + hopDistance) / descriptorWeight);
}

// Mac oracle: TShip::GetMaxStrength() const. The established descriptive name is kept
// for now, but this is a real TShip method, not a free resource-type lookup: every
// callsite loads the ship receiver into ECX and the body reads type at +0x04.
// FUNCTION: IMPERIALISM 0x005505a0
short TShip::GetMaxStrength() const {
  return g_NavyOrderResourceDescriptorTable[type].StockCap();
}

// FUNCTION: IMPERIALISM 0x005505c0
TShip* TShip::GetFirst() {
  return g_pNavyPrimaryOrderListHead;
}

// FUNCTION: IMPERIALISM 0x00550610
int TShip::GetIndex() const {
  int index = 0;
  for (TShip* node = g_pNavyPrimaryOrderListHead; node != 0 && node != this; node = node->next) {
    ++index;
  }
  return index;
}

// FUNCTION: IMPERIALISM 0x00550640
TShip* TShip::GetNth(short index) {
  TShip* node = g_pNavyPrimaryOrderListHead;
  while (node != nullptr && index != 0) {
    node = node->next;
    --index;
  }
  return node;
}

// Priority compare between two ship order nodes (see the header note); the original
// reads +0x20 (admiral backlink, then its experiencePoints) SYMMETRICALLY on both receiver
// and candidate -- the previous TTaskForce-receiver model misread the receiver side,
// a genuine mis-port this migration fixes.
// FUNCTION: IMPERIALISM 0x00550670
TShip* TShip::Finest(TShip* candidate, unsigned char preferUnassigned) {
  if (preferUnassigned != 0) {
    if (admiral != nullptr) {
      return candidate;
    }
    if (candidate == nullptr) {
      return this;
    }
    if (candidate->admiral != nullptr) {
      return this;
    }
  }
  if (candidate == nullptr) {
    return this;
  }
  if (this != nullptr) {
    TAdmiral* selfAdmiral = admiral;
    TAdmiral* candidateAdmiral = candidate->admiral;
    bool preferSelf = false;
    if (selfAdmiral == nullptr) {
      preferSelf = false;
    } else if (candidateAdmiral == nullptr) {
      preferSelf = true;
    } else {
      preferSelf = candidateAdmiral->experiencePoints < selfAdmiral->experiencePoints;
    }
    if (preferSelf) {
      return this;
    }

    bool preferCandidate = false;
    if (candidateAdmiral == nullptr) {
      preferCandidate = false;
    } else if (selfAdmiral == nullptr) {
      preferCandidate = true;
    } else {
      preferCandidate = selfAdmiral->experiencePoints < candidateAdmiral->experiencePoints;
    }
    if (!preferCandidate) {
      if (type != candidate->type) {
        if (candidate->type <= type) {
          return this;
        }
        return candidate;
      }
      short selfBucket = static_cast<short>(experience / 100);
      short candidateBucket = static_cast<short>(candidate->experience / 100);
      if (selfBucket != candidateBucket) {
        if (candidateBucket <= selfBucket) {
          return this;
        }
        return candidate;
      }
      if (candidate->strength < strength) {
        return this;
      }
    }
  }
  return candidate;
}

// FUNCTION: IMPERIALISM 0x00550820
short TShip::GetRange() const {
  return g_NavyOrderResourceDescriptorTable[type].CalculateWeight();
}

// FUNCTION: IMPERIALISM 0x00550840
int TShip::GetSpeed() const {
  const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[type];
  short strengthBucket = static_cast<short>(experience / 100);
  return (strengthBucket + 5 + desc.NavyPriorityWeightDword() * 10) / 10;
}

// FUNCTION: IMPERIALISM 0x00550970
short GetIndustryActionCostWeightByResourceType(short resourceType) {
  return g_industryActionCostWeightResCode10[resourceType];
}

// FUNCTION: IMPERIALISM 0x005509c0
void TShip::Sink() {
  TTaskForce* ownerEntry = this->taskForce;
  this->strength = -666;
  if (ownerEntry != 0) {
    // Same prune-head-then-recompute body TTaskForce::SinkOrSwimShips
    // (0x553fe0) runs on itself, minus the return flag.
    TMapOrderChildLinkNode* head = ownerEntry->shipList;
    if (head != 0) {
      TShip* headChild = static_cast<TShip*>(head->payload);
      unsigned char headDefeated = (headChild->strength <= 0);
      if (headDefeated != 0) {
        headChild->taskForce = 0;
        static_cast<TShip*>(head->payload)->Free();

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

    ownerEntry->shipList = head;
    ownerEntry->flagship = 0;
    TMapOrderChildLinkNode* node;
    for (node = head; node != 0; node = node->next) {
      ownerEntry->flagship = static_cast<TShip*>(node->payload)->Finest(ownerEntry->flagship, 0);
    }

    if (ownerEntry->shipList == 0) {
      ownerEntry->defeated = 1;
    }
  } else {
    this->Free();
  }
}

// FUNCTION: IMPERIALISM 0x00550aa0
int TShip::GetBattleStrengthRating() const {
  short resourceType = type;
  short strengthBucket = static_cast<short>(experience / 100);

  const TNavyOrderResourceDescriptor& desc = g_NavyOrderResourceDescriptorTable[resourceType];
  int navyPriorityScore = strengthBucket + 5 + desc.NavyPriorityWeightDword() * 10;
  short navyPriorityBucket = static_cast<short>(navyPriorityScore / 10);
  int resolveScore = strengthBucket + 5 + desc.ResolveWeightDword() * 10;
  short resolveBucket = static_cast<short>(resolveScore / 10);

  return ((navyPriorityBucket + desc.CalculateWeight()) * 100 + resolveBucket + strength) /
         desc.TaskForceWeight();
}

// FUNCTION: IMPERIALISM 0x00550b60
int TShip::GetStudliness() const {
  const TNavyOrderResourceDescriptor& descriptor = g_NavyOrderResourceDescriptorTable[type];
  short quantityTerm = static_cast<short>(experience / 100);
  short navyTerm =
      static_cast<short>((quantityTerm + descriptor.NavyPriorityWeightDword() * 10 + 5) / 10);
  // The resolve-weight column is read as a full dword here; other callers use its low
  // signed word. The descriptor accessors preserve both widths.
  return ((navyTerm + descriptor.CalculateWeight()) * 100 +
          static_cast<short>((quantityTerm + descriptor.ResolveWeightDword() * 10 + 5) / 10) +
          strength) /
         descriptor.TaskForceWeight();
}

// FUNCTION: IMPERIALISM 0x00550e70
short GetResourceDescriptorWeightWord0ByType(int resourceType) {
  return g_NavyOrderResourceDescriptorTable[static_cast<short>(resourceType)]
      .ResourceDescriptorWeightWord0();
}

// FUNCTION: IMPERIALISM 0x00550f60
bool TShip::IsInHomePort() const {
  return location->QueryPortZoneCapability();
}

// FUNCTION: IMPERIALISM 0x00550f80
void TShip::Damage(short decrement) {
  strength = static_cast<short>(strength - decrement);
}

// FUNCTION: IMPERIALISM 0x00550ff0
void TShip::ReassignToForce(TTaskForce* newOwnerEntry) {
  TTaskForce* owner_ctx = taskForce;
  if (owner_ctx != 0) {
    TMapOrderChildLinkNode* list_head = owner_ctx->shipList;

    if ((list_head != 0) && (this != list_head->payload)) {
      list_head = list_head->next->FindNodeMatching(this);
    }

    if (list_head != 0) {
      list_head = owner_ctx->shipList;
      if (list_head != 0) {
        if (this == list_head->payload) {
          list_head = list_head->DeleteMapOrderChildLinkAndReturnNext();
        } else {
          list_head->next->RemoveLinkedOrderNodeByValueRecursive(this);
        }
      }

      owner_ctx->shipList = list_head;

      // Low 16 bits of the shared per-order-type descriptor's enabled-flag
      // dword (see TNavyOrderResourceDescriptor in global_data_tables.h),
      // reused here as a bucket-count array index into the SAME +0x1e-based
      // short[] region DropShips /
      // SinkOrSwimShips use on the entry (0x551066 disassembly:
      // `dec word ptr [edi + eax*2 + 0x1e]` -- confirmed +0x1e, not +0x18).
      short bucket_offset =
          static_cast<short>(g_NavyOrderResourceDescriptorTable[type].ToolbarBucketIndex());
      --owner_ctx->shipCountsByToolbarSlot[bucket_offset];
    }

    if (this == owner_ctx->flagship) {
      list_head = owner_ctx->shipList;
      owner_ctx->flagship = 0;
      for (; list_head != 0; list_head = list_head->next) {
        owner_ctx->flagship =
            static_cast<TShip*>(list_head->payload)->Finest(owner_ctx->flagship, 0);
      }
    }

    taskForce = 0;
  }

  if (newOwnerEntry != 0) {
    newOwnerEntry->Add(this);
  }
}

// FUNCTION: IMPERIALISM 0x00551100
void TShip::Capture(short nation) {
  TTaskForce* parent = taskForce;
  if (parent != 0 && parent->nation != nation) {
    TMapOrderChildLinkNode* link = parent->shipList;
    if (link != 0 && this != link->payload) {
      link = link->next->FindNodeMatching(this);
    }
    if (link != 0) {
      TMapOrderChildLinkNode* head = parent->shipList;
      if (head != 0) {
        if (this == head->payload) {
          head = head->DeleteMapOrderChildLinkAndReturnNext();
        } else {
          head->next->RemoveLinkedOrderNodeByValueRecursive(this);
        }
      }
      parent->shipList = head;

      short bucketIndex =
          static_cast<short>(g_NavyOrderResourceDescriptorTable[type].ToolbarBucketIndex());
      --parent->shipCountsByToolbarSlot[bucketIndex];
    }

    if (this == parent->flagship) {
      parent->flagship = 0;
      TMapOrderChildLinkNode* node;
      for (node = parent->shipList; node != 0; node = node->next) {
        parent->flagship = static_cast<TShip*>(node->payload)->Finest(parent->flagship, 0);
      }
    }

    taskForce = 0;
  }

  TMission* missionBackref = mission;
  if (missionBackref != 0 && missionBackref->nationId04 != nation) {
    missionBackref->RejectConstituent(this, 1);
  }

  this->nation = nation;
}

// FUNCTION: IMPERIALISM 0x00551220
void TShip::SetTaskForce(TTaskForce* newEntry) {
  taskForce = newEntry;
  if (newEntry == nullptr) {
    return;
  }
  newEntry->AssertValid();

  // Cache the entry's aggression dword.
  aggression = newEntry->aggression;

  short kind = static_cast<short>(newEntry->shipOrders);
  if (kind != 0 && kind != 7 && kind != 8 && kind != 4) {
    selection = 0;
  }
}

// FUNCTION: IMPERIALISM 0x005519d0
int FindCumulativeWeightBucketIndex(short* weightTable, short roll) {
  int index = -1;
  do {
    ++index;
    roll = static_cast<short>(roll - weightTable[index]);
  } while (roll > 0);
  return index;
}
