#include "game/navy/TAdmiral.h"

#include <stdlib.h>
#include <string.h>

#include "game/military/mapped_flavor_text.h"
#include "game/navy/TShip.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/navy_order.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/core/TStream.h"
#include "game/core/CString.h"
#include "game/gfx/ui_invalidation_guard.h"

namespace {

__inline unsigned int PointerSeedBits(const void* pointer) {
  unsigned int bits;
  memcpy(&bits, &pointer, sizeof(bits));
  return bits;
}

} // namespace

// SYNTHETIC: IMPERIALISM 0x005512d0
// TAdmiral::CreateObject

// SYNTHETIC: IMPERIALISM 0x00551410
// TAdmiral::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAdmiral, TObject)

// FUNCTION: IMPERIALISM 0x00551430
TAdmiral::TAdmiral(NationSlot nationSlotArg)
    : nationSlot(nationSlotArg), assignedShip(0), displayName(), experiencePoints(0),
      next(g_pNavySecondaryOrderListHead), prev(0) {
  g_pNavySecondaryOrderListHead = this;
  if (next != 0) {
    next->prev = this;
  }
  if (static_cast<unsigned short>(nationSlot) != 0xffff) {
    g_apTerrainTypeDescriptorTable[nationSlot]->GenerateEthnicName(&displayName);
    for (TAdmiral* node = g_pNavySecondaryOrderListHead; node != 0; node = node->next) {
      if (node == this) {
        continue;
      }
      if (node->displayName.Compare(this->displayName) == 0) {
        this->NameThyself();
      }
    }
  }
}

// SYNTHETIC: IMPERIALISM 0x00551550
// TAdmiral::`scalar deleting destructor'

// Inline-expanded into every caller in the original (0x552250 and 0x551850 carry the
// body verbatim, and 0x5b0500 in another TU still CALLs 0x552250 itself), so it must be
// `inline` for MSVC500 /Ob1 to reproduce that. Callers spell the clear-backlink steps
// out on `this->assignedShip` directly (the original re-reads the member after
// the +0x20 store), so there is no ClearPrimaryOrderBacklink helper.
static inline void RecomputeMapOrderOwnerActiveSelection(TTaskForce* ownerContext) {
  if (ownerContext == 0) {
    return;
  }
  ownerContext->flagship = 0;
  for (TMapOrderChildLinkNode* link = ownerContext->shipList; link != 0; link = link->next) {
    TShip* activeEntry = ownerContext->flagship;
    ownerContext->flagship = static_cast<TShip*>(link->payload)->Finest(activeEntry, 0);
  }
}

// FUNCTION: IMPERIALISM 0x00551580
TAdmiral::~TAdmiral() {}

// FUNCTION: IMPERIALISM 0x005515d0
void TAdmiral::Free() {
  if (this->prev != 0) {
    this->prev->next = this->next;
  } else {
    g_pNavySecondaryOrderListHead = this->next;
  }
  if (this->next != 0) {
    this->next->prev = this->prev;
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x00551670
void TAdmiral::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytes(&nationSlot, 2);
  stream->WriteSharedString(&displayName);
  stream->WriteBytes(&experiencePoints, 2);

  int index = 0;
  TShip* node = g_pNavyPrimaryOrderListHead;
  if (node != 0) {
    while (node != assignedShip) {
      node = node->next;
      ++index;
      if (node == 0) {
        break;
      }
    }
  }
  stream->WriteBytes(&index, 2);
}

// FUNCTION: IMPERIALISM 0x00551700
void TAdmiral::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&nationSlot, 2);
  stream->ReadSharedString(&displayName, 0x20);
  stream->ReadBytes(&experiencePoints, 2);
  short index;
  stream->ReadBytes(&index, 2);

  TShip* node = g_pNavyPrimaryOrderListHead;
  while (node != 0 && index != 0) {
    node = node->next;
    --index;
  }

  if (assignedShip != 0) {
    assignedShip->admiral = 0;
    RecomputeMapOrderOwnerActiveSelection(assignedShip->taskForce);
  }

  assignedShip = node;
  if (node != 0) {
    node->admiral = this;
    RecomputeMapOrderOwnerActiveSelection(node->taskForce);
  }
}

// Mac oracle: Victory. Clamped so experiencePoints / 100 stays within the four
// skill tiers the readers expect.
// FUNCTION: IMPERIALISM 0x00551820
void TAdmiral::Victory(short experienceGain) {
  experiencePoints = static_cast<short>(experiencePoints + experienceGain);
  if (experiencePoints >= 500) {
    experiencePoints = 499;
  }
}

// FUNCTION: IMPERIALISM 0x00551850
void TAdmiral::ReassignThyself() {
  if (this->assignedShip != 0) {
    this->assignedShip->admiral = 0;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
  this->assignedShip = 0;

  TShip* best = 0;
  for (TShip* node = g_pNavyPrimaryOrderListHead; node != 0; node = node->next) {
    if (node->nation == this->nationSlot) {
      best = node->Finest(best, 1);
    }
  }

  if (this->assignedShip != 0) {
    this->assignedShip->admiral = 0;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
  this->assignedShip = best;
  if (best != 0) {
    best->admiral = this;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
  if (best == 0) {
    this->Free();
  }
}

// Mac oracle: IsSeniorTo. The original tests the receiver itself for null, so a null
// admiral compares junior to everything and any admiral outranks a null argument.
// FUNCTION: IMPERIALISM 0x00551990
unsigned char TAdmiral::IsSeniorTo(const TAdmiral* other) const {
  if (this == 0) {
    return 0;
  }
  if (other == 0) {
    return 1;
  }
  return experiencePoints > other->experiencePoints;
}

// Mac oracle: TAdmiral::EstimateEnemyForces(short*, const TZone*, short) const.
// FUNCTION: IMPERIALISM 0x00551a00
short TAdmiral::EstimateEnemyForces(short* estimatedCounts, const TZone* zone,
                                    NationSlot nation) const {
  int skill = this == 0 ? 0 : experiencePoints / 100 + 1;
  srand(g_pSimMgr->GetEconomicTurn() + PointerSeedBits(this) + PointerSeedBits(zone) + nation);

  int i;
  for (i = 0; i < 5; ++i) {
    estimatedCounts[i] = 0;
  }

  int total = 0;
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship->nation != nation || ship->location != zone) {
      continue;
    }

    short countRoll = static_cast<short>(rand() % 100);
    short estimatedCount = -1;
    do {
      ++estimatedCount;
      countRoll = static_cast<short>(countRoll +
                                     -g_aNavalIntelligenceAccuracyProfiles[skill][estimatedCount]);
    } while (countRoll > 0);

    short classRoll = static_cast<short>(rand() % 100);
    short classEstimate = -1;
    do {
      ++classEstimate;
      classRoll = static_cast<short>(
          classRoll + -g_aNavalIntelligenceAccuracyProfiles[skill][classEstimate + 3]);
    } while (classRoll > 0);

    if (g_bPerfectNavalIntelligenceCheat != 0 &&
        (static_cast<unsigned short>(GetAsyncKeyState(VK_MENU)) & 0x8000) != 0) {
      classEstimate = 3;
      estimatedCount = 1;
    }

    short category;
    if (classEstimate == 1) {
      category = 4;
    } else if (classEstimate == 2) {
      category = static_cast<short>(rand() % 4);
    } else {
      category = static_cast<short>(g_aIndustryCapabilityClassSlotTable[ship->type].classId);
    }
    estimatedCounts[category] = static_cast<short>(estimatedCounts[category] + estimatedCount);
    total += estimatedCount;
  }
  return static_cast<short>(total);
}

// Mac oracle: TAdmiral::GetFleetReport(CStr255&, TZone*, short) const.
// FUNCTION: IMPERIALISM 0x00551be0
void TAdmiral::GetFleetReport(CString* out, TZone* zone, NationSlot nation) const {
  short estimates[5];
  short total = EstimateEnemyForces(estimates, zone, nation);

  if (total == 0) {
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(out, 0x2762, 0x1e);
    return;
  }

  CString comma;
  CString conjunction;
  CString itemTemplate;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&comma, 0x2762, 0x1f);
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&conjunction, 0x2762, 0x20);
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&itemTemplate, 0x2762, 0x21);
  *out = g_szEmptyString;

  short remaining = total;
  int category;
  for (category = 0; category < 4; ++category) {
    short count = estimates[category];
    if (count <= 0) {
      continue;
    }
    remaining = static_cast<short>(remaining - count);
    if (!out->IsEmpty()) {
      *out += remaining == 0 ? conjunction : comma;
    }
    CString number;
    number.Format(g_szDecimalFormat, static_cast<int>(count));
    CString shipType = GetLocalizedNavalReportShipType(static_cast<short>(category), count != 1);
    CString item;
    scanBracketExpressions(g_pSimMgr, &item, static_cast<LPCSTR>(itemTemplate),
                           static_cast<LPCSTR>(number), static_cast<LPCSTR>(shipType));
    *out += item;
  }

  if (estimates[4] > 0) {
    if (!out->IsEmpty()) {
      *out += conjunction;
    }
    CString number;
    number.Format(g_szDecimalFormat, static_cast<int>(estimates[4]));
    CString unknownTemplate;
    g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(
        &unknownTemplate, 0x2762, static_cast<short>(estimates[4] > 1 ? 0x23 : 0x22));
    CString item;
    scanBracketExpressions(g_pSimMgr, &item, static_cast<LPCSTR>(unknownTemplate),
                           static_cast<LPCSTR>(number));
    *out += item;
  }

  int skill = this == 0 ? 0 : experiencePoints / 100 + 1;
  CString observedComposition = *out;
  CString certaintyTemplate;
  g_pModuleLibraryCacheState->LoadUiStringResourceByGroupAndIndex(&certaintyTemplate, 0x2762,
                                                                  static_cast<short>(skill + 0x24));
  scanBracketExpressions(g_pSimMgr, out, static_cast<LPCSTR>(certaintyTemplate),
                         static_cast<LPCSTR>(observedComposition));
}

// Mac oracle: EstimateStrengthRating.
// FUNCTION: IMPERIALISM 0x00552160
int TAdmiral::EstimateStrengthRating(const TTaskForce* force, int unusedArg) const {
  (void)unusedArg;
  int total = 0;
  for (TMapOrderChildLinkNode* node = force->shipList; node != nullptr; node = node->next) {
    total += static_cast<TShip*>(node->payload)->GetBattleStrengthRating();
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00552250
void TAdmiral::AssignToShip(TShip* primaryOrderNode) {
  if (this->assignedShip != 0) {
    this->assignedShip->admiral = 0;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
  this->assignedShip = primaryOrderNode;
  if (primaryOrderNode != 0) {
    primaryOrderNode->admiral = this;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
}

// The original function extends from 0x552310 through 0x552404. Earlier inventory
// rows incorrectly treated its loop body as three independent orphan functions.
// FUNCTION: IMPERIALISM 0x00552310
void TAdmiral::ReassignToZone(TZone* zone) {
  if (this->assignedShip != 0) {
    this->assignedShip->admiral = 0;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
  this->assignedShip = 0;

  TShip* best = 0;
  for (TShip* node = g_pNavyPrimaryOrderListHead; node != 0; node = node->next) {
    if (node->location == zone && node->nation == this->nationSlot) {
      best = node->Finest(best, 1);
    }
  }

  if (this->assignedShip != 0) {
    this->assignedShip->admiral = 0;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
  this->assignedShip = best;
  if (best != 0) {
    best->admiral = this;
    RecomputeMapOrderOwnerActiveSelection(this->assignedShip->taskForce);
  }
}

// Mac oracle: TAdmiral::NameThyself(). Rebuilds this admiral's generated name and
// repeats when it collides with another live admiral.
// FUNCTION: IMPERIALISM 0x00552450
void TAdmiral::NameThyself() {
  g_apTerrainTypeDescriptorTable[this->nationSlot]->GenerateEthnicName(&this->displayName);
  for (TAdmiral* node = g_pNavySecondaryOrderListHead; node != 0; node = node->next) {
    if (node == this) {
      continue;
    }
    if (node->displayName.Compare(this->displayName) == 0) {
      this->NameThyself();
    }
  }
}

// Genuine cdecl by-value helper (the caller cleans its hidden return pointer and two
// arguments). It maps the four report categories back to an enabled ship resource.
// FUNCTION: IMPERIALISM 0x00557320
CString GetLocalizedNavalReportShipType(short category, char plural) {
  short resourceType = 0;
  int i;
  for (i = 13; i > 0; --i) {
    if (g_aIndustryCapabilityClassSlotTable[i].classId == category &&
        g_pTechMgr->resourceTypeEnabled19d[i] != 0) {
      resourceType = static_cast<short>(i);
      break;
    }
  }
  CString result;
  g_pSimMgr->GetString(plural != 0 ? 0x271a : 0x2716, resourceType, &result);
  return result;
}

// FUNCTION: IMPERIALISM 0x005573f0
TAdmiral* TAdmiral::CreateForTerrainType(NationSlot terrainTypeIndex) {
  TAdmiral* admiral = new TAdmiral(terrainTypeIndex);
  if (admiral == 0) {
    MessageBoxA(0, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UNavy.cpp", 0xe21);
  }
  return admiral;
}
