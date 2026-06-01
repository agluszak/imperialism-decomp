// Diplomacy turn-state backend reconstruction.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

namespace {
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kVtableDiplomacyTurnStateManager = 0x00654D90;
} // namespace

struct DiplomacyTurnStateManager {
  void* vftable;
  unsigned char pad04[0x78a];
  short field78e;
  short field790;
  unsigned char pad792[2];
  int field794;
  int field798;
  unsigned char pad79c[0x18d4 - 0x79c];
  void* pendingWarTransitionQueue18d4;

  void ConstructDiplomacyTurnStateManager_Vtbl00654d90();
  char IsNationPairAtWar(int sourceNationSlot, int targetNationSlot);
  char HasAnyWarRelationForNation(int sourceNationSlot);
  char HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot);
  void QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot);
};

struct WarTransitionPair {
  short sourceNationSlot;
  short targetNationSlot;
};

// FUNCTION: IMPERIALISM 0x004ee6c0
void DiplomacyTurnStateManager::ConstructDiplomacyTurnStateManager_Vtbl00654d90() {
  char* self = reinterpret_cast<char*>(this);
  int zero = 0;
  *reinterpret_cast<int*>(self + 0x794) = zero;
  *reinterpret_cast<int*>(self + 0x798) = zero;
  *reinterpret_cast<void**>(self) = reinterpret_cast<void*>(kVtableDiplomacyTurnStateManager);
  *reinterpret_cast<short*>(self + 0x790) = static_cast<short>(zero);
  *reinterpret_cast<short*>(self + 0x78e) = static_cast<short>(-1);
}

// FUNCTION: IMPERIALISM 0x004ef540
char DiplomacyTurnStateManager::IsNationPairAtWar(int sourceNationSlot, int targetNationSlot) {
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if ((reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable)[source] != 0) &&
      (reinterpret_cast<void**>(kAddrTerrainTypeDescriptorTable)[target] != 0)) {
    return VCall_Diplomacy_GetRelationTierSlot70(this, sourceNationSlot, targetNationSlot) == 6;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef600
char DiplomacyTurnStateManager::HasAnyWarRelationForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (VCall_Diplomacy_HasPolicyWithNationSlot44(this, sourceNationSlot, targetNationSlot) != 0) {
      return 1;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef650
char DiplomacyTurnStateManager::HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (VCall_Diplomacy_HasOutdatedWarRelationSlot48(this, sourceNationSlot, targetNationSlot) !=
        0) {
      return 1;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004f09c0
void DiplomacyTurnStateManager::QueueNationPairWarTransition(int sourceNationSlot,
                                                             int targetNationSlot) {
  WarTransitionPair pair;
  pair.sourceNationSlot = static_cast<short>(sourceNationSlot);
  pair.targetNationSlot = static_cast<short>(targetNationSlot);
  VCall_WarTransitionQueue_PushPairSlot40(pendingWarTransitionQueue18d4, &pair);
  VCall_Diplomacy_SetRelationCodeSlot74WithMode(this, sourceNationSlot, targetNationSlot, 6, 1);
}
