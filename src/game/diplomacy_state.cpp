// Diplomacy turn-state backend reconstruction.

#include "decomp_types.h"
#include "game/TIndexAndRankList.h"
#include "game/TSortedByRelationshipList.h"
#include "game/TSortedPtrList.h"
#include "game/CString.h"
#include "game/TDiplomacyTurnStateManager.h"
#include "game/NationState.h"
#include "game/generated/vcall_facades.h"
#include <new>

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
void* g_apTerrainTypeDescriptorTable[23] = {0};
extern void* g_apNationStates[7];
void* g_apNationStates_End = 0;
void* g_pLocalizationTable = 0;
void* g_pInterNationEventQueueManager = 0;
void* g_pGlobalUiRootController = 0;
void* g_pGameFlowState = 0;
TDiplomacyTurnStateManager*  g_pDiplomacyTurnStateManager = 0;
char vtbl_DiplomacyTurnStateManager_00654d90 = 0;
char vtbl_TurnEventNextPacket_00654e50 = 0;
char g_vtblTSortedByRelationshipList = 0;
}

namespace {
const unsigned int kVtableTurnEventNextPacket = 0x00654E50;
const unsigned int kTurnEventTagNext = 0x4E655854; // 'NeXT'
// Scratch shared-string RAII local: ctor installs the empty shared-string ref,
// dtor releases it. ApplyDiplomacyInterNationStatesForTurn declares four of these,
// which reproduces the MSVC EH cleanup frame and the staged construct/destruct
// (ehstate 0->1->2->3 up, reverse down) seen in the original 0x004f01e0 body.
struct ScratchSharedString {
  CString str;
  ScratchSharedString() { str.InitFromEmpty(); }
};

} // namespace

undefined4 thunk_InitializeRangePairAndResetCursor(void);
undefined4 thunk_QueueInterNationEventRecordDeduped(void);
undefined4 thunk_EmitTurnEvent3Mode18WithActiveNation(void);
undefined4 thunk_IsNationSlotEligibleForEventProcessing(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);

struct TurnEventQueue {
  virtual void teq_slot0() = 0; virtual void teq_slot1() = 0; virtual void teq_slot2() = 0; virtual void teq_slot3() = 0;
  virtual void teq_slot4() = 0; virtual void teq_slot5() = 0; virtual void teq_slot6() = 0; virtual void teq_slot7() = 0;
  virtual void teq_slot8() = 0; virtual void teq_slot9() = 0; virtual void teq_slot10() = 0; virtual void teq_slot11() = 0;
  virtual void teq_slot12() = 0; virtual void teq_slot13() = 0;
  virtual void EnqueueSlot38(void* packet) = 0; // 14 (0x38)
};

struct LocalizationTable {
  virtual void loc_slot0() = 0; virtual void loc_slot1() = 0; virtual void loc_slot2() = 0; virtual void loc_slot3() = 0;
  virtual void loc_slot4() = 0; virtual void loc_slot5() = 0; virtual void loc_slot6() = 0; virtual void loc_slot7() = 0;
  virtual void loc_slot8() = 0; virtual void loc_slot9() = 0; virtual void loc_slot10() = 0; virtual void loc_slot11() = 0;
  virtual void loc_slot12() = 0; virtual void loc_slot13() = 0; virtual void loc_slot14() = 0; virtual void loc_slot15() = 0;
  virtual void loc_slot16() = 0;
  virtual void CallSlot44() = 0; // 17 (0x44)
};

struct WarTransitionQueue {
  virtual void wtq_slot0() = 0; virtual void wtq_slot1() = 0; virtual void wtq_slot2() = 0; virtual void wtq_slot3() = 0;
  virtual void wtq_slot4() = 0; virtual void wtq_slot5() = 0; virtual void wtq_slot6() = 0; virtual void wtq_slot7() = 0;
  virtual void wtq_slot8() = 0; virtual void wtq_slot9() = 0; virtual void wtq_slot10() = 0; virtual void wtq_slot11() = 0;
  virtual void RemoveFirstPairSlot30(int mode) = 0; // 12 (0x30)
  virtual void* PeekFirstPairSlot34() = 0; // 13 (0x34)
  virtual void wtq_slot14() = 0; // 14 (0x38)
  virtual void wtq_slot15() = 0; // 15 (0x3c)
  virtual void PushPairSlot40(void* pair) = 0; // 16 (0x40)
};

struct TerrainDescriptor {
  virtual void td_slot0() = 0; virtual void td_slot1() = 0; virtual void td_slot2() = 0; virtual void td_slot3() = 0;
  virtual void td_slot4() = 0; virtual void td_slot5() = 0; virtual void td_slot6() = 0; virtual void td_slot7() = 0;
  virtual void td_slot8() = 0; virtual void td_slot9() = 0; virtual void td_slot10() = 0; virtual void td_slot11() = 0;
  virtual void td_slot12() = 0; virtual void td_slot13() = 0; virtual void td_slot14() = 0; virtual void td_slot15() = 0;
  virtual void td_slot16() = 0; virtual void td_slot17() = 0;
  virtual void SetDiplomacyStandingSlot48(int targetNation, int standing) = 0; // 18 (0x48)
  virtual void td_slot19() = 0; // 19 (0x4c)
  virtual void td_slot20() = 0; // 20 (0x50)
  virtual void td_slot21() = 0; // 21 (0x54)
  virtual void td_slot22() = 0; // 22 (0x58)
  virtual char HasMinorStandingLinkSlot5C(int sourceNation) = 0; // 23 (0x5c)
  virtual void td_slot24() = 0; virtual void td_slot25() = 0; virtual void td_slot26() = 0; virtual void td_slot27() = 0;
  virtual void td_slot28() = 0; virtual void td_slot29() = 0; virtual void td_slot30() = 0; virtual void td_slot31() = 0;
  virtual void td_slot32() = 0; virtual void td_slot33() = 0; virtual void td_slot34() = 0;
  virtual void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode) = 0; // 35 (0x8c)
  virtual char HasStandingPropagationBridgeSlot90(int targetNation) = 0; // 36 (0x90)
  virtual void NotifyRelationCode4TargetSlot94(int sourceNation, int actionCode) = 0; // 37 (0x94)
};


struct TCountry {
  void thunk_QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB, char isReplayBypass);
};

struct WarTransitionPair {
  short sourceNationSlot;
  short targetNationSlot;
};

struct RelationshipRankEntry {
  short nationSlot;
  short standingScore;
};

// The pending-war-transition queue and the relationship-candidate list were
// previously modeled as two local raw structs (a TSortedPtrList-shaped
// `TSortedByRelationshipList` with vtable 0x00649068, and a
// TSortedByRelationshipList-shaped `RelationshipCandidateList` with vtable
// 0x00654d38). Both are now the grounded foundation classes:
//   - queue (slot 0x18d4)     -> TSortedPtrList            (vtable 0x00649068)
//   - relationship candidates -> TSortedByRelationshipList (vtable 0x00654d38)
// Evidence: identical field layout (CPtrArray entries/count/capacity/growBy +
// short relationType/pad16) and the exact vtable each ctor installs.

struct TurnEventPacket {
  void* vftable;
  int rangeStart;
  int rangeEnd;
  int cursor;
  int rangeEndCopy;
  int field14;

  void thunk_ConstructTurnEventPacketBase();
  void thunk_InitializeRangePairAndResetCursor(int rangeStart, int rangeEnd, int arg3, int arg4, int arg5);

  TurnEventPacket() {
    thunk_ConstructTurnEventPacketBase();
    vftable = &vtbl_TurnEventNextPacket_00654e50;
  }

  void* operator new(size_t size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    // Empty
  }
};

static __inline void QueueInterNationEventRecordDeduped(void* countryState, int eventCode,
                                                       int nationA, int nationB,
                                                       char isReplayBypass) {
  reinterpret_cast<TCountry*>(countryState)->thunk_QueueInterNationEventRecordDeduped(
      eventCode, nationA, nationB, isReplayBypass);
}

static __inline char IsNationSlotEligibleForEventProcessingFast(int nationSlot) {
  return reinterpret_cast<char(__cdecl*)(int)>(thunk_IsNationSlotEligibleForEventProcessing)(
      nationSlot);
}

// FUNCTION: IMPERIALISM 0x00406758
void TCountry::thunk_QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB, char isReplayBypass) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, int, int, char)>(
      0x0055c9f0)(this, 0, eventCode, nationA, nationB, isReplayBypass);
}

static __inline void InitializeRangePairAndResetCursor(TurnEventPacket* packet, int rangeStart,
                                                       int rangeEnd) {
  packet->thunk_InitializeRangePairAndResetCursor(rangeStart, rangeEnd, 0, 0, 0);
}

static __inline void EmitTurnEvent3Mode18WithActiveNation(void) {
  reinterpret_cast<void(__cdecl*)(void)>(thunk_EmitTurnEvent3Mode18WithActiveNation)();
}

static __inline void EmitTurnEvent3Mode18WithActiveNation(void* controller) {
  reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_EmitTurnEvent3Mode18WithActiveNation)(
      controller, 0);
}



static __inline TDiplomacyTurnStateManager*  ReadGlobalTDiplomacyTurnStateManager() {
  return reinterpret_cast<TDiplomacyTurnStateManager* >(g_pDiplomacyTurnStateManager);
}

// FUNCTION: IMPERIALISM 0x004ee6c0
TDiplomacyTurnStateManager*  TDiplomacyTurnStateManager::ConstructTDiplomacyTurnStateManager_Vtbl00654d90() {
  int zero = 0;
  queuedWarTransitionActive794 = zero;
  queuedWarTransitionPending798 = zero;
  *reinterpret_cast<void**>(this) = &vtbl_DiplomacyTurnStateManager_00654d90;
  proposalDispatchCounter790 = static_cast<short>(zero);
  lastProcessedNationSlot78e = static_cast<short>(-1);
  return this;
}

// FUNCTION: IMPERIALISM 0x00409944
TDiplomacyTurnStateManager*  TDiplomacyTurnStateManager::thunk_ConstructTDiplomacyTurnStateManager_Vtbl00654d90() {
  return ConstructTDiplomacyTurnStateManager_Vtbl00654d90();
}

// FUNCTION: IMPERIALISM 0x004ee7a0
void TDiplomacyTurnStateManager::InitializeTDiplomacyTurnStateManagerDefaults() {
  TSortedPtrList* queue = new TSortedPtrList();
  queue->relationType = 4;
  pendingWarTransitionQueue18d4 = queue;

  register int zero = 0;

  short* relationCode = relationCodeMatrix04;
  unsigned char* pendingPolicyCode = pendingPolicyCodeMatrix304;
  int pairCount = kDiplomacyPairMatrixEntries;

  do {
    *relationCode = static_cast<short>(zero);
    *pendingPolicyCode = 0xff;
    ++relationCode;
    ++pendingPolicyCode;
    --pairCount;
  } while (pairCount != 0);

  selectedSourceNationSlot784 = static_cast<short>(-1);
  selectedTargetNationSlot786 = static_cast<short>(-1);
  selectionFlagsA788 = static_cast<short>(zero);
  selectionFlagsB78a = static_cast<short>(zero);
  selectionFlagsC78c = static_cast<short>(zero);
  proposalArrayMode18d8 = static_cast<short>(zero);

  short* rowStart = relationTurnStampMatrixFe0;
  int rowCount = kNationSlotCount;

  do {
    short* linearTurnStamp = rowStart;
    short* transposeTurnStamp = rowStart;
    int columnCount = kNationSlotCount;

    do {
      *linearTurnStamp = static_cast<short>(-1);
      *transposeTurnStamp = static_cast<short>(-1);

      ++linearTurnStamp;
      transposeTurnStamp += kNationSlotCount;

      --columnCount;
    } while (columnCount != 0);

    ++rowStart;
    --rowCount;
  } while (rowCount != 0);
}

// FUNCTION: IMPERIALISM 0x00403837
void TDiplomacyTurnStateManager::thunk_InitializeTDiplomacyTurnStateManagerDefaults() {
  InitializeTDiplomacyTurnStateManagerDefaults();
}

// FUNCTION: IMPERIALISM 0x004ef540
char TDiplomacyTurnStateManager::IsNationPairAtWar(int sourceNationSlot, int targetNationSlot) {
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
      (g_apTerrainTypeDescriptorTable[target] != 0)) {
    return GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 6;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef590
char TDiplomacyTurnStateManager::IsNationPairRelationTurnStampOutOfDate(int sourceNationSlot,
                                                                       int targetNationSlot) {
  if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) == 0) {
    return 0;
  }
  short currentTurn =
      VCall_LocalizationRuntime_GetTurnTick(g_pLocalizationTable);
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  return relationTurnStampMatrixFe0[source * kNationSlotCount + target] != currentTurn;
}

// FUNCTION: IMPERIALISM 0x004ef600
char TDiplomacyTurnStateManager::HasAnyWarRelationForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      return 1;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef650
char TDiplomacyTurnStateManager::HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot) {
  int targetNationSlot = 0;
  do {
    if (HasOutdatedWarRelationSlot48(sourceNationSlot, targetNationSlot) !=
        0) {
      return 1;
    }
    targetNationSlot++;
  } while (targetNationSlot < 0x17);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef700
char TDiplomacyTurnStateManager::ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
    int sourceNationSlot, int targetNationSlot, int actionCode) {
  char isValid = 0;
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if (target == source) {
    ReadGlobalTDiplomacyTurnStateManager()->proposalArrayMode18d8 = 0xe;
    return isValid;
  }

  void* targetTerrain = (&g_apTerrainTypeDescriptorTable)[target];
  short targetTerrainOwner = *reinterpret_cast<short*>(reinterpret_cast<char*>(targetTerrain) + 0xe);
  if (targetTerrainOwner != -1) {
    if (targetTerrainOwner >= 200) {
      proposalArrayMode18d8 = 0xc;
      return isValid;
    }
    proposalArrayMode18d8 = 0xd;
    return isValid;
  }

  int pairIndex = source * kNationSlotCount + target;
  switch (actionCode) {
  case 2:
    if (relationSideEffectMatrix1402[pairIndex] != 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (target < 7) {
      proposalArrayMode18d8 = 0x12;
      return isValid;
    }
    break;
  case 3:
    if (target > 6) {
      proposalArrayMode18d8 = 3;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 2) {
      proposalArrayMode18d8 = 0x11;
      return isValid;
    }
    break;
  case 4:
    if (relationSideEffectMatrix1402[pairIndex] != 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 3) {
      proposalArrayMode18d8 = 0x10;
      return isValid;
    }
    if (target < 7) {
      proposalArrayMode18d8 = 0xf;
      return isValid;
    }
    break;
  case 5:
    if (HasOutdatedWarRelationSlot48(sourceNationSlot, targetNationSlot) ==
        0) {
      proposalArrayMode18d8 = 5;
      return isValid;
    }
    break;
  case 6:
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 6;
      return isValid;
    }
    break;
  case 7:
  case 8:
    if (relationSideEffectMatrix1402[pairIndex] < 2) {
      proposalArrayMode18d8 = 1;
      return isValid;
    }
    break;
  case 9:
  case 10:
    if (relationSideEffectMatrix1402[pairIndex] == 0) {
      proposalArrayMode18d8 = 7;
      return isValid;
    }
    break;
  case 11:
    if (GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 2) {
      proposalArrayMode18d8 = 8;
      return isValid;
    }
    break;
  case 14:
    if (relationSideEffectMatrix1402[pairIndex] != 0) {
      proposalArrayMode18d8 = 9;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(
            g_apNationStates[source]) +
                                0x10) < 500) {
      proposalArrayMode18d8 = 0x16;
      return isValid;
    }
    break;
  case 15:
    if (relationSideEffectMatrix1402[pairIndex] == 0) {
      proposalArrayMode18d8 = 0xa;
      return isValid;
    }
    if (relationSideEffectMatrix1402[pairIndex] == 2) {
      proposalArrayMode18d8 = 0xb;
      return isValid;
    }
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) != 0) {
      proposalArrayMode18d8 = 2;
      return isValid;
    }
    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(
            g_apNationStates[source]) +
                                0x10) < 5000) {
      proposalArrayMode18d8 = 0x15;
      return isValid;
    }
    break;
  }
  isValid = 1;
  return isValid;
}

// FUNCTION: IMPERIALISM 0x004efc30
char TDiplomacyTurnStateManager::HasAllianceGuardSlot60(int nationSlot, int guardedNationSlot) {
  if (ReadGlobalTDiplomacyTurnStateManager()->HasAnyWarRelationForNation(nationSlot) == 0) {
    return 0;
  }

  int primaryNationSlot = 0;
  do {
    if (HasPolicyWithNationSlot44(primaryNationSlot, nationSlot) != 0 &&
        HasPolicyWithNationSlot44(guardedNationSlot, primaryNationSlot) == 0) {
      return 1;
    }
    primaryNationSlot++;
  } while (primaryNationSlot < 7);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004efcb0
void TDiplomacyTurnStateManager::SetStandingScoreSlot28(int sourceNationSlot, int targetNationSlot,
                                                       int standingScore) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  int forwardIndex = source * kNationSlotCount + target;
  short* forwardScore = &relationStandingScoreMatrix79c[forwardIndex];
  short requestedScore = static_cast<short>(standingScore);
  if (requestedScore == *forwardScore) {
    return;
  }

  int clampedScore = requestedScore;
  if (requestedScore < 0) {
    clampedScore = 0;
  }
  if (requestedScore > 0xff && static_cast<short>(sourceNationSlot) != static_cast<short>(targetNationSlot)) {
    clampedScore = 0xff;
  }
  if (requestedScore <= 0x31) {
    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) == 0) {
      clampedScore = 0x32;
    } else {
      clampedScore = requestedScore;
    }
    if (static_cast<short>(clampedScore) < 0) {
      clampedScore = 0;
    }
  }

  *forwardScore = static_cast<short>(clampedScore);
  int reverseIndex = target * kNationSlotCount + source;
  relationStandingScoreMatrix79c[reverseIndex] = static_cast<short>(clampedScore);

  if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
    int minorNationSlot = 7;
    void** terrainCursor = &g_apTerrainTypeDescriptorTable[7];
    do {
      TerrainDescriptor* terrain = reinterpret_cast<TerrainDescriptor*>(*terrainCursor);
      if (terrain != 0 && terrain->HasMinorStandingLinkSlot5C(sourceNationSlot) != 0) {
        CopyDiplomacyStandingMatrixRowAndColumnSlot2c(minorNationSlot, sourceNationSlot);
      }
      terrainCursor++;
      minorNationSlot++;
    } while (reinterpret_cast<int>(terrainCursor) < reinterpret_cast<int>(&g_apTerrainTypeDescriptorTable[23]));
  }

  if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
    int minorNationSlot = 7;
    void** terrainCursor = &g_apTerrainTypeDescriptorTable[7];
    do {
      TerrainDescriptor* terrain = reinterpret_cast<TerrainDescriptor*>(*terrainCursor);
      if (terrain != 0 && terrain->HasMinorStandingLinkSlot5C(targetNationSlot) != 0) {
        CopyDiplomacyStandingMatrixRowAndColumnSlot2c(minorNationSlot, targetNationSlot);
      }
      terrainCursor++;
      minorNationSlot++;
    } while (reinterpret_cast<int>(terrainCursor) < reinterpret_cast<int>(&g_apTerrainTypeDescriptorTable[23]));
  }
}

// FUNCTION: IMPERIALISM 0x004efe30
void TDiplomacyTurnStateManager::CopyDiplomacyStandingMatrixRowAndColumnSlot2c(
    int destinationNationSlot, int sourceNationSlot) {
  short* destinationColumnCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(destinationNationSlot)];
  short* destinationRowCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(destinationNationSlot) *
                                      kNationSlotCount];
  short* sourceRowCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(sourceNationSlot) *
                                      kNationSlotCount];
  short* sourceColumnCursor =
      &relationStandingScoreMatrix79c[static_cast<short>(sourceNationSlot)];

  int remaining = kNationSlotCount;
  do {
    *destinationRowCursor = *sourceRowCursor;
    sourceRowCursor++;
    *destinationColumnCursor = *sourceColumnCursor;
    destinationRowCursor++;
    sourceColumnCursor += kNationSlotCount;
    destinationColumnCursor += kNationSlotCount;
    remaining--;
  } while (remaining != 0);
}

// FUNCTION: IMPERIALISM 0x004eff40
void TDiplomacyTurnStateManager::PropagateRelationSideEffectSlot80(int sourceNationSlot,
                                                                  int targetNationSlot,
                                                                  int updateMode) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  short sourceTargetStanding =
      relationStandingScoreMatrix79c[source * kNationSlotCount + target];

  if (static_cast<char>(updateMode) == 1) {
    if (sourceTargetStanding - 0x32 < 0x31) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, sourceTargetStanding - 0x32);
    } else {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0x31);
    }
  } else {
    int adjustment = ((0x5a - sourceTargetStanding) * sourceTargetStanding) / 200;
    if (static_cast<short>(adjustment) < 0) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot,
                             sourceTargetStanding + adjustment);
    }
  }

  int candidateNationSlot = 0;
  int candidateOrdinal = 0;
  void** terrainCursor = g_apTerrainTypeDescriptorTable;
  do {
    TerrainDescriptor* candidateTerrain = reinterpret_cast<TerrainDescriptor*>(*terrainCursor);
    if (IsNationSlotEligibleForEventProcessingFast(candidateNationSlot) != 0 &&
        static_cast<short>(candidateNationSlot) != static_cast<short>(sourceNationSlot) &&
        static_cast<short>(candidateNationSlot) != static_cast<short>(targetNationSlot) &&
        *reinterpret_cast<short*>(reinterpret_cast<char*>(candidateTerrain) + 0xe) == -1) {
      int divisorTier;
      if (HasFlag84ForNationSlot84(targetNationSlot) == 0) {
        if (HasFlag84ForNationSlot84(candidateNationSlot) == 0) {
          divisorTier =
              candidateTerrain->HasStandingPropagationBridgeSlot90(sourceNationSlot) != 0 ? 2 : 4;
        } else {
          divisorTier = 8;
        }
      } else {
        divisorTier = HasFlag84ForNationSlot84(candidateNationSlot) != 0 ? 4 : 8;
      }

      short currentStanding =
          relationStandingScoreMatrix79c[source * kNationSlotCount + candidateNationSlot];
      short targetCandidateStanding =
          relationStandingScoreMatrix79c[target * kNationSlotCount + candidateNationSlot];
      int candidateAdjustment =
          ((0x5a - targetCandidateStanding) * candidateOrdinal) / (divisorTier * 0x32);
      if (static_cast<char>(sourceNationSlot) == 0) {
        candidateAdjustment = static_cast<short>(candidateAdjustment) / 2;
      }

      short delta = static_cast<short>(candidateAdjustment);
      int appliedDelta = delta;
      if (currentStanding < 0x32) {
        if (delta > 0 && currentStanding + delta > 0x31) {
          appliedDelta = 0x31 - currentStanding;
        }
      } else if (currentStanding + delta < 0x32) {
        appliedDelta = 0x32 - currentStanding;
      }
      SetStandingScoreSlot28(sourceNationSlot, candidateNationSlot,
                             currentStanding + appliedDelta);
    }

    candidateNationSlot++;
    candidateOrdinal++;
    terrainCursor++;
  } while (static_cast<short>(candidateNationSlot) <= 0x16);
}

// FUNCTION: IMPERIALISM 0x004f09c0
void TDiplomacyTurnStateManager::QueueNationPairWarTransition(int sourceNationSlot,
                                                             int targetNationSlot) {
  WarTransitionPair pair;
  pair.sourceNationSlot = static_cast<short>(sourceNationSlot);
  pair.targetNationSlot = static_cast<short>(targetNationSlot);
  VCall_WarTransitionQueue_PushPairSlot40(pendingWarTransitionQueue18d4, &pair);
  SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, 6, 1);
}

// FUNCTION: IMPERIALISM 0x004f19c0
int TDiplomacyTurnStateManager::GetNationPairDiplomacyStandingTierCode(int sourceNationSlot,
                                                                      int targetNationSlot) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  short standingScore =
      relationStandingScoreMatrix79c[source * kNationSlotCount + target];
  if (standingScore <= 0x14) {
    return 0;
  }
  if (standingScore <= 0x31) {
    return 1;
  }
  if (standingScore <= 0x4f) {
    return 2;
  }
  if (standingScore <= 0x64) {
    return 3;
  }
  if (standingScore <= 0x87) {
    return 4;
  }
  if (standingScore <= 0xaa) {
    return 5;
  }
  if (standingScore <= 0xcd) {
    return 6;
  }
  return (standingScore > 0xf0) + 7;
}

// FUNCTION: IMPERIALISM 0x004f1b10
short TDiplomacyTurnStateManager::GetNationPairDiplomacyRelationCode(int sourceNationSlot,
                                                                    int targetNationSlot) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  return relationPropagationMatrixBbe[source * kNationSlotCount + target];
}

// FUNCTION: IMPERIALISM 0x004f1b40
void TDiplomacyTurnStateManager::SetNationPairDiplomacyRelationCodeFinal(
    int sourceNationSlot, int targetNationSlot, int relationCode) {
  SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, relationCode, 1);
}

// FUNCTION: IMPERIALISM 0x004efeb0
void TDiplomacyTurnStateManager::ApplyRelationCode4AndQueueEvent18ForTargetNation(
    int sourceNationSlot, int targetNationSlot, int updateMode) {
  SetRelationCodeSlot78Final(sourceNationSlot, targetNationSlot, 4);
  if (static_cast<char>(updateMode) == 1) {
    PropagateRelationSideEffectSlot80(sourceNationSlot, targetNationSlot, 0);
  }

  TerrainDescriptor* targetTerrain = reinterpret_cast<TerrainDescriptor*>(
      g_apTerrainTypeDescriptorTable[static_cast<short>(targetNationSlot)]);
  if (targetTerrain != 0) {
    targetTerrain->NotifyRelationCode4TargetSlot94(sourceNationSlot, 0x139);
    QueueInterNationEventRecordDeduped(g_pInterNationEventQueueManager, 0x18,
                                       static_cast<short>(targetNationSlot),
                                       static_cast<short>(sourceNationSlot), 0);
  }
}

// FUNCTION: IMPERIALISM 0x004f2050
int TDiplomacyTurnStateManager::CountMajorAllianceRelationsForNation(int sourceNationSlot) {
  int allianceCount = 0;
  short* relationCursor = &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
  int remainingMajorNationSlots = 7;
  do {
    if (*relationCursor == 2) {
      allianceCount++;
    }
    relationCursor++;
    remainingMajorNationSlots--;
  } while (remainingMajorNationSlots != 0);
  return allianceCount;
}

// FUNCTION: IMPERIALISM 0x004f2090
int TDiplomacyTurnStateManager::GetNthAlliedMajorNationSlotForNation(int nthAllianceIndex,
                                                                    int sourceNationSlot) {
  int allianceOrdinal = 0;
  int candidateNationSlot = 0;
  do {
    if (allianceOrdinal == nthAllianceIndex + 1) {
      return candidateNationSlot - 1;
    }
    if (relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount + candidateNationSlot] ==
        2) {
      allianceOrdinal++;
    }
    candidateNationSlot++;
  } while (candidateNationSlot < 7);
  return candidateNationSlot - 1;
}

// FUNCTION: IMPERIALISM 0x004f1f50
char TDiplomacyTurnStateManager::IsPrimaryNationSlotIndex(int nationSlot) {
  return static_cast<short>(nationSlot) < 7;
}

// FUNCTION: IMPERIALISM 0x004f1f70
void TDiplomacyTurnStateManager::BuildRelationshipListSlot88(int sourceNationSlot,
                                                            int primaryOnlyFlag, void* list) {
  short candidateNationSlot;
  short lastNationSlot;
  if (static_cast<short>(primaryOnlyFlag) == 0) {
    candidateNationSlot = 7;
    lastNationSlot = 0x16;
  } else {
    candidateNationSlot = 0;
    lastNationSlot = 6;
  }

  if (candidateNationSlot > lastNationSlot) {
    return;
  }

  int candidateIndex = static_cast<short>(candidateNationSlot);
  void** terrainCursor = &g_apTerrainTypeDescriptorTable[candidateIndex];
  do {
    void* terrain = *terrainCursor;
    if (terrain != 0 &&
        *reinterpret_cast<short*>(reinterpret_cast<char*>(terrain) + 0xe) == -1 &&
        candidateNationSlot != static_cast<short>(sourceNationSlot)) {
      RelationshipRankEntry entry;
      entry.nationSlot = candidateNationSlot;
      int source = static_cast<short>(sourceNationSlot);
      entry.standingScore =
          relationStandingScoreMatrix79c[source * kNationSlotCount + candidateIndex];
      VCall_RelationshipList_AddEntrySlot38(list, &entry);
    }
    candidateNationSlot++;
    candidateIndex++;
    terrainCursor++;
  } while (candidateNationSlot <= lastNationSlot);
}

// FUNCTION: IMPERIALISM 0x004f2100
int TDiplomacyTurnStateManager::SelectNationSlotFromCollectedStandingEntriesSlot98(
    int sourceNationSlot, int primaryOnlyFlag) {
  TSortedByRelationshipList* list = new TSortedByRelationshipList();
  list->relationType = 4;
  BuildRelationshipListSlot88(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
  if (list->count < 1) {
    return -1;
  }

  RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
      VCall_RelationshipList_GetEntrySlot2C(list, list->count));
  int nationSlot = entry->nationSlot;
  if (list != 0) {
    VCall_RelationshipList_ReleaseSlot24(list);
  }
  return nationSlot;
}

// FUNCTION: IMPERIALISM 0x004f21f0
int TDiplomacyTurnStateManager::SelectDiplomacyTargetNationFromCandidateSetSlot94(
    int sourceNationSlot, int primaryOnlyFlag, int sideEffectCode) {
  if (static_cast<short>(sideEffectCode) == 0) {
    return SelectNationSlotFromCollectedStandingEntriesSlot98(sourceNationSlot, primaryOnlyFlag);
  }

  TSortedByRelationshipList* list = new TSortedByRelationshipList();
  list->relationType = 4;
  BuildRelationshipListSlot88(sourceNationSlot, static_cast<char>(primaryOnlyFlag), list);
  int entryIndex = list->count;
  if (entryIndex < 1) {
    return -1;
  }

  int matchedNationSlot = -1;
  while (entryIndex > 0 && matchedNationSlot == -1) {
    RelationshipRankEntry* entry = static_cast<RelationshipRankEntry*>(
        VCall_RelationshipList_GetEntrySlot2C(list, entryIndex));
    int candidateNationSlot = entry->nationSlot;
    int source = static_cast<short>(sourceNationSlot);
    if (relationSideEffectMatrix1402[source * kNationSlotCount + candidateNationSlot] ==
        static_cast<short>(sideEffectCode)) {
      matchedNationSlot = candidateNationSlot;
    }
    entryIndex--;
  }

  if (list != 0) {
    VCall_RelationshipList_ReleaseSlot24(list);
  }
  return matchedNationSlot;
}

// FUNCTION: IMPERIALISM 0x004f01e0
void TDiplomacyTurnStateManager::ApplyDiplomacyInterNationStatesForTurn() {
  // Pre-pass (unless localization phase 2): run the per-nation begin-turn slot 0x1c8
  // over the seven majors descending, gated on the nation's eligibility byte at +0xa0.
  if (reinterpret_cast<int*>(g_pLocalizationTable)[0x11] != 2) {
    void** nationCursor = &g_apNationStates[6];
    int remaining = 7;
    do {
      int* nation = reinterpret_cast<int*>(*nationCursor);
      if (nation != 0 && static_cast<char>(nation[0x28]) == 0) {
        reinterpret_cast<NationState*>(nation)->BeginTurnDiplomacyPrePassSlot1c8();
      }
      --nationCursor;
      --remaining;
    } while (remaining != 0);
  }

  // Four scratch shared strings held live across the pass (EH-RAII frame).
  ScratchSharedString scratch0;
  ScratchSharedString scratch1;
  ScratchSharedString scratch2;
  ScratchSharedString scratch3;

  if (reinterpret_cast<int*>(g_pLocalizationTable)[0x11] == 2) {
    void** nationCursor = &g_apNationStates[6];
    int remaining = 7;
    do {
      if (*nationCursor != 0) {
        reinterpret_cast<NationState*>(*nationCursor)->RefreshTurnDiplomacyStateSlot1cc();
      }
      --nationCursor;
      --remaining;
    } while (remaining != 0);
  } else {
    void** nationCursor = g_apNationStates;
    int remaining = 7;
    do {
      if (*nationCursor != 0) {
        reinterpret_cast<NationState*>(*nationCursor)->ApplyTurnDiplomacyStateSlot1e0();
      }
      ++nationCursor;
      --remaining;
    } while (remaining != 0);

    int row = 0;       // major nation
    int rowBase = 0;   // row * kNationSlotCount
    do {
      if (g_apTerrainTypeDescriptorTable[row] != 0) {
        int col = 0;          // paired terrain/minor index
        int colBase = 0;      // col * kNationSlotCount
        int fieldOffset = 0xb2;
        do {
          if (g_apTerrainTypeDescriptorTable[col] != 0) {
            char* rowNation = reinterpret_cast<char*>(g_apNationStates[row]);
            short flag = *reinterpret_cast<short*>(rowNation + fieldOffset + 0x2e);
            if (flag != -1) {
              if (HasFlag84ForNationSlot84(col) != 0) {
                // arg0 is the constant 0 (held in [esp+0x10] across the loop in the original).
                reinterpret_cast<NationState*>(g_apNationStates[col])
                    ->NotifyActionSlot94(0, flag);
              }
              reinterpret_cast<NationState*>(g_apNationStates[row])
                  ->RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(row);
            }
            short relationCode = *reinterpret_cast<short*>(rowNation + fieldOffset);
            if (relationCode != -1) {
              if (relationCode == 0x133) {
                relationSideEffectMatrix1402[rowBase + col] = 1;
                relationSideEffectMatrix1402[row + colBase] = 1;
                reinterpret_cast<TCountry*>(g_pInterNationEventQueueManager)
                    ->thunk_QueueInterNationEventRecordDeduped(0x12, row, col, 0);
              } else if (relationCode == 0x134) {
                relationSideEffectMatrix1402[rowBase + col] = 2;
                relationSideEffectMatrix1402[row + colBase] = 2;
                reinterpret_cast<TCountry*>(g_pInterNationEventQueueManager)
                    ->thunk_QueueInterNationEventRecordDeduped(0x14, row, col, 0);
              } else if (relationCode == 0x131) {
                if (HasPolicyWithNationSlot44(row, col) == 0) {
                  reinterpret_cast<NationState*>(g_apNationStates[row])
                      ->ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(col, 4, -1);
                }
              } else {
                reinterpret_cast<TerrainDescriptor*>(g_apTerrainTypeDescriptorTable[col])
                    ->ApplyTerrainDiplomacyRelationFlagSlot8c(row, relationCode);
              }
            }
          }
          ++col;
          fieldOffset += 2;
          colBase += kNationSlotCount;
        } while (static_cast<short>(col) < kNationSlotCount);
      }
      ++row;
      rowBase += kNationSlotCount;
    } while (static_cast<short>(row) < 7);
  }
}

// FUNCTION: IMPERIALISM 0x004020b8
void TDiplomacyTurnStateManager::thunk_ApplyDiplomacyInterNationStatesForTurn() {
  ApplyDiplomacyInterNationStatesForTurn();
}

// FUNCTION: IMPERIALISM 0x004f1b70
void TDiplomacyTurnStateManager::SetNationPairDiplomacyRelationCode(int sourceNationSlot,
                                                                   int targetNationSlot,
                                                                   int relationCode,
                                                                   int updateMode) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  int forwardIndex = source * kNationSlotCount + target;
  short newRelationCode = static_cast<short>(relationCode);
  if (newRelationCode == relationPropagationMatrixBbe[forwardIndex]) {
    return;
  }

  relationPropagationMatrixBbe[forwardIndex] = newRelationCode;
  int reverseIndex = target * kNationSlotCount + source;
  relationPropagationMatrixBbe[reverseIndex] = newRelationCode;
  relationTurnStampMatrixFe0[forwardIndex] =
      VCall_LocalizationRuntime_GetTurnTick(g_pLocalizationTable);
  relationTurnStampMatrixFe0[reverseIndex] =
      VCall_LocalizationRuntime_GetTurnTick(g_pLocalizationTable);

  if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
    reinterpret_cast<NationState*>(g_apNationStates[source])->NotifyRelationCodeSlot2A8(target, relationCode);
  }
  if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
    reinterpret_cast<NationState*>(g_apNationStates[target])->NotifyRelationCodeSlot2A8(source, relationCode);
  }

  switch (newRelationCode) {
  case 0:
  case 1:
    break;
  case 2:
    QueueInterNationEventRecordDeduped(g_pInterNationEventQueueManager, 0x1a, source,
                                       target, 0);
    return;
  case 3:
    SetStandingScoreSlot28(sourceNationSlot, targetNationSlot,
                           relationStandingScoreMatrix79c[forwardIndex] + 10);
    break;
  case 4:
    if (relationStandingScoreMatrix79c[forwardIndex] <= 0x31) {
      SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0x32);
    }
    if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
      reinterpret_cast<NationState*>(g_apNationStates[source])->NotifyAllianceSlot214(target);
    }
    if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
      reinterpret_cast<NationState*>(g_apNationStates[target])->NotifyAllianceSlot214(source);
    }
    if ((HasFlag84ForNationSlot84(sourceNationSlot) != 0) &&
        (HasFlag84ForNationSlot84(targetNationSlot) != 0)) {
      relationSideEffectMatrix1402[forwardIndex] = 2;
      relationSideEffectMatrix1402[reverseIndex] = 2;
      reinterpret_cast<TerrainDescriptor*>(g_apTerrainTypeDescriptorTable[source])->SetDiplomacyStandingSlot48(targetNationSlot, 100);
      reinterpret_cast<TerrainDescriptor*>(g_apTerrainTypeDescriptorTable[target])->SetDiplomacyStandingSlot48(sourceNationSlot, 100);
      return;
    }
    break;
  case 5:
    SetStandingScoreSlot28(sourceNationSlot, targetNationSlot, 0xff);
    break;
  case 6: {
    void* sourceTerrain = g_apTerrainTypeDescriptorTable[source];
    void* targetTerrain = g_apTerrainTypeDescriptorTable[target];
    if ((*reinterpret_cast<short*>(reinterpret_cast<char*>(sourceTerrain) + 0xe) == -1) &&
        (*reinterpret_cast<short*>(reinterpret_cast<char*>(targetTerrain) + 0xe) < 200)) {
      QueueInterNationEventRecordDeduped(g_pInterNationEventQueueManager, 0x19, source,
                                         target, 0);
    }
    reinterpret_cast<TerrainDescriptor*>(sourceTerrain)->SetDiplomacyStandingSlot48(targetNationSlot, 300);
    reinterpret_cast<TerrainDescriptor*>(targetTerrain)->SetDiplomacyStandingSlot48(sourceNationSlot, 300);
    relationSideEffectMatrix1402[forwardIndex] = 0;
    relationSideEffectMatrix1402[reverseIndex] = 0;
    if (HasFlag84ForNationSlot84(sourceNationSlot) != 0) {
      reinterpret_cast<NationState*>(g_apNationStates[source])->NotifyWarResetSlot290();
    }
    if (HasFlag84ForNationSlot84(targetNationSlot) != 0) {
      reinterpret_cast<NationState*>(g_apNationStates[target])->NotifyWarResetSlot290();
    }
    if (static_cast<char>(updateMode) == 1) {
      PropagateRelationSideEffectSlot80(sourceNationSlot, targetNationSlot,
                                        1);
      return;
    }
  } break;
  }
}

// FUNCTION: IMPERIALISM 0x004f0a10
void TDiplomacyTurnStateManager::ProcessQueuedWarTransitions() {
  if (reinterpret_cast<int*>(pendingWarTransitionQueue18d4)[2] != 0) {
    char propagatedTransition = 0;
    WarTransitionPair* pair =
        static_cast<WarTransitionPair*>(reinterpret_cast<WarTransitionQueue*>(pendingWarTransitionQueue18d4)->PeekFirstPairSlot34());
    int targetNationSlot = pair->targetNationSlot;
    int sourceNationSlot = pair->sourceNationSlot;
    reinterpret_cast<WarTransitionQueue*>(pendingWarTransitionQueue18d4)->RemoveFirstPairSlot30(1);

    if (HasPolicyWithNationSlot44(sourceNationSlot, targetNationSlot) == 0) {
      SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, 6, 0);
    }

    reinterpret_cast<NationState*>(g_apTerrainTypeDescriptorTable[targetNationSlot])->NotifyActionSlot94(sourceNationSlot, 0x131);

    QueueInterNationEventRecordDeduped(g_pInterNationEventQueueManager, 1, targetNationSlot, sourceNationSlot, 0);
    QueueInterNationEventRecordDeduped(g_pInterNationEventQueueManager, 0, sourceNationSlot, targetNationSlot, 0);

    if (targetNationSlot < 7) {
      reinterpret_cast<NationState*>(g_apNationStates[sourceNationSlot])->NotifyActionSlot94(targetNationSlot, 0xc8);
    }

    if (HasFlag84ForNationSlot84(targetNationSlot) == 0) {
      int ownerNationSlot = -1;
      void* targetTerrain = g_apTerrainTypeDescriptorTable[targetNationSlot];
      bool isUnowned = (*reinterpret_cast<short*>(reinterpret_cast<char*>(targetTerrain) + 0xe) == (short)ownerNationSlot);
      if (isUnowned) {
        ownerNationSlot =
            SelectDiplomacyTargetNationFromCandidateSetSlot94(targetNationSlot, 1, 2);
      }

      if (ownerNationSlot > -1) {
        int transitionResult = reinterpret_cast<NationState*>(g_apNationStates[ownerNationSlot])->CheckTransitionSlot27C(targetNationSlot, sourceNationSlot);
        propagatedTransition = (transitionResult == 2);
      }
    } else {
      int otherNationSlot = 0;
      void** nationStateCursor = g_apNationStates;
      short* targetRelationCursor =
          &relationPropagationMatrixBbe[targetNationSlot * kNationSlotCount];
      do {
        if (*targetRelationCursor == 2 &&
            HasPolicyWithNationSlot44(otherNationSlot, sourceNationSlot) == 0) {
          int transitionResult = reinterpret_cast<NationState*>(*nationStateCursor)->PropagateWarTransitionSlot280(targetNationSlot, sourceNationSlot, 0);
          propagatedTransition = (transitionResult == 2);
        }
        ++nationStateCursor;
        ++otherNationSlot;
        ++targetRelationCursor;
      } while (reinterpret_cast<int>(nationStateCursor) < reinterpret_cast<int>(&g_apNationStates_End));

      otherNationSlot = 0;
      nationStateCursor = g_apNationStates;
      short* sourceRelationCursor =
          &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
      do {
        if (*sourceRelationCursor == 2 &&
            ReadGlobalTDiplomacyTurnStateManager()->HasPolicyWithNationSlot44(
                otherNationSlot, targetNationSlot) == 0) {
          int transitionResult = reinterpret_cast<NationState*>(*nationStateCursor)->PropagateWarTransitionSlot280(targetNationSlot, sourceNationSlot, 1);
          propagatedTransition = (transitionResult == 2);
        }
        ++nationStateCursor;
        ++otherNationSlot;
        ++sourceRelationCursor;
      } while (reinterpret_cast<int>(nationStateCursor) < reinterpret_cast<int>(&g_apNationStates_End));
    }

    if (propagatedTransition == 0) {
      TurnEventPacket* packet = new TurnEventPacket();
      InitializeRangePairAndResetCursor(packet, kTurnEventTagNext,
                                        reinterpret_cast<int>(g_pGlobalUiRootController));
      reinterpret_cast<TurnEventQueue*>(g_pGlobalUiRootController)->EnqueueSlot38(packet);
    }
  } else {
    bool isLocalizationOne = (reinterpret_cast<int*>(g_pLocalizationTable)[17] == 1);
    if (isLocalizationOne) {
      EmitTurnEvent3Mode18WithActiveNation(g_pGameFlowState);
    } else {
      reinterpret_cast<LocalizationTable*>(g_pLocalizationTable)->CallSlot44();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00406aaf
void TDiplomacyTurnStateManager::thunk_ProcessQueuedWarTransitions() {
  ProcessQueuedWarTransitions();
}

// FUNCTION: IMPERIALISM 0x004f0db0
void DispatchProcessQueuedWarTransitions() {
  ReadGlobalTDiplomacyTurnStateManager()->thunk_ProcessQueuedWarTransitions();
}

undefined4 thunk_QueueInterNationEventRecordDeduped(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00403d5f
void TurnEventPacket::thunk_ConstructTurnEventPacketBase() {
  reinterpret_cast<void(__fastcall*)(void*, int)>(0x00487820)(this, 0);
}

// FUNCTION: IMPERIALISM 0x00405ee3
void TurnEventPacket::thunk_InitializeRangePairAndResetCursor(int rangeStart, int rangeEnd, int arg3, int arg4, int arg5) {
  reinterpret_cast<void(__fastcall*)(TurnEventPacket*, int, int, int, int, int, int)>(
      0x004878a0)(this, 0, rangeStart, rangeEnd, arg3, arg4, arg5);
}
