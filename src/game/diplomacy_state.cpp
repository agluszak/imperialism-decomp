// Diplomacy turn-state backend reconstruction.

#include "decomp_types.h"
#include "game/generated/vcall_facades.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

namespace {
const unsigned int kAddrTerrainTypeDescriptorTable = 0x006A4310;
const unsigned int kAddrNationStateTable = 0x006A4370;
const unsigned int kAddrLocalizationTable = 0x006A20F8;
const unsigned int kAddrGlobalCountryState = 0x006A43E8;
const unsigned int kAddrGlobalTurnEventQueue = 0x006A1344;
const unsigned int kAddrPendingEventController = 0x006A43C8;
const unsigned int kAddrDiplomacyTurnStateManager = 0x006A43D0;
const unsigned int kVtableDiplomacyTurnStateManager = 0x00654D90;
const unsigned int kVtableTPtrList = 0x00649068;
const unsigned int kVtableTurnEventNextPacket = 0x00654E50;
const unsigned int kTurnEventTagNext = 0x4E655854; // 'NeXT'
enum {
  kDiplomacyPairMatrixEntries = 0x180,
  kNationSlotCount = 0x17,
  kNationPairMatrixEntries = kNationSlotCount * kNationSlotCount
};

static __inline void* ReadGlobalPointer(unsigned int address) {
  return *reinterpret_cast<void**>(address);
}

static __inline void* ReadPointerTableSlot(unsigned int address, int slot) {
  return reinterpret_cast<void**>(address)[slot];
}
} // namespace

undefined4 thunk_ConstructTurnEventPacketBase(void);
undefined4 thunk_InitializeRangePairAndResetCursor(void);
undefined4 thunk_QueueInterNationEventRecordDeduped(void);
undefined4 thunk_EmitTurnEvent3Mode18WithActiveNation(void);
undefined4 CPtrArray(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);

struct DiplomacyTurnStateManager {
  void* vftable;
  short relationCodeMatrix04[kDiplomacyPairMatrixEntries];
  unsigned char pendingPolicyCodeMatrix304[kDiplomacyPairMatrixEntries];
  short pendingPolicyTierMatrix484[kDiplomacyPairMatrixEntries];
  short selectedSourceNationSlot784;
  short selectedTargetNationSlot786;
  short selectionFlagsA788;
  short selectionFlagsB78a;
  short selectionFlagsC78c;
  short lastProcessedNationSlot78e;
  short proposalDispatchCounter790;
  unsigned char pad792[2];
  int queuedWarTransitionActive794;
  int queuedWarTransitionPending798;
  short relationStandingScoreMatrix79c[kNationPairMatrixEntries];
  short relationPropagationMatrixBbe[kNationPairMatrixEntries];
  short relationTurnStampMatrixFe0[kNationPairMatrixEntries];
  short relationSideEffectMatrix1402[kNationPairMatrixEntries];
  unsigned char pad1824[0x18d4 - 0x1824];
  void* pendingWarTransitionQueue18d4;
  short proposalArrayMode18d8;
  unsigned char pad18da[2];

  void ConstructDiplomacyTurnStateManager_Vtbl00654d90();
  void thunk_ConstructDiplomacyTurnStateManager_Vtbl00654d90();
  void InitializeDiplomacyTurnStateManagerDefaults();
  void thunk_InitializeDiplomacyTurnStateManagerDefaults();
  char IsNationPairAtWar(int sourceNationSlot, int targetNationSlot);
  char HasAnyWarRelationForNation(int sourceNationSlot);
  char HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot);
  void QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot);
  int GetNationPairDiplomacyStandingTierCode(int sourceNationSlot, int targetNationSlot);
  short GetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot);
  char IsPrimaryNationSlotIndex(int nationSlot);
  void thunk_ProcessQueuedWarTransitions();
  void ProcessQueuedWarTransitions();
};

struct WarTransitionPair {
  short sourceNationSlot;
  short targetNationSlot;
};

struct TurnEventPacket {
  void* vftable;
  int rangeStart;
  int rangeEnd;
  int cursor;
  int rangeEndCopy;
  int field14;
};

static __inline void QueueInterNationEventRecordDeduped(void* countryState, int eventCode,
                                                       int nationA, int nationB,
                                                       char isReplayBypass) {
  reinterpret_cast<void(__fastcall*)(void*, int, int, int, int, char)>(
      thunk_QueueInterNationEventRecordDeduped)(countryState, 0, eventCode, nationA, nationB,
                                                isReplayBypass);
}

static __inline void ConstructTurnEventPacketBase(TurnEventPacket* packet) {
  reinterpret_cast<void(__fastcall*)(TurnEventPacket*, int)>(thunk_ConstructTurnEventPacketBase)(
      packet, 0);
}

static __inline void InitializeRangePairAndResetCursor(TurnEventPacket* packet, int rangeStart,
                                                       int rangeEnd) {
  reinterpret_cast<void(__fastcall*)(TurnEventPacket*, int, int, int)>(
      thunk_InitializeRangePairAndResetCursor)(packet, 0, rangeStart, rangeEnd);
}

static __inline void EmitTurnEvent3Mode18WithActiveNation(void) {
  reinterpret_cast<void(__cdecl*)(void)>(thunk_EmitTurnEvent3Mode18WithActiveNation)();
}

static __inline void EmitTurnEvent3Mode18WithActiveNation(void* controller) {
  reinterpret_cast<void(__fastcall*)(void*, int)>(thunk_EmitTurnEvent3Mode18WithActiveNation)(
      controller, 0);
}

static __inline void ConstructTPtrListObject(void* listObject) {
  reinterpret_cast<void(__fastcall*)(void*, int)>(CPtrArray)(listObject, 0);
}

static __inline DiplomacyTurnStateManager* ReadGlobalDiplomacyTurnStateManager() {
  return *reinterpret_cast<DiplomacyTurnStateManager**>(kAddrDiplomacyTurnStateManager);
}

// FUNCTION: IMPERIALISM 0x004ee6c0
void DiplomacyTurnStateManager::ConstructDiplomacyTurnStateManager_Vtbl00654d90() {
  int zero = 0;
  queuedWarTransitionActive794 = zero;
  queuedWarTransitionPending798 = zero;
  vftable = reinterpret_cast<void*>(kVtableDiplomacyTurnStateManager);
  proposalDispatchCounter790 = static_cast<short>(zero);
  lastProcessedNationSlot78e = static_cast<short>(-1);
}

// FUNCTION: IMPERIALISM 0x00409944
void DiplomacyTurnStateManager::thunk_ConstructDiplomacyTurnStateManager_Vtbl00654d90() {
  ConstructDiplomacyTurnStateManager_Vtbl00654d90();
}

// FUNCTION: IMPERIALISM 0x004ee7a0
void DiplomacyTurnStateManager::InitializeDiplomacyTurnStateManagerDefaults() {
  void* queue = reinterpret_cast<void*>(AllocateWithFallbackHandler(0x18));
  if (queue != 0) {
    ConstructTPtrListObject(queue);
    *reinterpret_cast<void**>(queue) = reinterpret_cast<void*>(kVtableTPtrList);
  }
  *reinterpret_cast<short*>(reinterpret_cast<char*>(queue) + 0x14) = 4;
  pendingWarTransitionQueue18d4 = queue;

  int pairIndex = 0;
  do {
    relationCodeMatrix04[pairIndex] = 0;
    pendingPolicyCodeMatrix304[pairIndex] = 0xff;
    pairIndex++;
  } while (pairIndex < kDiplomacyPairMatrixEntries);

  selectedSourceNationSlot784 = static_cast<short>(-1);
  selectedTargetNationSlot786 = static_cast<short>(-1);
  selectionFlagsA788 = 0;
  selectionFlagsB78a = 0;
  selectionFlagsC78c = 0;
  proposalArrayMode18d8 = 0;

  short* linearTurnStamp = relationTurnStampMatrixFe0;
  short* rowStart = relationTurnStampMatrixFe0;
  int row = kNationSlotCount;
  do {
    int column = kNationSlotCount;
    short* transposeTurnStamp = rowStart;
    do {
      *linearTurnStamp = static_cast<short>(-1);
      *transposeTurnStamp = static_cast<short>(-1);
      ++linearTurnStamp;
      transposeTurnStamp += kNationSlotCount;
      --column;
    } while (column != 0);
    ++rowStart;
    --row;
  } while (row != 0);
}

// FUNCTION: IMPERIALISM 0x00403837
void DiplomacyTurnStateManager::thunk_InitializeDiplomacyTurnStateManagerDefaults() {
  InitializeDiplomacyTurnStateManagerDefaults();
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

// FUNCTION: IMPERIALISM 0x004f19c0
int DiplomacyTurnStateManager::GetNationPairDiplomacyStandingTierCode(int sourceNationSlot,
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
short DiplomacyTurnStateManager::GetNationPairDiplomacyRelationCode(int sourceNationSlot,
                                                                    int targetNationSlot) {
  int source = static_cast<short>(sourceNationSlot);
  int target = static_cast<short>(targetNationSlot);
  return relationPropagationMatrixBbe[source * kNationSlotCount + target];
}

// FUNCTION: IMPERIALISM 0x004f1f50
char DiplomacyTurnStateManager::IsPrimaryNationSlotIndex(int nationSlot) {
  return static_cast<short>(nationSlot) < 7;
}

// FUNCTION: IMPERIALISM 0x004f0a10
void DiplomacyTurnStateManager::ProcessQueuedWarTransitions() {
  void* queue = pendingWarTransitionQueue18d4;
  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(queue) + 8) == 0) {
    void* localizationTable = ReadGlobalPointer(kAddrLocalizationTable);
    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(localizationTable) + 0x44) == 1) {
      EmitTurnEvent3Mode18WithActiveNation(ReadGlobalPointer(kAddrPendingEventController));
      return;
    }
    VCall_LocalizationTable_CallSlot44(localizationTable);
    return;
  }

  char propagatedTransition = 0;
  WarTransitionPair* pair =
      static_cast<WarTransitionPair*>(VCall_WarTransitionQueue_PeekFirstPairSlot34(queue));
  int targetNationSlot = pair->targetNationSlot;
  int sourceNationSlot = pair->sourceNationSlot;
  VCall_WarTransitionQueue_RemoveFirstPairSlot30(queue, 1);

  if (VCall_Diplomacy_HasPolicyWithNationSlot44(this, sourceNationSlot, targetNationSlot) == 0) {
    VCall_Diplomacy_SetRelationCodeSlot74WithMode(this, sourceNationSlot, targetNationSlot, 6, 0);
  }

  VCall_NationState_NotifyActionSlot94(
      ReadPointerTableSlot(kAddrTerrainTypeDescriptorTable, targetNationSlot), sourceNationSlot,
      0x131);

  void* countryState = ReadGlobalPointer(kAddrGlobalCountryState);
  QueueInterNationEventRecordDeduped(countryState, 1, targetNationSlot, sourceNationSlot, 0);
  QueueInterNationEventRecordDeduped(countryState, 0, sourceNationSlot, targetNationSlot, 0);

  if (targetNationSlot < 7) {
    VCall_NationState_NotifyActionSlot94(ReadPointerTableSlot(kAddrNationStateTable, sourceNationSlot),
                                         targetNationSlot, 0xc8);
  }

  if (VCall_Diplomacy_HasFlag84ForNationSlot84(this, targetNationSlot) == 0) {
    int ownerNationSlot = -1;
    void* targetTerrain = ReadPointerTableSlot(kAddrTerrainTypeDescriptorTable, targetNationSlot);
    if (*reinterpret_cast<short*>(reinterpret_cast<char*>(targetTerrain) + 0xe) == -1) {
      ownerNationSlot =
          VCall_Diplomacy_SetRelationCodeSlot94(this, targetNationSlot, 1, 2);
    }

    if (ownerNationSlot > -1) {
      int transitionResult = VCall_NationState_CheckTransitionSlot27C(
          ReadPointerTableSlot(kAddrNationStateTable, ownerNationSlot), targetNationSlot,
          sourceNationSlot);
      propagatedTransition = (transitionResult == 2);
    }
  } else {
    int otherNationSlot = 0;
    void** nationStateCursor = reinterpret_cast<void**>(kAddrNationStateTable);
    short* targetRelationCursor =
        &relationPropagationMatrixBbe[targetNationSlot * kNationSlotCount];
    do {
      if (*targetRelationCursor == 2 &&
          VCall_Diplomacy_HasPolicyWithNationSlot44(this, otherNationSlot, sourceNationSlot) == 0) {
        int transitionResult = VCall_NationState_PropagateWarTransitionSlot280(
            *nationStateCursor, targetNationSlot, sourceNationSlot, 0);
        propagatedTransition = (transitionResult == 2);
      }
      ++nationStateCursor;
      ++otherNationSlot;
      ++targetRelationCursor;
    } while (reinterpret_cast<unsigned int>(nationStateCursor) < 0x006A438C);

    otherNationSlot = 0;
    nationStateCursor = reinterpret_cast<void**>(kAddrNationStateTable);
    short* sourceRelationCursor =
        &relationPropagationMatrixBbe[sourceNationSlot * kNationSlotCount];
    do {
      if (*sourceRelationCursor == 2 &&
          VCall_Diplomacy_HasPolicyWithNationSlot44(ReadGlobalDiplomacyTurnStateManager(),
                                                    otherNationSlot, targetNationSlot) == 0) {
        int transitionResult = VCall_NationState_PropagateWarTransitionSlot280(
            *nationStateCursor, targetNationSlot, sourceNationSlot, 1);
        propagatedTransition = (transitionResult == 2);
      }
      ++nationStateCursor;
      ++otherNationSlot;
      ++sourceRelationCursor;
    } while (reinterpret_cast<unsigned int>(nationStateCursor) < 0x006A438C);
  }

  if (propagatedTransition == 0) {
    TurnEventPacket* packet =
        reinterpret_cast<TurnEventPacket*>(AllocateWithFallbackHandler(sizeof(TurnEventPacket)));
    if (packet != 0) {
      ConstructTurnEventPacketBase(packet);
      packet->vftable = reinterpret_cast<void*>(kVtableTurnEventNextPacket);
    }
    InitializeRangePairAndResetCursor(packet, kTurnEventTagNext,
                                      reinterpret_cast<int>(ReadGlobalPointer(kAddrGlobalTurnEventQueue)));
    VCall_TurnEventQueue_EnqueueSlot38(ReadGlobalPointer(kAddrGlobalTurnEventQueue), packet);
  }
}

// FUNCTION: IMPERIALISM 0x00406aaf
void DiplomacyTurnStateManager::thunk_ProcessQueuedWarTransitions() {
  ProcessQueuedWarTransitions();
}

// FUNCTION: IMPERIALISM 0x004f0db0
void DispatchProcessQueuedWarTransitions() {
  ReadGlobalDiplomacyTurnStateManager()->thunk_ProcessQueuedWarTransitions();
}
