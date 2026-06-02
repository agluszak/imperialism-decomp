// Diplomacy turn-state backend reconstruction.

#include "decomp_types.h"
#include "game/TIndexAndRankList.h"
#include "game/generated/vcall_facades.h"

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
void* g_pDiplomacyTurnStateManager = 0;
char vtbl_DiplomacyTurnStateManager_00654d90 = 0;
char vtbl_TurnEventNextPacket_00654e50 = 0;
}

namespace {
const unsigned int kVtableTPtrList = 0x00649068;
const unsigned int kVtableTurnEventNextPacket = 0x00654E50;
const unsigned int kTurnEventTagNext = 0x4E655854; // 'NeXT'
enum {
  kDiplomacyPairMatrixEntries = 0x180,
  kNationSlotCount = 0x17,
  kNationPairMatrixEntries = kNationSlotCount * kNationSlotCount
};
} // namespace

undefined4 thunk_InitializeRangePairAndResetCursor(void);
undefined4 thunk_QueueInterNationEventRecordDeduped(void);
undefined4 thunk_EmitTurnEvent3Mode18WithActiveNation(void);
static __inline void ConstructTPtrListObject(void* listObject) {
  reinterpret_cast<TIndexAndRankList*>(listObject)->CPtrArray();
}
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
};

struct NationState {
  virtual void ns_slot0() = 0; virtual void ns_slot1() = 0; virtual void ns_slot2() = 0; virtual void ns_slot3() = 0;
  virtual void ns_slot4() = 0; virtual void ns_slot5() = 0; virtual void ns_slot6() = 0; virtual void ns_slot7() = 0;
  virtual void ns_slot8() = 0; virtual void ns_slot9() = 0; virtual void ns_slot10() = 0; virtual void ns_slot11() = 0;
  virtual void ns_slot12() = 0; virtual void ns_slot13() = 0; virtual void ns_slot14() = 0; virtual void ns_slot15() = 0;
  virtual void ns_slot16() = 0; virtual void ns_slot17() = 0; virtual void ns_slot18() = 0; virtual void ns_slot19() = 0;
  virtual void ns_slot20() = 0; virtual void ns_slot21() = 0; virtual void ns_slot22() = 0; virtual void ns_slot23() = 0;
  virtual void ns_slot24() = 0; virtual void ns_slot25() = 0; virtual void ns_slot26() = 0; virtual void ns_slot27() = 0;
  virtual void ns_slot28() = 0; virtual void ns_slot29() = 0; virtual void ns_slot30() = 0; virtual void ns_slot31() = 0;
  virtual void ns_slot32() = 0; virtual void ns_slot33() = 0; virtual void ns_slot34() = 0; virtual void ns_slot35() = 0;
  virtual void ns_slot36() = 0;
  virtual void NotifyActionSlot94(int targetNation, int action) = 0; // 37 (0x94)
  virtual void ns_slot38() = 0; virtual void ns_slot39() = 0; virtual void ns_slot40() = 0; virtual void ns_slot41() = 0;
  virtual void ns_slot42() = 0; virtual void ns_slot43() = 0; virtual void ns_slot44() = 0; virtual void ns_slot45() = 0;
  virtual void ns_slot46() = 0; virtual void ns_slot47() = 0; virtual void ns_slot48() = 0; virtual void ns_slot49() = 0;
  virtual void ns_slot50() = 0; virtual void ns_slot51() = 0; virtual void ns_slot52() = 0; virtual void ns_slot53() = 0;
  virtual void ns_slot54() = 0; virtual void ns_slot55() = 0; virtual void ns_slot56() = 0; virtual void ns_slot57() = 0;
  virtual void ns_slot58() = 0; virtual void ns_slot59() = 0; virtual void ns_slot60() = 0; virtual void ns_slot61() = 0;
  virtual void ns_slot62() = 0; virtual void ns_slot63() = 0; virtual void ns_slot64() = 0; virtual void ns_slot65() = 0;
  virtual void ns_slot66() = 0; virtual void ns_slot67() = 0; virtual void ns_slot68() = 0; virtual void ns_slot69() = 0;
  virtual void ns_slot70() = 0; virtual void ns_slot71() = 0; virtual void ns_slot72() = 0; virtual void ns_slot73() = 0;
  virtual void ns_slot74() = 0; virtual void ns_slot75() = 0; virtual void ns_slot76() = 0; virtual void ns_slot77() = 0;
  virtual void ns_slot78() = 0; virtual void ns_slot79() = 0; virtual void ns_slot80() = 0; virtual void ns_slot81() = 0;
  virtual void ns_slot82() = 0; virtual void ns_slot83() = 0; virtual void ns_slot84() = 0; virtual void ns_slot85() = 0;
  virtual void ns_slot86() = 0; virtual void ns_slot87() = 0; virtual void ns_slot88() = 0; virtual void ns_slot89() = 0;
  virtual void ns_slot90() = 0; virtual void ns_slot91() = 0; virtual void ns_slot92() = 0; virtual void ns_slot93() = 0;
  virtual void ns_slot94() = 0; virtual void ns_slot95() = 0; virtual void ns_slot96() = 0; virtual void ns_slot97() = 0;
  virtual void ns_slot98() = 0; virtual void ns_slot99() = 0; virtual void ns_slot100() = 0; virtual void ns_slot101() = 0;
  virtual void ns_slot102() = 0; virtual void ns_slot103() = 0; virtual void ns_slot104() = 0; virtual void ns_slot105() = 0;
  virtual void ns_slot106() = 0; virtual void ns_slot107() = 0; virtual void ns_slot108() = 0; virtual void ns_slot109() = 0;
  virtual void ns_slot110() = 0; virtual void ns_slot111() = 0; virtual void ns_slot112() = 0; virtual void ns_slot113() = 0;
  virtual void ns_slot114() = 0; virtual void ns_slot115() = 0; virtual void ns_slot116() = 0; virtual void ns_slot117() = 0;
  virtual void ns_slot118() = 0; virtual void ns_slot119() = 0; virtual void ns_slot120() = 0; virtual void ns_slot121() = 0;
  virtual void ns_slot122() = 0; virtual void ns_slot123() = 0; virtual void ns_slot124() = 0; virtual void ns_slot125() = 0;
  virtual void ns_slot126() = 0; virtual void ns_slot127() = 0; virtual void ns_slot128() = 0; virtual void ns_slot129() = 0;
  virtual void ns_slot130() = 0; virtual void ns_slot131() = 0; virtual void ns_slot132() = 0;
  virtual void NotifyAllianceSlot214(int targetNation) = 0; // 133 (0x214)
  virtual void ns_slot134() = 0; virtual void ns_slot135() = 0; virtual void ns_slot136() = 0; virtual void ns_slot137() = 0;
  virtual void ns_slot138() = 0; virtual void ns_slot139() = 0; virtual void ns_slot140() = 0; virtual void ns_slot141() = 0;
  virtual void ns_slot142() = 0; virtual void ns_slot143() = 0; virtual void ns_slot144() = 0; virtual void ns_slot145() = 0;
  virtual void ns_slot146() = 0; virtual void ns_slot147() = 0; virtual void ns_slot148() = 0; virtual void ns_slot149() = 0;
  virtual void ns_slot150() = 0; virtual void ns_slot151() = 0; virtual void ns_slot152() = 0; virtual void ns_slot153() = 0;
  virtual void ns_slot154() = 0; virtual void ns_slot155() = 0; virtual void ns_slot156() = 0; virtual void ns_slot157() = 0;
  virtual void ns_slot158() = 0;
  virtual int CheckTransitionSlot27C(int targetNation, int sourceNation) = 0; // 159 (0x27c)
  virtual int PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) = 0; // 160 (0x280)
  virtual void ns_slot161() = 0; virtual void ns_slot162() = 0; virtual void ns_slot163() = 0;
  virtual void NotifyWarResetSlot290() = 0; // 164 (0x290)
  virtual void ns_slot165() = 0; virtual void ns_slot166() = 0; virtual void ns_slot167() = 0; virtual void ns_slot168() = 0;
  virtual void ns_slot169() = 0;
  virtual void NotifyRelationCodeSlot2A8(int targetNation, int relationCode) = 0; // 170 (0x2A8)
};

struct TCountry {
  void thunk_QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB, char isReplayBypass);
};

struct DiplomacyTurnStateManager {
  // Native virtual functions layout
  virtual void slot_00() = 0; // 0 (0x00)
  virtual void slot_04() = 0; // 1 (0x04)
  virtual void slot_08() = 0; // 2 (0x08)
  virtual void slot_0c() = 0; // 3 (0x0c)
  virtual void slot_10() = 0; // 4 (0x10)
  virtual void slot_14() = 0; // 5 (0x14)
  virtual void slot_18() = 0; // 6 (0x18)
  virtual void slot_1c() = 0; // 7 (0x1c)
  virtual void slot_20() = 0; // 8 (0x20)
  virtual void slot_24() = 0; // 9 (0x24)
  virtual void SetStandingScoreSlot28(int sourceNation, int targetNation, int score) = 0; // 10 (0x28)
  virtual void slot_2c() = 0; // 11 (0x2c)
  virtual void slot_30() = 0; // 12 (0x30)
  virtual void slot_34() = 0; // 13 (0x34)
  virtual void slot_38() = 0; // 14 (0x38)
  virtual void slot_3c() = 0; // 15 (0x3c)
  virtual void slot_40() = 0; // 16 (0x40)
  virtual char HasPolicyWithNationSlot44(int sourceNation, int targetNation) = 0; // 17 (0x44)
  virtual char HasOutdatedWarRelationSlot48(int sourceNation, int targetNation) = 0; // 18 (0x48)
  virtual char HasAnyWarRelationForNation(int sourceNation) = 0; // 19 (0x4c)
  virtual void slot_50() = 0; // 20 (0x50)
  virtual void slot_54() = 0; // 21 (0x54)
  virtual void slot_58() = 0; // 22 (0x58)
  virtual char ValidateDiplomacyActionSlot5c(int sourceNation, int targetNation, int actionCode) = 0; // 23 (0x5c)
  virtual char HasAllianceGuardSlot60(int sourceNation, int targetNation) = 0; // 24 (0x60)
  virtual void slot_64() = 0; // 25 (0x64)
  virtual void slot_68() = 0; // 26 (0x68)
  virtual void slot_6c() = 0; // 27 (0x6c)
  virtual short GetRelationTierSlot70(int sourceNation, int targetNation) = 0; // 28 (0x70)
  virtual void SetRelationCodeSlot74WithMode(int sourceNation, int targetNation, int relationCode, int updateMode) = 0; // 29 (0x74)
  virtual void slot_78() = 0; // 30 (0x78)
  virtual void slot_7c() = 0; // 31 (0x7c)
  virtual void PropagateRelationSideEffectSlot80(int sourceNation, int targetNation, int updateMode) = 0; // 32 (0x80)
  virtual char HasFlag84ForNationSlot84(int nation) = 0; // 33 (0x84)
  virtual void BuildRelationshipListSlot88(int sourceNation, int targetNation, void* list) = 0; // 34 (0x88)
  virtual void slot_8c() = 0; // 35 (0x8c)
  virtual void slot_90() = 0; // 36 (0x90)
  virtual int SetRelationCodeSlot94(int targetNation, int a, int b) = 0; // 37 (0x94)

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

  DiplomacyTurnStateManager* ConstructDiplomacyTurnStateManager_Vtbl00654d90();
  DiplomacyTurnStateManager* thunk_ConstructDiplomacyTurnStateManager_Vtbl00654d90();
  void InitializeDiplomacyTurnStateManagerDefaults();
  void thunk_InitializeDiplomacyTurnStateManagerDefaults();
  char IsNationPairAtWar(int sourceNationSlot, int targetNationSlot);
  char IsNationPairRelationTurnStampOutOfDate(int sourceNationSlot, int targetNationSlot);
  char HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot);
  char ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(int sourceNationSlot,
                                                                int targetNationSlot,
                                                                int actionCode);
  void QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot);
  int GetNationPairDiplomacyStandingTierCode(int sourceNationSlot, int targetNationSlot);
  short GetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot);
  char IsPrimaryNationSlotIndex(int nationSlot);
  void SetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot,
                                          int relationCode, int updateMode);
  void thunk_ProcessQueuedWarTransitions();
  void ProcessQueuedWarTransitions();
};

struct WarTransitionPair {
  short sourceNationSlot;
  short targetNationSlot;
};

struct TSortedByRelationshipList {
  void* vtable;
  int field04;
  int field08;
  int field0c;
  int field10;
  short relationType;
  short pad16;

  TSortedByRelationshipList() {
    ConstructTPtrListObject(this);
    vtable = reinterpret_cast<void*>(kVtableTPtrList);
  }

  void* operator new(size_t size) {
    return reinterpret_cast<void*>(AllocateWithFallbackHandler(size));
  }
  void operator delete(void* ptr) {
    // Empty
  }
};


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



static __inline DiplomacyTurnStateManager* ReadGlobalDiplomacyTurnStateManager() {
  return reinterpret_cast<DiplomacyTurnStateManager*>(g_pDiplomacyTurnStateManager);
}

// FUNCTION: IMPERIALISM 0x004ee6c0
DiplomacyTurnStateManager* DiplomacyTurnStateManager::ConstructDiplomacyTurnStateManager_Vtbl00654d90() {
  int zero = 0;
  queuedWarTransitionActive794 = zero;
  queuedWarTransitionPending798 = zero;
  *reinterpret_cast<void**>(this) = &vtbl_DiplomacyTurnStateManager_00654d90;
  proposalDispatchCounter790 = static_cast<short>(zero);
  lastProcessedNationSlot78e = static_cast<short>(-1);
  return this;
}

// FUNCTION: IMPERIALISM 0x00409944
DiplomacyTurnStateManager* DiplomacyTurnStateManager::thunk_ConstructDiplomacyTurnStateManager_Vtbl00654d90() {
  return ConstructDiplomacyTurnStateManager_Vtbl00654d90();
}

// FUNCTION: IMPERIALISM 0x004ee7a0
void DiplomacyTurnStateManager::InitializeDiplomacyTurnStateManagerDefaults() {
  TSortedByRelationshipList* queue = new TSortedByRelationshipList();
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
void DiplomacyTurnStateManager::thunk_InitializeDiplomacyTurnStateManagerDefaults() {
  InitializeDiplomacyTurnStateManagerDefaults();
}

// FUNCTION: IMPERIALISM 0x004ef540
char DiplomacyTurnStateManager::IsNationPairAtWar(int sourceNationSlot, int targetNationSlot) {
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if ((g_apTerrainTypeDescriptorTable[source] != 0) &&
      (g_apTerrainTypeDescriptorTable[target] != 0)) {
    return GetRelationTierSlot70(sourceNationSlot, targetNationSlot) == 6;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004ef590
char DiplomacyTurnStateManager::IsNationPairRelationTurnStampOutOfDate(int sourceNationSlot,
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
char DiplomacyTurnStateManager::HasAnyWarRelationForNation(int sourceNationSlot) {
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
char DiplomacyTurnStateManager::HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot) {
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
char DiplomacyTurnStateManager::ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
    int sourceNationSlot, int targetNationSlot, int actionCode) {
  char isValid = 0;
  short source = static_cast<short>(sourceNationSlot);
  short target = static_cast<short>(targetNationSlot);
  if (target == source) {
    ReadGlobalDiplomacyTurnStateManager()->proposalArrayMode18d8 = 0xe;
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
char DiplomacyTurnStateManager::HasAllianceGuardSlot60(int nationSlot, int guardedNationSlot) {
  if (ReadGlobalDiplomacyTurnStateManager()->HasAnyWarRelationForNation(nationSlot) == 0) {
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

// FUNCTION: IMPERIALISM 0x004f09c0
void DiplomacyTurnStateManager::QueueNationPairWarTransition(int sourceNationSlot,
                                                             int targetNationSlot) {
  WarTransitionPair pair;
  pair.sourceNationSlot = static_cast<short>(sourceNationSlot);
  pair.targetNationSlot = static_cast<short>(targetNationSlot);
  VCall_WarTransitionQueue_PushPairSlot40(pendingWarTransitionQueue18d4, &pair);
  SetRelationCodeSlot74WithMode(sourceNationSlot, targetNationSlot, 6, 1);
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

// FUNCTION: IMPERIALISM 0x004f1b70
void DiplomacyTurnStateManager::SetNationPairDiplomacyRelationCode(int sourceNationSlot,
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
void DiplomacyTurnStateManager::ProcessQueuedWarTransitions() {
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
            SetRelationCodeSlot94(targetNationSlot, 1, 2);
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
            ReadGlobalDiplomacyTurnStateManager()->HasPolicyWithNationSlot44(
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
void DiplomacyTurnStateManager::thunk_ProcessQueuedWarTransitions() {
  ProcessQueuedWarTransitions();
}

// FUNCTION: IMPERIALISM 0x004f0db0
void DispatchProcessQueuedWarTransitions() {
  ReadGlobalDiplomacyTurnStateManager()->thunk_ProcessQueuedWarTransitions();
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
