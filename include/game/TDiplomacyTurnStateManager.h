#pragma once

#include "decomp_types.h"

class TSortedPtrList;

enum {
  kDiplomacyPairMatrixEntries = 0x180,
  kNationSlotCount = 0x17,
  kNationPairMatrixEntries = kNationSlotCount * kNationSlotCount
};

// MFC-style diplomacy backend. The global TTDiplomacyTurnStateManager (vtable
// 0x00654d90) holds the per-nation-pair relation / standing / propagation
// matrices and the per-turn relationship-processing logic. Concrete virtual
// slots model its native vtable; the non-virtual methods are the recovered
// behaviour. Constructed once and reached via g_pTDiplomacyTurnStateManager.
// VTABLE: IMPERIALISM 0x00654d90
struct TDiplomacyTurnStateManager {
  // Native virtual functions layout
  virtual void slot_00(); // 0 (0x00)
  virtual void slot_04(); // 1 (0x04)
  virtual void slot_08(); // 2 (0x08)
  virtual void slot_0c(); // 3 (0x0c)
  virtual void slot_10(); // 4 (0x10)
  virtual void slot_14(); // 5 (0x14)
  virtual void slot_18(); // 6 (0x18)
  virtual void slot_1c(); // 7 (0x1c)
  virtual void slot_20(); // 8 (0x20)
  virtual void slot_24(); // 9 (0x24)
  virtual void SetStandingScoreSlot28(int sourceNation, int targetNation,
                                      int score); // 10 (0x28)
  virtual void CopyDiplomacyStandingMatrixRowAndColumnSlot2c(int destinationNation,
                                                             int sourceNation);  // 11 (0x2c)
  virtual void slot_30();                                                        // 12 (0x30)
  virtual void slot_34();                                                        // 13 (0x34)
  virtual void slot_38();                                                        // 14 (0x38)
  virtual void slot_3c();                                                        // 15 (0x3c)
  virtual void slot_40();                                                        // 16 (0x40)
  virtual char HasPolicyWithNationSlot44(int sourceNation, int targetNation);    // 17 (0x44)
  virtual char HasOutdatedWarRelationSlot48(int sourceNation, int targetNation); // 18 (0x48)
  virtual char HasAnyWarRelationForNation(int sourceNation);                     // 19 (0x4c)
  virtual void slot_50();                                                        // 20 (0x50)
  virtual void slot_54();                                                        // 21 (0x54)
  virtual void slot_58();                                                        // 22 (0x58)
  virtual char ValidateDiplomacyActionSlot5c(int sourceNation, int targetNation,
                                             int actionCode);              // 23 (0x5c)
  virtual char HasAllianceGuardSlot60(int sourceNation, int targetNation); // 24 (0x60)
  virtual void slot_64();                                                  // 25 (0x64)
  virtual int GetRelationTypeSlot68(int sourceNation, int targetNation);   // 26 (0x68)
  virtual void slot_6c();                                                  // 27 (0x6c)
  virtual short GetRelationTierSlot70(int sourceNation, int targetNation); // 28 (0x70)
  virtual void SetRelationCodeSlot74WithMode(int sourceNation, int targetNation, int relationCode,
                                             int updateMode); // 29 (0x74)
  virtual void SetRelationCodeSlot78Final(int sourceNation, int targetNation,
                                          int relationCode); // 30 (0x78)
  virtual void ApplyRelationCode4Slot7c(int sourceNation, int targetNation,
                                        int updateMode); // 31 (0x7c)
  virtual void PropagateRelationSideEffectSlot80(int sourceNation, int targetNation,
                                                 int updateMode); // 32 (0x80)
  virtual char HasFlag84ForNationSlot84(int nation);              // 33 (0x84)
  virtual void BuildRelationshipListSlot88(int sourceNation, int targetNation,
                                           void* list);            // 34 (0x88)
  virtual int CountMajorAllianceRelationsSlot8c(int sourceNation); // 35 (0x8c)
  virtual int GetNthAlliedMajorNationSlot90(int nthAllianceIndex,
                                            int sourceNation); // 36 (0x90)
  virtual int SelectDiplomacyTargetNationFromCandidateSetSlot94(int sourceNation,
                                                                int primaryOnlyFlag,
                                                                int sideEffectCode); // 37 (0x94)
  virtual int SelectNationSlotFromCollectedStandingEntriesSlot98(int sourceNation,
                                                                 int primaryOnlyFlag); // 38 (0x98)
  virtual void slot_9c();                                                              // 39 (0x9c)

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
  TSortedPtrList* pendingWarTransitionQueue18d4;
  short proposalArrayMode18d8;
  unsigned char pad18da[2];

  TDiplomacyTurnStateManager* ConstructTDiplomacyTurnStateManager_Vtbl00654d90();
  TDiplomacyTurnStateManager* thunk_ConstructTDiplomacyTurnStateManager_Vtbl00654d90();
  void InitializeTDiplomacyTurnStateManagerDefaults();
  void thunk_InitializeTDiplomacyTurnStateManagerDefaults();
  char IsNationPairAtWar(int sourceNationSlot, int targetNationSlot);
  char IsNationPairRelationTurnStampOutOfDate(int sourceNationSlot, int targetNationSlot);
  char HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNationSlot);
  char ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(int sourceNationSlot,
                                                                int targetNationSlot,
                                                                int actionCode);
  void QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot);
  int GetNationPairDiplomacyStandingTierCode(int sourceNationSlot, int targetNationSlot);
  short GetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot);
  short LookupOrderCompatibilityMatrixValue(int sourceNationSlot, int targetNationSlot);
  char IsPrimaryNationSlotIndex(int nationSlot);
  void SetNationPairDiplomacyRelationCodeFinal(int sourceNationSlot, int targetNationSlot,
                                               int relationCode);
  void ApplyRelationCode4AndQueueEvent18ForTargetNation(int sourceNationSlot, int targetNationSlot,
                                                        int updateMode);
  int CountMajorAllianceRelationsForNation(int sourceNationSlot);
  int GetNthAlliedMajorNationSlotForNation(int nthAllianceIndex, int sourceNationSlot);
  void SetNationPairDiplomacyRelationCode(int sourceNationSlot, int targetNationSlot,
                                          int relationCode, int updateMode);
  void thunk_ProcessQueuedWarTransitions();
  void ProcessQueuedWarTransitions();
  void ApplyDiplomacyInterNationStatesForTurn();
  void thunk_ApplyDiplomacyInterNationStatesForTurn();
  void ResetTerrainAdjacencyMatrixRowAndSymmetricLink(short nationSlot);

protected:
  ~TDiplomacyTurnStateManager();
};

#include "game/diplomacy_globals.h"
