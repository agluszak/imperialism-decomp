#pragma once

#include "decomp_types.h"
#include "game/TObject.h"
#include "game/mfc.h"

class TSortedPtrList;

enum {
  kDiplomacyPairMatrixEntries = 0x180,
  kNationSlotCount = 0x17,
  kNationPairMatrixEntries = kNationSlotCount * kNationSlotCount
};

// MFC-style diplomacy backend. The global TDiplomacyTurnStateManager (vtable
// 0x00654d90) holds the per-nation-pair relation / standing / propagation
// matrices and the per-turn relationship-processing logic.
// VTABLE: IMPERIALISM 0x00654d90
class TDiplomacyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TDiplomacyMgr)
  ~TDiplomacyMgr() override;
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  void WriteTo(TStream* stream) override;  // 5 (0x14) 0x004ef2a0
  void ReadFrom(TStream* stream) override; // 6 (0x18) 0x004ef080
  void Free() override;                    // 7 (0x1c) 0x004ef040
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)

  virtual void SetStandingScoreSlot28(int sourceNation, int targetNation, int score); // 10 (0x28)
  virtual void CopyDiplomacyStandingMatrixRowAndColumnSlot2c(int destinationNation,
                                                             int sourceNation); // 11 (0x2c)
  virtual void ApplyDiplomacyInterNationStatesForTurn();                          // 12 (0x30)
  virtual void SelectPriorityNationIndicesForMinorCapabilityRows();             // 13 (0x34)
  virtual void RebuildDiplomacyStandingAndInfluenceMatrices();                    // 14 (0x38)
  virtual void InitializeDiplomacyStandingBaselineRandom();                       // 15 (0x3c)
  virtual void BuildMajorNationDiplomacyStandingRanking();                       // 16 (0x40)
  virtual char IsNationPairAtWar(int sourceNation, int targetNation);           // 17 (0x44)
  virtual char IsNationPairRelationTurnStampOutOfDate(int sourceNation,
                                                      int targetNation); // 18 (0x48)
  virtual char HasAnyWarRelationForNation(int sourceNation);                     // 19 (0x4c)
  virtual char HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNation);   // 20 (0x50)
  virtual char IsNationSlotInPrimaryGroupA(int nationSlot);                      // 21 (0x54)
  virtual char IsNationSlotInPrimaryGroupB(int nationSlot);                      // 22 (0x58)
  virtual char ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
      int sourceNation, int targetNation, int actionCode); // 23 (0x5c)
  virtual char HasAllianceGuardSlot60(int sourceNation, int targetNation); // 24 (0x60)
  virtual char HasState300LinkBetweenNationPair(int sourceNation, int targetNation); // 25 (0x64)
  virtual int GetNationPairDiplomacyStandingTierCode(int sourceNation,
                                                     int targetNation); // 26 (0x68)
  virtual void ShowRelationCodeNoticeForNationPairIfRelevant(int sourceNation,
                                                             int targetNation); // 27 (0x6c)
  virtual short GetNationPairDiplomacyRelationCode(int sourceNation,
                                                   int targetNation); // 28 (0x70)
  virtual void SetNationPairDiplomacyRelationCode(int sourceNation, int targetNation,
                                                 int relationCode, int updateMode); // 29 (0x74)
  virtual void SetNationPairDiplomacyRelationCodeFinal(int sourceNation, int targetNation,
                                                       int relationCode); // 30 (0x78)
  virtual void ApplyRelationCode4AndQueueEvent18ForTargetNation(int sourceNation,
                                                                int targetNation,
                                                                int updateMode); // 31 (0x7c)
  virtual void PropagateRelationSideEffectSlot80(int sourceNation, int targetNation,
                                                 int updateMode); // 32 (0x80)
  virtual char IsPrimaryNationSlotIndex(int nationSlot);          // 33 (0x84)
  virtual void BuildRelationshipListSlot88(int sourceNation, int targetNation,
                                           void* list); // 34 (0x88)
  virtual int CountMajorAllianceRelationsSlot8c(int sourceNation); // 35 (0x8c)
  virtual int GetNthAlliedMajorNationSlot90(int nthAllianceIndex, int sourceNation); // 36 (0x90)
  virtual int SelectDiplomacyTargetNationFromCandidateSetSlot94(int sourceNation,
                                                                  int primaryOnlyFlag,
                                                                  int sideEffectCode); // 37 (0x94)
  virtual int SelectNationSlotFromCollectedStandingEntriesSlot98(int sourceNation,
                                                                 int primaryOnlyFlag); // 38 (0x98)
  virtual int WrapperFor_IsNationSlotEligibleForEventProcessingAt413250(
      int nationSlot); // 39 (0x9c)

  // Slot-name aliases retained for recovered call sites.
  char HasPolicyWithNationSlot44(int sourceNation, int targetNation) {
    return IsNationPairAtWar(sourceNation, targetNation);
  }
  char HasOutdatedWarRelationSlot48(int sourceNation, int targetNation) {
    return IsNationPairRelationTurnStampOutOfDate(sourceNation, targetNation);
  }
  char ValidateDiplomacyActionSlot5c(int sourceNation, int targetNation, int actionCode) {
    return ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(sourceNation, targetNation,
                                                                    actionCode);
  }
  int GetRelationTypeSlot68(int sourceNation, int targetNation) {
    return GetNationPairDiplomacyStandingTierCode(sourceNation, targetNation);
  }
  short GetRelationTierSlot70(int sourceNation, int targetNation) {
    return GetNationPairDiplomacyRelationCode(sourceNation, targetNation);
  }
  void SetRelationCodeSlot74WithMode(int sourceNation, int targetNation, int relationCode,
                                     int updateMode) {
    SetNationPairDiplomacyRelationCode(sourceNation, targetNation, relationCode, updateMode);
  }
  void SetRelationCodeSlot78Final(int sourceNation, int targetNation, int relationCode) {
    SetNationPairDiplomacyRelationCodeFinal(sourceNation, targetNation, relationCode);
  }
  void ApplyRelationCode4Slot7c(int sourceNation, int targetNation, int updateMode) {
    ApplyRelationCode4AndQueueEvent18ForTargetNation(sourceNation, targetNation, updateMode);
  }
  char HasFlag84ForNationSlot84(int nation) { return IsPrimaryNationSlotIndex(nation); }

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

  TDiplomacyMgr* ConstructTDiplomacyTurnStateManager_Vtbl00654d90();
  void InitializeTDiplomacyTurnStateManagerDefaults();
  void QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot);
  short LookupOrderCompatibilityMatrixValue(int sourceNationSlot, int targetNationSlot);
  void ProcessQueuedWarTransitions();
  void ResetTerrainAdjacencyMatrixRowAndSymmetricLink(short nationSlot);

  TDiplomacyMgr();
};

#include "game/diplomacy_globals.h"
