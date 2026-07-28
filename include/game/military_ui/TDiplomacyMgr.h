#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/nation_domain_types.h"
#include "game/app/TObject.h"
#include "game/mfc.h"

class TSortedPtrList;

enum {
  kDiplomacyPairMatrixEntries = 0x180,
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
  void WriteTo(TStream* stream) override;  // 5 (0x14) 0x004ef2a0
  void ReadFrom(TStream* stream) override; // 6 (0x18) 0x004ef080
  void Free() override;                    // 7 (0x1c) 0x004ef040

  virtual void SetStandingScoreSlot28(int sourceNation, int targetNation, int score); // 10 (0x28)
  virtual void CopyDiplomacyStandingMatrixRowAndColumnSlot2c(int destinationNation,
                                                             int sourceNation); // 11 (0x2c)
  virtual void ApplyDiplomacyInterNationStatesForTurn();                        // 12 (0x30)
  virtual void SelectPriorityNationIndicesForMinorCapabilityRows();             // 13 (0x34)
  // Verified RET 4 (one stack byte arg): forceOrMode==2 means "do a full clear" of
  // relationCodeMatrix04 before rebuilding. Recomputes the two top-ranked nations' scoring
  // arrays against every terrain-descriptor slot, then walks every nation-pair-matrix tile
  // to assign it to the top or second nation's influence side (or neutral), and finally
  // may prod the losing nation's AI via TGreatPower::SetNationPendingActionStateAndPayload.
  virtual void RebuildDiplomacyStandingAndInfluenceMatrices(char forceOrMode); // 14 (0x38)
  virtual void InitializeDiplomacyStandingBaselineRandom();                    // 15 (0x3c)
  // Sums each major power's comparativePowerRows1824 metrics into a power score,
  // ranks the 7 major powers descending by that score (random coin-flip tiebreak),
  // and writes the top two nation slots out. Verified RET 8 (2 stack args).
  virtual void BuildMajorNationDiplomacyStandingRanking(int* topNationSlot,
                                                        int* secondNationSlot);     // 16 (0x40)
  virtual bool IsNationPairAtWar(NationSlot sourceNation, NationSlot targetNation); // 17 (0x44)
  // NationSlot, not int: the body reads both parameters through MOVSX from their low
  // words (0x4ef5b3 / 0x4ef5be), and the 0x561b50 caller pushes a value whose high half is
  // deliberately garbage (MOVSX AX from a byte, then PUSH EAX) -- only a 16-bit parameter
  // makes that callsite correct.
  virtual bool IsNationPairRelationTurnStampOutOfDate(NationSlot sourceNation,
                                                      NationSlot targetNation); // 18 (0x48)
  virtual bool HasAnyWarRelationForNation(int sourceNation);                    // 19 (0x4c)
  virtual bool HasAnyWarRelationTurnStampOutOfDateForNation(int sourceNation);  // 20 (0x50)
  virtual bool IsSpecialRelationSourceForMinorNationSlot(int nationSlot,
                                                         int minorNationSlot); // 21 (0x54)
  virtual bool IsSpecialRelationTargetForMinorNationSlot(int nationSlot,
                                                         int minorNationSlot); // 22 (0x58)
  virtual bool
  ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(int sourceNation, int targetNation,
                                                           eDipAction action); // 23 (0x5c)
  virtual bool HasAllianceGuardForNationPair(int sourceNation,
                                             int targetNation);               // 24 (0x60)
  virtual bool HasNationPairNeedLevel300(int sourceNation, int targetNation); // 25 (0x64)
  virtual DiplomacyRelationshipNotch GetRelationshipNotch(NationSlot sourceNation,
                                                          NationSlot targetNation); // 26 (0x68)
  // Load the relation's display name from string group 0x2714 for alliance,
  // non-aggression, peace, or war. Other relation codes leave treatyName unchanged.
  virtual void LoadTreatyNameForNationPairIfDisplayable(NationSlot sourceNationSlot,
                                                        NationSlot targetNationSlot,
                                                        CString* treatyName); // 27 (0x6c)
  virtual DiplomacyRelationshipStorage
  GetNationPairDiplomacyRelationCode(NationSlot sourceNation,
                                     NationSlot targetNation); // 28 (0x70)
  virtual void SetNationPairDiplomacyRelationCode(int sourceNation, int targetNation,
                                                  DiplomacyRelationship relationship,
                                                  int updateMode); // 29 (0x74)
  virtual void SetNationPairDiplomacyRelationCodeFinal(int sourceNation, int targetNation,
                                                       DiplomacyRelationship relationship); // 30
  // (0x78)
  virtual void ApplyPeaceRelationshipAndQueueEvent18ForTargetNation(int sourceNation,
                                                                    int targetNation,
                                                                    int updateMode); // 31 (0x7c)
  virtual void PropagateRelationSideEffectSlot80(int sourceNation, int targetNation,
                                                 int updateMode); // 32 (0x80)
  virtual bool IsMajorNationSlot(int nationSlot);                 // 33 (0x84)
  // Both scalar params are genuinely short: the body reads primaryOnlyFlag as a word
  // and callers push the raw partial register (mov dx, [this+0xc]; push edx).
  virtual void BuildRelationshipListSlot88(NationSlot sourceNation, short primaryOnlyFlag,
                                           void* list); // 34 (0x88)
  // ORACLE: Mac TDiplomacyMgr::GetNumAllies(long); Windows uses int.
  virtual int GetNumAllies(int sourceNation);                                        // 35 (0x8c)
  virtual int GetNthAlliedMajorNationSlot90(int nthAllianceIndex, int sourceNation); // 36 (0x90)
  virtual int SelectDiplomacyTargetNationFromCandidateSetSlot94(int sourceNation,
                                                                int primaryOnlyFlag,
                                                                int sideEffectCode); // 37 (0x94)
  virtual int SelectNationSlotFromCollectedStandingEntriesSlot98(int sourceNation,
                                                                 int primaryOnlyFlag); // 38 (0x98)
  virtual int SelectBestMajorNationForMinorByStandingAndNeed(int minorNationSlot);     // 39 (0x9c)

  // 0x004f2820 (Mac: BuildEmbassy) — stores the symmetric mission level and queues
  // the corresponding trade-consulate or embassy news event.
  char BuildEmbassy(DiplomaticMissionLevelStorage missionLevel, int sourceNation, int targetNation);

  short relationCodeMatrix04[kDiplomacyPairMatrixEntries];
  signed char pendingPolicyCodeMatrix304[kDiplomacyPairMatrixEntries];
  short pendingPolicyTierMatrix484[kDiplomacyPairMatrixEntries];
  CongressLeadership congressLeadership784; // +0x784
  // Build the turn-event-2 relation-matrix sync packet (delta against the baseline
  // snapshot when one exists) and refresh the baseline copy. 0x4f2760.
  struct TurnEvent2SyncPacket* BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
  // 0x4f27f0 — apply a received turn-event-2 sync packet to the relation matrix.
  void ApplyTurnEvent2SyncPacketToRelationMatrix(TurnEvent2SyncPacket* packet);

  CongressSupportTally congressSupport788; // +0x788..+0x78d
  NationSlot lastProcessedNationSlot78e;
  short proposalDispatchCounter790;
  unsigned char pad792[2];
  // Baseline snapshot of the relation-matrix block (0x79c..0x18d4, 0x1138 bytes) used
  // by the turn-event-2 delta sync; lazily heap-allocated, size cached alongside.
  short* relationMatrixBaselineCopy794;
  int relationMatrixBaselineSize798;
  short relationStandingScores[kNationPairMatrixEntries];
  DiplomacyRelationshipStorage relationPropagationMatrixBbe[kNationPairMatrixEntries];
  short relationTurnStampMatrixFe0[kNationPairMatrixEntries];
  DiplomaticMissionLevelStorage relationSideEffectMatrix1402[kNationPairMatrixEntries];
  // 0x004f1760 — see comparativePowerRows1824 below.
  void RecomputeNationComparativePowerMetrics();

  // 0x1824 — per-nation comparative-power rows rebuilt each turn by
  // RecomputeNationComparativePowerMetrics (0x4f1760): {army, avgRelation,
  // territory+tech combined, commodity} normalized to 0..100 (0..50+50 for combined).
  int comparativePowerRows1824[7][4];
  NationSlot specialRelationSourceSlots1894[0x10];
  NationSlot specialRelationTargetSlots18b4[0x10];
  TSortedPtrList* pendingWarTransitionQueue18d4;
  short proposalArrayMode18d8;
  unsigned char pad18da[2];

  TDiplomacyMgr();
  void InitializeTDiplomacyTurnStateManagerDefaults();
  void RebuildCivilianOrderCompatibilityMatrices();
  void QueueNationPairWarTransition(int sourceNationSlot, int targetNationSlot);
  short LookupOrderCompatibilityMatrixValue(int sourceNationSlot, int targetNationSlot);
  void ProcessQueuedWarTransitions();
  void ResetTerrainAdjacencyMatrixRowAndSymmetricLink(NationSlot nationSlot);
  // 0x4eee60 -- resets the removed nation's relation rows/columns (standing-score and
  // propagation matrices). Great-power slots 0..6 clear the propagation entry unless it is
  // already the "6" sentinel (or the nation lost its terrain descriptor); the standing
  // score resets to 0x5a only when the descriptor is gone. Minor slots 7..22 always reset.
  void RemoveNationSlotAndNotifyPeers_Impl(NationSlot nationSlot);
  // Mirrors g_pSimMgr's current turn tick into proposalDispatchCounter790. 0x4f0590.
  void SyncNationField790FromLocalizationStateId();

  // 0x4f24a0. Finds the minor nation (among g_apNationAuxRuntimeStateSlots) whose
  // encodedNationSlot decodes to nationCode via IsEncodedNationSlotMinus200Equal, then
  // rebuilds that minor's relation-matrix row/column against every major power (default
  // standing/propagation) and every other eligible minor (looked up from the other
  // minor's own decoded disposition band when it already has one, else from the
  // requesting nation's IsPolicyCodeInSpecialNationPolicySet capability check), and
  // finally notifies every eligible major power via SetTradePolicyTo.
  void RebuildMinorNationDispositionLookupTables(int nationCode);
};
ASSERT_SIZE(TDiplomacyMgr, 0x18dc);
