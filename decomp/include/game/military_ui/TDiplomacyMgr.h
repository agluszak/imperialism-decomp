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
// VTABLE: IMPERIALISM 0x00654d90
class TDiplomacyMgr : public TObject {
public:
  DECLARE_DYNCREATE(TDiplomacyMgr)
  ~TDiplomacyMgr() override;
  void WriteTo(TStream* stream) override;  // 5 (0x14) 0x004ef2a0
  void ReadFrom(TStream* stream) override; // 6 (0x18) 0x004ef080
  void Free() override;                    // 7 (0x1c) 0x004ef040

  // ORACLE: Mac names TDiplomacyMgr::SetRelationship(short, short, short).
  virtual void SetRelationship(NationSlot sourceNation, NationSlot targetNation,
                               short score); // 10 (0x28)
  // ORACLE: Mac names TDiplomacyMgr::SetRelationshipsToMatch(short, short).
  virtual void SetRelationshipsToMatch(NationSlot destinationNation,
                                       NationSlot sourceNation);    // 11 (0x2c)
  virtual void ApplyDiplomacyInterNationStatesForTurn();            // 12 (0x30)
  virtual void SelectPriorityNationIndicesForMinorCapabilityRows(); // 13 (0x34)
  virtual void ConveneCouncil(char forceOrMode); // 14 (0x38)
  virtual void InitializeDiplomacyStandingBaselineRandom();                    // 15 (0x3c)
  virtual void ChooseCandidates(int* topNationSlot,
                                                        int* secondNationSlot);     // 16 (0x40)
  virtual bool IsNationPairAtWar(NationSlot sourceNation, NationSlot targetNation); // 17 (0x44)
  virtual bool IsNationPairRelationTurnStampOutOfDate(NationSlot sourceNation,
                                                      NationSlot targetNation);       // 18 (0x48)
  virtual bool HasAnyWarRelationForNation(NationSlot sourceNation);                   // 19 (0x4c)
  virtual bool HasAnyWarRelationTurnStampOutOfDateForNation(NationSlot sourceNation); // 20 (0x50)
  virtual bool IsSpecialRelationSourceForMinorNationSlot(NationSlot nationSlot,
                                                         NationSlot minorNationSlot); // 21 (0x54)
  virtual bool IsSpecialRelationTargetForMinorNationSlot(NationSlot nationSlot,
                                                         NationSlot minorNationSlot); // 22 (0x58)
  virtual bool
  ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(NationSlot sourceNation,
                                                           NationSlot targetNation,
                                                           eDipAction action); // 23 (0x5c)
  virtual bool HasAllianceGuardForNationPair(NationSlot sourceNation,
                                             NationSlot targetNation); // 24 (0x60)
  virtual bool HasNationPairNeedLevel300(NationSlot sourceNation,
                                         NationSlot targetNation); // 25 (0x64)
  virtual DiplomacyRelationshipNotch GetRelationshipNotch(NationSlot sourceNation,
                                                          NationSlot targetNation); // 26 (0x68)
  virtual void GetTreatyStatusText(NationSlot sourceNationSlot,
                                                        NationSlot targetNationSlot,
                                                        CString* treatyName); // 27 (0x6c)
  virtual DiplomacyRelationshipStorage
  GetNationPairDiplomacyRelationCode(NationSlot sourceNation,
                                     NationSlot targetNation); // 28 (0x70)
  virtual void SetNationPairDiplomacyRelationCode(NationSlot sourceNation, NationSlot targetNation,
                                                  DiplomacyRelationshipStorage relationship,
                                                  unsigned char updateMode); // 29 (0x74)
  virtual void
  SetNationPairDiplomacyRelationCodeFinal(NationSlot sourceNation, NationSlot targetNation,
                                          DiplomacyRelationshipStorage relationship); // 30
  // (0x78)
  virtual void
  TerminateAlliance(NationSlot sourceNation,
                                                       NationSlot targetNation,
                                                       unsigned char updateMode); // 31 (0x7c)
  // ORACLE: Mac names TDiplomacyMgr::InflictWarPenalty(short, short, unsigned char).
  virtual void InflictWarPenalty(NationSlot sourceNation, NationSlot targetNation,
                                 unsigned char updateMode); // 32 (0x80)
  // ORACLE: Mac names TDiplomacyMgr::IsGreatPower(short).
  virtual bool IsGreatPower(NationSlot nationSlot); // 33 (0x84)
  // Both scalar params are genuinely short: the body reads primaryOnlyFlag as a word
  // and callers push the raw partial register (mov dx, [this+0xc]; push edx).
  // ORACLE: Mac names TDiplomacyMgr::BuildRelationshipList(short, short,
  // TSortedByRelationshipList*).
  virtual void BuildRelationshipList(NationSlot sourceNation, short primaryOnlyFlag,
                                     void* list); // 34 (0x88)
  // ORACLE: Mac TDiplomacyMgr::GetNumAllies(long); Windows uses int.
  virtual int GetNumAllies(int sourceNation); // 35 (0x8c)
  // ORACLE: Mac names TDiplomacyMgr::GetAllyNumber(long, long).
  virtual int GetAllyNumber(int nthAllianceIndex, int sourceNation); // 36 (0x90)
  // MATCH: VC5 emits this overload group in reverse declaration order. Keep the two-arg
  // declaration first so the three-arg method occupies slot 0x94 in the emitted vtable.
  // ORACLE: Mac names TDiplomacyMgr::GetFavorite(long, unsigned char).
  virtual int GetFavorite(int sourceNation, int primaryOnlyFlag); // 38 (0x98)
  // ORACLE: Mac names TDiplomacyMgr::GetFavorite(long, unsigned char, short).
  virtual int GetFavorite(int sourceNation, int primaryOnlyFlag,
                          int sideEffectCode); // 37 (0x94)
  // ORACLE: Mac names TDiplomacyMgr::GetFavoriteTradePartner(long).
  virtual int GetFavoriteTradePartner(int minorNationSlot); // 39 (0x9c)

  char BuildEmbassy(DiplomaticMissionLevelStorage missionLevel, int sourceNation, int targetNation);

  short relationCodeMatrix[kDiplomacyPairMatrixEntries];
  signed char pendingPolicyCodeMatrix[kDiplomacyPairMatrixEntries];
  short pendingPolicyTierMatrix[kDiplomacyPairMatrixEntries];
  CongressLeadership congressLeadership; // +0x784
  struct TurnEvent2SyncPacket* BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
  void HandleDiplomaticStandingsMsg(TurnEvent2SyncPacket* packet);

  CongressSupportTally congressSupport; // +0x788..+0x78d
  NationSlot lastProcessedNationSlot;
  short lastDiplomaticEffortTurn;
  unsigned char padding792[2];
  short* relationMatrixBaselineCopy;
  int relationMatrixBaselineSize;
  short relationStandingScores[kNationPairMatrixEntries];
  DiplomacyRelationshipStorage relationPropagationMatrix[kNationPairMatrixEntries];
  short relationTurnStampMatrix[kNationPairMatrixEntries];
  DiplomaticMissionLevelStorage relationSideEffectMatrix[kNationPairMatrixEntries];
  void RecomputeNationComparativePowerMetrics();

  int comparativePowerRows[7][4];
  NationSlot specialRelationSourceSlots[0x10];
  NationSlot specialRelationTargetSlots[0x10];
  TSortedPtrList* pendingWarTransitionQueue;
  short proposalArrayMode;
  unsigned char padding18da[2];

  TDiplomacyMgr();
  void InitializeTDiplomacyTurnStateManagerDefaults();
  void RebuildCivilianOrderCompatibilityMatrices();
  void QueueNationPairWarTransition(NationSlot sourceNationSlot, NationSlot targetNationSlot);
  short GetEmbassyStatus(int sourceNationSlot, int targetNationSlot);
  void ProcessQueuedWarTransitions();
  void ResetTerrainAdjacencyMatrixRowAndSymmetricLink(NationSlot nationSlot);
  void RemoveNationSlotAndNotifyPeers_Impl(NationSlot nationSlot);
  // ORACLE: Mac names TDiplomacyMgr::SetLastDiploEffort(). Mirrors the current turn.
  void SetLastDiploEffort(); // 0x4f0590

  void UpdateTables(int nationCode); // 0x4f2430, Mac oracle
  void RebuildMinorNationDispositionLookupTables(NationSlot nationCode);
};
ASSERT_SIZE(TDiplomacyMgr, 0x18dc);
