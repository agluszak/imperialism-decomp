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
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  virtual void SetRelationship(NationSlot sourceNation, NationSlot targetNation, short score);
  virtual void SetRelationshipsToMatch(NationSlot destinationNation, NationSlot sourceNation);
  virtual void ApplyDiplomacyInterNationStatesForTurn();
  virtual void SelectPriorityNationIndicesForMinorCapabilityRows();
  virtual void ConveneCouncil(char forceOrMode);
  virtual void InitializeDiplomacyStandingBaselineRandom();
  virtual void ChooseCandidates(int* topNationSlot, int* secondNationSlot);
  virtual bool AreAtWar(NationSlot sourceNation, NationSlot targetNation);
  virtual bool AreInEstablishedWar(NationSlot sourceNation, NationSlot targetNation);
  virtual bool IsAtWarWithAnybody(NationSlot sourceNation);
  virtual bool IsInEstablishedWarWithAnybody(NationSlot sourceNation);
  virtual bool IsSpecialRelationSourceForMinorNationSlot(NationSlot nationSlot,
                                                         NationSlot minorNationSlot);
  virtual bool IsSpecialRelationTargetForMinorNationSlot(NationSlot nationSlot,
                                                         NationSlot minorNationSlot);
  virtual bool IsActionAllowed(NationSlot sourceNation, NationSlot targetNation, eDipAction action);
  virtual bool HasAllianceGuardForNationPair(NationSlot nationSlot, NationSlot guardedNationSlot);
  virtual bool IsBoycott(NationSlot sourceNation, NationSlot targetNation);
  virtual DiplomacyRelationshipNotch GetRelationshipNotch(NationSlot sourceNation,
                                                          NationSlot targetNation);
  virtual void GetTreatyStatusText(NationSlot sourceNationSlot, NationSlot targetNationSlot,
                                   CString* treatyName);
  virtual DiplomacyRelationshipStorage GetTreatyStatus(NationSlot sourceNation,
                                                       NationSlot targetNation);
  virtual void SetTreatyStatus(NationSlot sourceNation, NationSlot targetNation,
                               DiplomacyRelationshipStorage relationship, unsigned char updateMode);
  virtual void SetNationPairDiplomacyRelationCodeFinal(NationSlot sourceNation,
                                                       NationSlot targetNation,
                                                       DiplomacyRelationshipStorage relationship);
  // (0x78)
  virtual void TerminateAlliance(NationSlot sourceNation, NationSlot targetNation,
                                 unsigned char updateMode);
  virtual void InflictWarPenalty(NationSlot sourceNation, NationSlot targetNation,
                                 unsigned char updateMode);
  virtual bool IsGreatPower(NationSlot nationSlot);
  // ABI: primaryOnlyFlag is a genuine short; callers push a partial register.
  virtual void BuildRelationshipList(NationSlot sourceNation, short primaryOnlyFlag, void* list);
  // ORACLE: Mac TDiplomacyMgr::GetNumAllies(long); Windows uses int.
  virtual int GetNumAllies(int sourceNation);
  virtual int GetAllyNumber(int nthAllianceIndex, int sourceNation);
  // MATCH: VC5 emits this overload group in reverse order; keep the two-arg form first.
  virtual int GetFavorite(int sourceNation, int primaryOnlyFlag);
  virtual int GetFavorite(int sourceNation, int primaryOnlyFlag, int sideEffectCode);
  virtual int GetFavoriteTradePartner(int minorNationSlot);

  bool BuildEmbassy(DiplomaticMissionLevelStorage missionLevel, int sourceNation, int targetNation);

  short relationCodeMatrix[kDiplomacyPairMatrixEntries];
  signed char pendingPolicyCodeMatrix[kDiplomacyPairMatrixEntries];
  short pendingPolicyTierMatrix[kDiplomacyPairMatrixEntries];
  CongressLeadership congressLeadership;
  struct TurnEvent2SyncPacket* BuildTurnEvent2ArraySyncPacketFromBufferAndRefreshBaselineCopy();
  void HandleDiplomaticStandingsMsg(TurnEvent2SyncPacket* packet);

  CongressSupportTally congressSupport;
  NationSlot lastProcessedNationSlot;
  short lastDiplomaticEffortTurn;
  short* relationMatrixBaselineCopy;
  int relationMatrixBaselineSize;
  short relationStandingScores[kNationPairMatrixEntries];
  DiplomacyRelationshipStorage relationPropagationMatrix[kNationPairMatrixEntries];
  short relationTurnStampMatrix[kNationPairMatrixEntries];
  DiplomaticMissionLevelStorage relationSideEffectMatrix[kNationPairMatrixEntries];
  void CalculateRatings();

  int comparativePowerRows[7][4];
  NationSlot specialRelationSourceSlots[0x10];
  NationSlot specialRelationTargetSlots[0x10];
  TSortedPtrList* pendingWarTransitionQueue;
  short proposalArrayMode;

  TDiplomacyMgr();
  void IDiplomacyMgr();
  void RebuildCivilianOrderCompatibilityMatrices();
  void AddDeclarationOfWar(NationSlot sourceNationSlot, NationSlot targetNationSlot);
  short GetEmbassyStatus(int sourceNationSlot, int targetNationSlot);
  void IssueDeclarationsOfWar();
  void ResetTerrainAdjacencyMatrixRowAndSymmetricLink(NationSlot nationSlot);
  void RemoveNationSlotAndNotifyPeers(NationSlot nationSlot);
  // Records the current turn.
  void SetLastDiploEffort();

  void UpdateTables(int nationCode);
  void RebuildMinorNationDispositionLookupTables(NationSlot nationCode);
};
ASSERT_SIZE(TDiplomacyMgr, 0x18dc);
