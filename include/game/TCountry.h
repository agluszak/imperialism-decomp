#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/nation_domain_types.h"
#include "game/TObject.h"
#include "game/TLongintList.h"
#include "game/TSortedList.h"

class TStream;

enum { kTerrainTypeDescriptorTableCount = 23 };

// Intermediate base between TObject and TGreatPower (Ghidra: TCountry). Owns the nation
// identity strings, the nation-slot metrics, the military-unit list and the owned-region
// list, and serializes that sub-object via WriteTo (0x004d6e60) / ReadFrom (0x004d6bf0).
// Its own vtable (0x00653868) is a 52-slot prefix of TGreatPower's 0x00653938; only the
// TObject stream-lifecycle overrides are modeled here, so the vtable is intentionally
// left partial (the 0x0a..0x29 nation virtuals are still declared on TGreatPower).
// VTABLE: IMPERIALISM 0x00653868
class TCountry : public TObject {
public:
  DECLARE_DYNCREATE(TCountry)
  ~TCountry() override;

  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d6e60
  void ReadFrom(TStream* stream) override; // body 0x004d6bf0
  void Free() override;                    // body 0x004d6ba0

  // slots 0x0a-0x29 — concrete TCountry prefix. Slots 0x2a-0x33 are NULL in the
  // original base table and remain undeclared; pure virtuals would emit _purecall.
  virtual void WriteCoreFieldsToStream(TStream* stream);
  virtual void ReadCoreFieldsFromStream(TStream* stream, int unusedArg);
  virtual void SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void);
  virtual void CreateMilitaryRecruitOrderForNode(int nodeContext);
  virtual void AddToNationMetricAtField10(int amount);
  virtual void AssignDisplayNamesToUnnamedMilitaryUnits(void);
  virtual int GetHomeRegionCityRecordIndex(void);
  virtual void QueueRecruitOrdersForUndergarrisonedRegions(void);
  virtual void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel);
  virtual void ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode);
  virtual void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot);
  virtual void ApplyJoinEmpireMode1TargetTransition(int targetNationSlot);
  virtual void ApplyJoinEmpireMode2FinalizeNationNameState(void);
  virtual char IsEncodedNationSlotMinus200Equal(int nationCode);
  virtual void RemoveRegionIdFromNationOwnedRegionList(int regionId);
  virtual void AddRegionIdToNationOwnedRegionList(int regionId);
  virtual void SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot, int policyCode);
  virtual void DecrementDiplomacyCounterA2ByValue(int delta);
  virtual int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot);
  virtual short GetDiplomacyCounterA2(void);
  virtual short GetDiplomacyExternalStateByTarget(short nationSlot);
  virtual short QueryNationMetricBySlot7C(short metricSlot);
  virtual void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier);
  virtual bool IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot);
  virtual char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                             int arg4);
  virtual void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId);
  virtual char ReturnFalseNationStateCapabilityFlag90(short arg);
  virtual void NotifyActionSlot94(int sourceNation, int actionCode);
  virtual char ReturnFalseNationStateCapabilityFlag98(void);
  virtual char ReturnFalseNationStateCapabilityFlag9C(void);
  virtual char ShouldDispatchImmediatelySlot28(void);
  virtual void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2);

  int SumWeightedNeighborLinkScoreForLinkedNodes(void);

  // Diplomacy / nation-state helpers (bodies may access TGreatPower tail via `this`).
  void DeserializeDiplomacyNationStateFromStream(TStream* stream);
  void SerializeDiplomacyNationStateToStream(TStream* stream);
  char IsDiplomacyPolicyAllowedForTargetClassState(short policyCode, short targetNationSlot);
  void SetNationTradePolicyValueForTargetAndNotify(short targetNationSlot, short policyValue);
  void ApplyNationStateCode200AndQueueEvent1B(int targetNationSlot);

  void InitializeNationStateIdentityAndOwnedRegionList(short nationSlot);
  // Fill out with this nation's overlay label (its shared credential/name text), or the
  // empty string when the descriptor slot is null. 0x004d7860.
  void FormatOverlayTerrainLabelText(CString* out);
  // 0x4d8430 — sums g_aUnitOrderCostProfileByAbilityId[type][2] over militaryUnitList44.
  int ComputeSelectedMilitaryPowerScore();
  // 0x4d7930 - copy the nation's shared name text (TSimMgr::sharedTextSlots[nationSlot])
  // into out; a null descriptor yields the default (empty) name. Callable through a null
  // `this` (member access only happens after the null check).
  void AssignSharedStringFromDescriptorNameOrDefault(CString* out);

  // Assign the display name and mirror it into the TSimMgr shared-text slot for
  // this nation (0x4d7a00).
  void SetNationDisplayNameAndLocalizationSlotRef(const CString& name);

  // 0x004d7150, __thiscall, one stack arg (sign-extended short -> int store).
  void SetSerializedField8c(short value);

  // Bare `this+0xe` (encodedNationSlot) range check, same test as the free-function
  // IsNationTerrainEligible helper in TSimMgr::AdvanceGlobalTurnStateMachine (its sole
  // caller, over g_apTerrainTypeDescriptorTable entries). 0x0057f0e0, __thiscall.
  bool IsNationProfileInMinorRange100To199();

  // 0x4d7170: lazily computes and caches the nation's overlay-anchor tile index.
  short GetOrComputeOverlayAnchorTileIndex();

  CString identitySharedString0;
  CString identitySharedString1;
  short nationSlot;
  short encodedNationSlot;
  int treasuryValue10;
  short needLevelByNation[0x17];
  short field42;
  // 0x44 — military unit list; entries carry a unit-type short at +4 indexing
  // g_aUnitOrderCostProfileByAbilityId primary-per-unit column.
  TSortedList* militaryUnitList44;
  // 0x48 — per-unit-type counter of names already issued (slot 0x0f increments the
  // type's entry after assigning "<ordinal> <type name>").
  short unitNameOrdinalByType[0x1e];
  short unitNameCounter84; // 0x84 — monotonically increasing name tag (stored at +0x1a)
  short pad_86;
  // 0x88 — home region/tile index (the terrainStateTable row of the capital;
  // -1 = unset). The TGreatPower bodies access it as a full dword (0x004dfae0
  // stores movsx(short); 0x004db7d0/0x004dbf00 load dwords), the TCountry readers
  // narrow it to a short (0x004d87b0/0x004d71b0 `movsx word`) — expressed here as
  // an int field with static_cast<short> at the narrow readers.
  int homeRegionIndex;
  // 0x8c — cached overlay-anchor tile index (-1 = unset; lazily computed by
  // GetOrComputeOverlayAnchorTileIndex); serialized as a 4-byte block by slots
  // 0x0a/0x0b together with homeRegionIndex.
  int overlayAnchorTileCache8c;
  // The region-id list is a TLongintList (vtable 0x650a08 written by the inline ctor
  // at 0x4d6a5d), not a TSortedList; entries are cityScoreTable indices.
  TLongintList* ownedRegionList;

  // Defined inline so MSVC inlines the two CString-member constructions (and the
  // resulting EH frame) into derived ctors, matching the original TGreatPower ctor
  // which inlines the TCountry base construction rather than calling 0x004d67d0.
  TCountry();
};

// g_apTerrainTypeDescriptorTable — see game/global_data_tables.h.

// Nation-slot decode and linked-node scoring helpers (terrain table rows are TCountry*).
int DecodeTerrainNationSlotFromDescriptor(const TCountry* terrain, short encodedNationSlot);
int ResolveTerrainNationSlotFromTarget(int targetNationSlot);
int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex);
int ComputeWeightedNeighborLinkScoreForNodeIndex(short nodeIndex);

ASSERT_SIZE(TCountry, 0x94);
