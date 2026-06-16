#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/nation_domain_types.h"
#include "game/TObject.h"
#include "game/TPtrList.h"

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
  CRuntimeClass* GetRuntimeClass() const override;
  ~TCountry() override;

  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d6e60
  void ReadFrom(TStream* stream) override; // body 0x004d6bf0
  void Free() override;                    // body 0x004d6ba0

  // slots 0x0a-0x29 — concrete TCountry prefix. Slots 0x2a-0x33 are NULL in the
  // original base table and remain undeclared; pure virtuals would emit _purecall.
  virtual void WriteCoreStateAndTrackedOrdersToStream(void* stream);
  virtual void ReadCoreStateAndRecreateCivOrdersFromStream(void* stream, int unusedArg);
  virtual void SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void);
  virtual void CreateMilitaryRecruitOrderForNode(int nodeContext);
  virtual void AddToNationMetricAtField10(int amount);
  virtual void AssignDisplayNamesToUnnamedMilitaryUnits(void);
  virtual int GetHomeRegionCityRecordIndex(void);
  virtual void QueueRecruitOrdersForUndergarrisonedRegions(void);
  virtual void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel);
  virtual void ApplyJoinEmpireAcceptanceSideEffectsForTargetNation(int targetNationSlot, int mode);
  virtual void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot);
  virtual void ApplyJoinEmpireMode1TargetTransition(int targetNationSlot);
  virtual CString* GetIdentitySharedString1Slot58(void);
  virtual char IsEncodedNationSlotMinus200Equal(int nationCode);
  virtual void RemoveRegionIdFromNationOwnedRegionList(int regionId);
  virtual void AddRegionIdToNationOwnedRegionList(int regionId);
  virtual void SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot, int policyCode);
  virtual void DecrementDiplomacyCounterA2ByValue(int delta);
  virtual int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot);
  virtual short GetDiplomacyCounterA2(void);
  virtual short GetDiplomacyExternalStateB6ByTarget(short nationSlot);
  virtual short QueryNationMetricBySlot7C(short metricSlot);
  virtual void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier);
  virtual bool IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot);
  virtual char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                             int arg4);
  virtual void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId);
  virtual char ReturnFalseNationStateCapabilityFlag90(int arg);
  virtual void NotifyActionSlot94(int sourceNation, int actionCode);
  virtual char ReturnFalseNationStateCapabilityFlag98(void);
  virtual char ReturnFalseNationStateCapabilityFlag9C(void);
  virtual char ShouldDispatchImmediatelySlot28(void);
  virtual void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2);

  // Diplomacy / nation-state helpers (bodies may access TGreatPower tail via `this`).
  void DeserializeDiplomacyNationStateFromStream(TStream* stream);
  void SerializeDiplomacyNationStateToStream(TStream* stream);
  void RebuildDiplomacyEconomicPressureFromMapState(void);
  char IsDiplomacyPolicyAllowedForTargetClassState(short policyCode, short targetNationSlot);
  void SetNationTradePolicyValueForTargetAndNotify(short targetNationSlot, short policyValue);
  void ResolveAndApplyDiplomacyPolicyTransition(short targetNationSlot, short policyCode,
                                                int mode);
  void ProcessTurnEventNationStateTransitionAndDiplomacy(int eventCode, int targetNationSlot,
                                                         int payload);
  void HandleNetworkPortConstructionOrder(int nationId);
  void ApplyNationStateCode200AndQueueEvent1B(int targetNationSlot);
  void SetNationRowDisplayValueByDiplomacyPredicate(short nationSlot, short predicateCode);
  void QueueInterNationEvent17ForState300AffectedNations(void);
  void ApplyDiplomacyRelationMaskToProvinceLinkedObjects(short provinceId, short relationMask);

  CString identitySharedString0;
  CString identitySharedString1;
  short nationSlot;
  short encodedNationSlot;
  int treasuryValue10;
  short needLevelByNation[0x17];
  short field42;
  // 0x44 — military unit list; entries carry a unit-type short at +4 indexing
  // g_Classify_Nation_Military_LookupTable_00695CD4 power weights.
  TPtrList* militaryUnitList44;
  // 0x48 — per-unit-type counter of names already issued (slot 0x0f increments the
  // type's entry after assigning "<ordinal> <type name>").
  short unitNameOrdinalByType[0x1e];
  short unitNameCounter84; // 0x84 — monotonically increasing name tag (stored at +0x1a)
  short pad_86;
  short ownerNationSlot;
  short pad_8a;
  // 0x8c — serialized as a 4-byte block by slots 0x0a/0x0b together with the
  // 4 bytes at 0x88 (ownerNationSlot + pad).
  int serializedField8c;
  TPtrList* ownedRegionList;

  // Defined inline so MSVC inlines the two CString-member constructions (and the
  // resulting EH frame) into derived ctors, matching the original TGreatPower ctor
  // which inlines the TCountry base construction rather than calling 0x004d67d0.
  TCountry() {}
};

// Nation terrain rows: major slots hold TGreatPower*, minor slots hold TMinor*.
// GLOBAL: IMPERIALISM 0x006a4310
extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];

ASSERT_SIZE(TCountry, 0x94);
