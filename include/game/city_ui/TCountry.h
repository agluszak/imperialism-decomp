#pragma once

#include "decomp_types.h"
#include "game/core/CString.h"
#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/app/TObject.h"
#include "game/city_ui/TLongintList.h"
#include "game/ui_core/TSortedList.h"

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
  // Inline so derived destructors reproduce the original direct CString teardown rather
  // than calling an out-of-line TCountry destructor.
  // FUNCTION: IMPERIALISM 0x004d6880
  ~TCountry() override {}

  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d6e60
  void ReadFrom(TStream* stream) override; // body 0x004d6bf0
  void Free() override;                    // body 0x004d6ba0

  // slots 0x0a-0x29 — concrete TCountry prefix. Slots 0x2a-0x33 are NULL in the
  // original base table and remain undeclared; pure virtuals would emit _purecall.
  virtual void WriteCoreFieldsToStream(TStream* stream);
  virtual void ReadCoreFieldsFromStream(TStream* stream, int unusedArg);
  virtual void InitialMilitia(void);
  virtual void AddMilitia(int nodeContext);
  virtual void AddToTreasury(int amount);
  virtual void NameUnits(void);
  virtual int GetCapitolProvince(void);
  virtual void GrowMilitia(void);
  virtual void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy);
  virtual void ChangeMaster(int targetNationSlot, int mode);
  virtual void BecomeProtectorateOf(int targetNationSlot);
  virtual void BecomeColonyOf(int targetNationSlot);
  virtual void RegainIndependence(void);
  virtual char IsColonyOf(int nationCode);

  // Decode the owning great-power slot from encodedNationSlot: >= 200 -> tag - 200,
  // 100..199 -> tag - 100, else this nation's own slot. Header-inline: the original
  // bodies open-code this decode at each site. (Only TCountry fields; moved up from
  // TMinor so terrain-descriptor rows can decode without a downcast.)
  NationSlot DecodeOwnerNationSlot() const {
    NationSlot ownerNationSlot = encodedNationSlot;
    if (ownerNationSlot < 200) {
      if (ownerNationSlot < 100) {
        ownerNationSlot = nationSlot;
      } else {
        ownerNationSlot = static_cast<NationSlot>(ownerNationSlot - 100);
      }
    } else {
      ownerNationSlot = static_cast<NationSlot>(ownerNationSlot - 200);
    }
    return ownerNationSlot;
  }
  virtual void LoseProvince(int regionId);
  virtual void AddProvince(int regionId);
  virtual void NewStatusFor(int targetNationSlot, int policyCode);
  virtual void DeliverItem(short amount);
  virtual short GetAmtUnsold(short resourceKind);
  virtual short GetMerchantCapacity(void);
  virtual short GetStockpile(short resourceKind);
  virtual short GetTradeOffersFor(short resourceKind);
  virtual void PurchaseItem(short resourceKind, short amount, short price);
  virtual bool StillBuyingItem(ResourceKindStorage resourceKind);
  virtual char ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                 ResourceKindStorage resourceKind);
  // ORACLE: Mac names TCountry::AddOfferFrom(short, short).
  virtual void AddOfferFrom(NationSlot sourceNationSlot, DiplomacyProposalCodeStorage proposalCode);
  virtual char IsInConsortiumWith(short policyCode);
  // ORACLE: Mac names TCountry::AddNoticeFrom(short, short).
  virtual void AddNoticeFrom(short sourceNation, short actionCode);
  virtual bool IsClient(void) const;
  virtual bool IsHost(void) const;
  virtual bool IsRemote(void) const;
  virtual void PlopDownCity(short selectedRegion, const char* mapCellLabel);

  int SumWeightedNeighborLinkScoreForLinkedNodes(void);
  // 0x004d8390 — forwards to g_pMapContextActionManager's per-node weighted stationed-
  // unit score. Real __thiscall (ret 4; the 0x004e8750 metric-3 callsite loads the
  // country into ecx); `this` is unused by the body.
  int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex);

  // Diplomacy / nation-state helpers (bodies may access TGreatPower tail via `this`).
  void DeserializeDiplomacyNationStateFromStream(TStream* stream);
  void SerializeDiplomacyNationStateToStream(TStream* stream);
  void SetNationTradePolicyValueForTargetAndNotify(NationSlot targetNationSlot, short policyValue);
  void ApplyNationStateCode200AndQueueEvent1B(int targetNationSlot);

  void InitializeNationStateIdentityAndOwnedRegionList(NationSlot nationSlot);
  // Mac oracle: GenerateEthnicName(CStr32&) const. The Windows port uses CString;
  // the ABI is a single CString* stack argument on this TCountry receiver.
  void GenerateEthnicName(CString* out) const; // 0x4d7eb0
  // Fill out with this nation's overlay label (its shared credential/name text), or the
  // empty string when the descriptor slot is null. 0x004d7860.
  void FormatOverlayTerrainLabelText(CString* out);
  // 0x004d7a40 — copy identitySharedString1 (the +0x8 shared display-name ref) into
  // destString. Lives on TCountry (the field's owner): TViewMgr's overlay case 6 calls
  // it on g_apTerrainTypeDescriptorTable entries, which are TCountry*, not TGreatPower*.
  void LoadNationDisplayNameSharedRefFromField8(CString* destString);
  // 0x004d7ac0 -- the raw counterpart of the above: copies identitySharedString1
  // straight out, with no NormalizeRuntimeCredentialNameToken pass.
  void LoadNationDisplayNameRawFromField8(CString* destString);
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
  void SetSerializedField8c(int value);

  // Bare `this+0xe` (encodedNationSlot) range check, same test as the free-function
  // IsNationTerrainEligible helper in TSimMgr::AdvanceGlobalTurnStateMachine (its sole
  // caller, over g_apTerrainTypeDescriptorTable entries). 0x0057f0e0, __thiscall.
  bool IsNationProfileInMinorRange100To199();

  // 0x4d7170: lazily computes and caches the nation's overlay-anchor tile index.
  short GetOrComputeOverlayAnchorTileIndex();

  CString identitySharedString0;
  CString identitySharedString1;
  NationSlot nationSlot;
  EncodedNationSlot encodedNationSlot;
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
  int homeTileIndex;
  // 0x8c — cached overlay-anchor tile index (-1 = unset; lazily computed by
  // GetOrComputeOverlayAnchorTileIndex); serialized as a 4-byte block by slots
  // 0x0a/0x0b together with homeTileIndex.
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

// 0x004a5aa0 moved to TArmyMgr::ComputeWeightedNeighborLinkScoreForNodeIndex — both
// original callsites load ecx = g_pMapContextActionManager (thiscall, this unused).

ASSERT_SIZE(TCountry, 0x94);
