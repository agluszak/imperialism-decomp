#pragma once

#include "game/city_ui/TCountry.h"
#include "game/resource_domain_types.h"

struct TMinorRuntimeStatusEntry {
  short fields[7];
};

ASSERT_SIZE(TMinorRuntimeStatusEntry, 0x0e);

// Minor-power nation row (g_apTerrainTypeDescriptorTable[7..], g_apSecondaryNationStateSlots).
// Inherits the TCountry prefix (0x94) and extends with minor-only tail state to 0x2dc.
// VTABLE: IMPERIALISM 0x00653c90
class TMinor : public TCountry {
public:
  TMinor();

  DECLARE_DYNCREATE(TMinor)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;

  void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) override;
  void BecomeProtectorateOf(int targetNationSlot) override;
  void BecomeColonyOf(int targetNationSlot) override;
  void RegainIndependence(void) override;
  void LoseProvince(int regionId) override;
  void AddProvince(int regionId) override;
  short GetAmtUnsold(short resourceKind) override;
  short GetStockpile(short resourceKind) override;
  short GetTradeOffersFor(short resourceKind) override;
  void PurchaseItem(short resourceKind, short amount, short price) override;
  bool StillBuyingItem(ResourceKindStorage resourceKind) override;
  char ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  char IsInConsortiumWith(short policyCode) override;
  void AddNoticeFrom(short sourceNation, short actionCode) override;

  // slot 0x2a (+0xa8), TMinor's first new virtual — vtable 0x653c90+0xa8 -> 0x4e46a0,
  // dispatched virtually by HandleTurnResumeStateTelemetry (0x5434 0e region).
  virtual void InitializeTradeStatus(void);
  virtual void SetTradeBids(void); // slot 0x2b 0x4e4bd0
  // Slot 0x2c: TForeignMinister::DoProposeTreaties dispatches it through the vtable
  // (CALL [vtbl+0xb0]) on the minor-nation array element, not as a direct call.
  virtual char WouldAcceptOffer(NationSlot targetNationSlot,
                                DiplomacyProposalCodeStorage proposalCode); // 0x4e4ff0
  virtual void ConvertCapitolToTown(int nationId);                          // slot 0x2d 0x4e5730
  virtual void SetBoycottPoliciesToMatch(int targetNationSlot);             // slot 0x2e 0x4e5a40
  virtual void KillForeignCompaniesIn(int provinceId);                      // slot 0x2f 0x4e5ac0
  virtual void KillBoycottedForeignCompanies(void);                         // slot 0x30 0x4e5be0
  virtual void KillEnemyCiviliansIn(int provinceId);                        // slot 0x31 0x4e5d90
  short GetDiplomacyRandomThreshold124() const {
    return diplomacyRandomThreshold124;
  }

  virtual void DeportCiviliansIn(int provinceId,
                                 unsigned char includeAllPolicyTargets); // slot 0x32 0x4e6150
  virtual void AssimilateTroopsOf(int priorOwnerNationSlot);             // slot 0x33 0x4e6040
  virtual void ChangeArmyOwnership(int destinationNationSlot);           // slot 0x34 0x4e6520

  // Full (re)initialization of a minor nation's per-session state: nation identity +
  // owned-region list, diplomacy policy defaults, the five per-resource/per-nation
  // short tables and all 23 status rows cleared, need counters recounted from owned
  // map tiles, home tile selected (flagged tile, else a random valid candidate) with
  // its port zone ensured, and the per-slot diplomacy random thresholds and save
  // fields set from the 16-way nation-slot table. 0x4e3830, __thiscall, RET 4.
  void IMinor(NationSlot nationSlot);

private:
  short needCurrentByType[kResourceKindCount];
  short tradeOffersByResource[kResourceKindCount];
  short grantAmountsByResource[kResourceKindCount];
  short diplomacyRandomThreshold11e;
  short diplomacyRandomThreshold120;
  short diplomacyRandomThreshold122;
  short diplomacyRandomThreshold124;
  short diplomacyRandomThreshold126;
  short diplomacyRandomThreshold128;
  short diplomacyRandomThreshold12a;
  short diplomacyPolicyPredicateCode12c;
  short diplomacyPolicyPredicateCode12e;
  short diplomacyPolicyGate130;
  short diplomacyPolicyGate132;
  // Serialized as a unit by ReadFrom/WriteTo (byte-order swapped via
  // SwapAdjacentBytesInShortArray on load); diplomacySaveExt13c is only present when
  // g_nSaveFormatVersion > 0x39 (a later save-format addition). Same 0x17-short size as
  // the sibling grantAmountsByResource/recurringGrantByResource tables, but the indexed
  // dimension (nation vs. resource) is not yet confirmed.
  short diplomacySaveFields134[4]; // 0x134
public:
  short diplomacySaveExt13c[0x17]; // 0x13c
private:
  short recurringGrantByResource[kResourceKindCount];
  // +0x198. 23 rows of seven shorts, cleared row-by-row (as one 0x0e-byte memset per
  // row) by the same 0x17-iteration loop that clears the five short tables above
  // (0x4e3830). Rows 0..6 form the relation/grant/link matrix indexed
  // [relationSlot][majorNationSlot]; the individual meanings of rows 7..22 are not
  // yet recovered.
  TMinorRuntimeStatusEntry statusRows[0x17];
  short runtimeStatusTail2da;

protected:
  // Inline so network minor subclasses reproduce the original direct CString teardown.
  // FUNCTION: IMPERIALISM 0x004e37c0
  ~TMinor() override {}
};

ASSERT_SIZE(TMinor, 0x2dc);
