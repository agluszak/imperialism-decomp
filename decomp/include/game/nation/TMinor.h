#pragma once

#include "game/city_ui/TCountry.h"
#include "game/resource_domain_types.h"

struct TMinorForeignResourceYieldByMajorNation {
  short amountByMajorNation[kMajorNationCount];
};

ASSERT_SIZE(TMinorForeignResourceYieldByMajorNation, 0x0e);

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

  virtual void InitializeTradeStatus(void);
  virtual void SetTradeBids(void); // slot 0x2b 0x4e4bd0
  virtual char WouldAcceptOffer(NationSlot targetNationSlot,
                                DiplomacyProposalCodeStorage proposalCode); // 0x4e4ff0
  virtual void HandleNetworkPortConstructionOrder(int nationId);            // slot 0x2d 0x4e5730
  virtual void SetBoycottPoliciesToMatch(int targetNationSlot);             // slot 0x2e 0x4e5a40
  virtual void ClearTileActivityOverlayByProvinceId(int provinceId);        // slot 0x2f 0x4e5ac0
  virtual void KillBoycottedForeignCompanies(void);                         // slot 0x30 0x4e5be0
  virtual void KillEnemyCiviliansIn(int provinceId);                        // slot 0x31 0x4e5d90
  short GetDiplomacyRandomThreshold124() const {
    return diplomacyRandomThreshold124;
  }
  short GetCurrentTradeSupply(ResourceKindStorage resourceKind) const {
    ASSERT(resourceKind >= 0 && resourceKind < kResourceKindCount);
    return needCurrentByType[resourceKind];
  }
  short GetTradeOffer(ResourceKindStorage resourceKind) const {
    ASSERT(resourceKind >= 0 && resourceKind < kResourceKindCount);
    return tradeOffersByResource[resourceKind];
  }
  short GetTradeGrantDelta(ResourceKindStorage resourceKind) const {
    ASSERT(resourceKind >= 0 && resourceKind < kResourceKindCount);
    return grantAmountsByResource[resourceKind];
  }
  short GetPrimaryManufacturedPriceThreshold() const {
    return diplomacyRandomThreshold11e;
  }
  short GetSecondaryManufacturedPriceThreshold() const {
    return diplomacyRandomThreshold120;
  }
  short GetGeneralOfferPriceThreshold() const {
    return diplomacyRandomThreshold122;
  }
  short GetRandomOfferPriceThreshold() const {
    return diplomacyRandomThreshold124;
  }
  short GetCoalOfferPriceThreshold() const {
    return diplomacyRandomThreshold126;
  }
  short GetIronOfferPriceThreshold() const {
    return diplomacyRandomThreshold128;
  }
  short GetOilOfferPriceThreshold() const {
    return diplomacyRandomThreshold12a;
  }
  ResourceKindStorage GetPrimaryManufacturedRequest() const {
    return diplomacyPolicyPredicateCode12c;
  }
  ResourceKindStorage GetSecondaryManufacturedRequest() const {
    return diplomacyPolicyPredicateCode12e;
  }
  short GetPrimaryManufacturedRequestFulfilledAmount() const {
    return diplomacyPolicyGate130;
  }
  short GetSecondaryManufacturedRequestFulfilledAmount() const {
    return diplomacyPolicyGate132;
  }
  short GetIndependentResourceCount(ResourceKindStorage resourceKind) const {
    ASSERT(resourceKind >= 0 && resourceKind < kResourceKindCount);
    return independentResourceCountByType[resourceKind];
  }
  NationSlot GetConsortiumMember(int index) const {
    ASSERT(index >= 0 && index < 4);
    return diplomacySaveFields[index];
  }

  virtual void DeportCiviliansIn(int provinceId,
                                 bool includeAllPolicyTargets); // slot 0x32 0x4e6150
  virtual void AssimilateTroopsOf(int priorOwnerNationSlot);    // slot 0x33 0x4e6040
  virtual void ChangeArmyOwnership(int destinationNationSlot);  // slot 0x34 0x4e6520

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
  // The four persisted consortium nation slots consumed by IsInConsortiumWith.
  short diplomacySaveFields[4]; // 0x134
public:
  short independentResourceCountByType[kResourceKindCount]; // 0x13c
private:
  short foreignControlledResourceYieldByType[kResourceKindCount]; // 0x16a
  TMinorForeignResourceYieldByMajorNation
      foreignControlledResourceYieldByTypeAndMajorNation[kResourceKindCount]; // 0x198

protected:
  // Inline so network minor subclasses reproduce the original direct CString teardown.
  // FUNCTION: IMPERIALISM 0x004e37c0
  ~TMinor() override {}
};

ASSERT_SIZE(TMinor, 0x2dc);
