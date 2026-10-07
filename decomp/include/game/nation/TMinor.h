#pragma once

#include "game/nation_domain_types.h"
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
  bool ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  bool IsInConsortiumWith(short policyCode) override;
  void AddNoticeFrom(short sourceNation, short actionCode) override;

  virtual void InitializeTradeStatus(void);
  virtual void SetTradeBids(void);
  virtual bool WouldAcceptOffer(NationSlot targetNationSlot,
                                DiplomacyProposalCodeStorage proposalCode);
  virtual void HandleNetworkPortConstructionOrder(int nationId);
  virtual void SetBoycottPoliciesToMatch(int targetNationSlot);
  virtual void ClearTileActivityOverlayByProvinceId(int provinceId);
  virtual void KillBoycottedForeignCompanies(void);
  virtual void KillEnemyCiviliansIn(int provinceId);
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
    return primaryManufacturedPriceThreshold;
  }
  short GetSecondaryManufacturedPriceThreshold() const {
    return secondaryManufacturedPriceThreshold;
  }
  short GetGeneralOfferPriceThreshold() const {
    return generalOfferPriceThreshold;
  }
  short GetRandomOfferPriceThreshold() const {
    return randomOfferPriceThreshold;
  }
  short GetCoalOfferPriceThreshold() const {
    return coalOfferPriceThreshold;
  }
  short GetIronOfferPriceThreshold() const {
    return ironOfferPriceThreshold;
  }
  short GetOilOfferPriceThreshold() const {
    return oilOfferPriceThreshold;
  }
  ResourceKindStorage GetPrimaryManufacturedRequest() const {
    return primaryManufacturedRequest;
  }
  ResourceKindStorage GetSecondaryManufacturedRequest() const {
    return secondaryManufacturedRequest;
  }
  short GetPrimaryManufacturedRequestFulfilledAmount() const {
    return primaryManufacturedRequestFulfilledAmount;
  }
  short GetSecondaryManufacturedRequestFulfilledAmount() const {
    return secondaryManufacturedRequestFulfilledAmount;
  }
  short GetIndependentResourceCount(ResourceKindStorage resourceKind) const {
    ASSERT(resourceKind >= 0 && resourceKind < kResourceKindCount);
    return independentResourceCountByType[resourceKind];
  }
  NationSlot GetConsortiumMember(int index) const {
    ASSERT(index >= 0 && index < 4);
    return consortiumMembers[index];
  }

  virtual void DeportCiviliansIn(int provinceId, bool includeAllPolicyTargets);
  virtual void AssimilateTroopsOf(int priorOwnerNationSlot);
  virtual void ChangeArmyOwnership(int destinationNationSlot);

  void IMinor(NationSlot nationSlot);

private:
  short needCurrentByType[kResourceKindCount];
  short tradeOffersByResource[kResourceKindCount];
  short grantAmountsByResource[kResourceKindCount];
  short primaryManufacturedPriceThreshold;
  short secondaryManufacturedPriceThreshold;
  short generalOfferPriceThreshold;
  short randomOfferPriceThreshold;
  short coalOfferPriceThreshold;
  short ironOfferPriceThreshold;
  short oilOfferPriceThreshold;
  short primaryManufacturedRequest;
  short secondaryManufacturedRequest;
  short primaryManufacturedRequestFulfilledAmount;
  short secondaryManufacturedRequestFulfilledAmount;
  short consortiumMembers[4];

public:
  short independentResourceCountByType[kResourceKindCount];

private:
  short foreignControlledResourceYieldByType[kResourceKindCount];
  TMinorForeignResourceYieldByMajorNation
      foreignControlledResourceYieldByTypeAndMajorNation[kResourceKindCount];

protected:
  // Inline so network minor subclasses reproduce the original direct CString teardown.
  // FUNCTION: IMPERIALISM 0x004e37c0
  ~TMinor() override {}
};

ASSERT_SIZE(TMinor, 0x2dc);
