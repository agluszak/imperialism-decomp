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

// VTABLE: IMPERIALISM 0x00653868
class TCountry : public TObject {
public:
  DECLARE_DYNCREATE(TCountry)
  // FUNCTION: IMPERIALISM 0x004d6880
  ~TCountry() override {}

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  virtual void MultiWriteTo(TStream* stream);
  virtual void MultiReadFrom(TStream* stream, int unusedArg);
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
  virtual bool IsColonyOf(int nationCode);

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
  virtual bool ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                                 ResourceKindStorage resourceKind);
  virtual void AddOfferFrom(NationSlot sourceNationSlot, DiplomacyProposalCodeStorage proposalCode);
  virtual bool IsInConsortiumWith(short policyCode);
  virtual void AddNoticeFrom(short sourceNation, short actionCode);
  virtual bool IsClient(void) const;
  virtual bool IsHost(void) const;
  virtual bool IsRemote(void) const;
  virtual void PlopDownCity(short selectedRegion, const char* mapCellLabel);

  int GetTotalLandForce(void);
  int GetLandForceIn(int nodeIndex);

  void InitializeNationStateIdentityAndOwnedRegionList(NationSlot nationSlot);
  void GenerateEthnicName(CString* out) const;
  void FormatOverlayTerrainLabelText(CString* out);
  void GetName(CString* destString);
  void GetNameWithCode(CString* destString);
  int GetArmsInArmy();
  void AssignSharedStringFromDescriptorNameOrDefault(CString* out);

  void SetNationDisplayNameAndLocalizationSlotRef(const CString& name);

  void SetCenterTile(int value);

  bool IsProtectorate();

  short GeopoliticalCenter();

  CString identitySharedString0;
  CString identitySharedString1;
  NationSlot nationSlot;
  EncodedNationSlot encodedNationSlot;
  int treasuryValue;
  short tradePolicyByNation[kNationSlotCount];
  short field42;
  TSortedList* militaryUnitList;
  short unitNameOrdinalByType[0x1e];
  short unitNameCounter; // monotonically increasing name tag (stored at +0x1a)
  short pad_86;
  int homeTileIndex;
  int overlayAnchorTileCache;
  TLongintList* ownedRegionList;

  TCountry();
};

ASSERT_SIZE(TCountry, 0x94);
