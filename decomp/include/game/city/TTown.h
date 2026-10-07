#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/resource_domain_types.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x0066d7c8
class TTown : public TObject {
public:
  DECLARE_DYNCREATE(TTown)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;

  virtual void CalculateRawResources();
  virtual void CalculateResources();
  virtual void CalculateCityResources();
  virtual void Grow();
  virtual void SetName(const char* townName);

  char name[16]; // strcpy'd marker name
  short tileIndex;
  short field16;
  short field18;
  short createdTurnTick; // localization tick at creation
  short ownerNation;
  short resourceYieldByType[kResourceKindCount]; // one yield count per resource type
  bool transportLinked;
  char enabledFlag; // verbatim serialized/init byte, not normalized
  bool hasAdjacentCity;
  bool activeFlag;

  TTown();
  void ITown(const char* markerName, short tileIndex, bool enabledFlag, short ownerNation);
  int IsUnblockedPort(void) const; // Mac name; full-EAX 0/1 return

  ~TTown() override;
};

ASSERT_SIZE(TTown, 0x50);
