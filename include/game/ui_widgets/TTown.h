#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

struct CRuntimeClass;

// Town marker record (0x50 bytes) kept on TGreatPower::townMarkerList.
// VTABLE: IMPERIALISM 0x0066d7c8
class TTown : public TObject {
public:
  DECLARE_DYNCREATE(TTown)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;

  virtual void CalculateRawResources();       // slot 0x0a 0x5b6f70
  virtual void CalculateResources();          // slot 0x0b 0x5b7140
  virtual void CalculateCityResources();      // slot 0x0c 0x5b73e0
  virtual void Grow();                        // slot 0x0d 0x5b7570
  virtual void SetName(const char* townName); // slot 0x0e 0x5b77e0

  char name[0x10];   // 0x04 — strcpy'd marker name
  short tileIndex14; // 0x14
  // Two 16-bit slots, not a byte array: ITown zeroes them with `MOV word ptr
  // [EBP+0x16],0` / `[EBP+0x18],0` (0x5b6d1c/0x5b6d22) and both serializers move them
  // as separate 2-byte fields. Purpose unknown -- no reader exists anywhere in the
  // image beyond init and round-trip -- so they stay opaque but correctly sized.
  short field16;                   // 0x16
  short field18;                   // 0x18
  short createdTurnTick1a;         // 0x1a — localization tick at creation
  short ownerNation1c;             // 0x1c
  short resourceYieldByType[0x17]; // 0x1e..0x4b — one yield count per resource type
  bool transportLinkedFlag4c;      // 0x4c
  char enabledFlag4d;              // 0x4d — verbatim serialized/init byte, not normalized
  bool hasAdjacentCity4e;          // 0x4e
  bool activeFlag4f;               // 0x4f

  TTown();
  void ITown(const char* markerName, short tileIndex, char enabledFlag, short ownerNation);
  int IsUnblockedPort(void) const; // 0x5b7830: Mac name; full-EAX 0/1 return

  ~TTown() override;
};

ASSERT_SIZE(TTown, 0x50);
