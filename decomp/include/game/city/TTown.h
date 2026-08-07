#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/resource_domain_types.h"

struct CRuntimeClass;

// Town marker record (0x50 bytes) kept on TGreatPower::townMarkerList.
// A settlement marker placed on one strategic tile. A nation owns MANY of these
// (TGreatPower::townMarkerList) but exactly ONE TCity (TGreatPower::city, singular), so
// TTown and TCity are not two names for the same thing and neither contains the other:
//
//   TGreatPower --- city ------------> TCity      (one: industry, stock, production orders)
//               \-- townMarkerList --> TTown[]    (many: harvest tiles, grow, ports)
//
// A town is the harvesting half of the model. CalculateCityResources sums yields from its
// own tile and its 6 neighbours (the 0..6 loop), skipping tiles owned by another nation
// unless they are water, into resourceYieldByType. The city is the consuming half: it
// holds the stock counters and production orders that those yields feed.
//
// The link between them is TCity::homeTownMarkerB0, which points at the town occupying
// the nation's capital tile -- TGreatPower::SetHomeCityTileAndDisplayName (0x4dfd30)
// takes the nation's homeTileIndex straight from that marker's tileIndex. That is why
// a *town* method is named CalculateCityResources: the capital's own resource intake is
// gathered by the town marker sitting on it, not by TCity itself.
//
// There is deliberately no TCity back-pointer here. A town reaches its city through its
// owning nation (ownerNation -> TGreatPower -> city), which is what the resource code
// does; adding a field would not match the original's 0x50 layout.
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

  char name[0x10]; // 0x04 — strcpy'd marker name
  short tileIndex; // 0x14
  // Two 16-bit slots, not a byte array: ITown zeroes them with `MOV word ptr
  // [EBP+0x16],0` / `[EBP+0x18],0` (0x5b6d1c/0x5b6d22) and both serializers move them
  // as separate 2-byte fields. Purpose unknown -- no reader exists anywhere in the
  // image beyond init and round-trip -- so they stay opaque but correctly sized.
  short field16;                                 // 0x16
  short field18;                                 // 0x18
  short createdTurnTick;                         // 0x1a — localization tick at creation
  short ownerNation;                             // 0x1c
  short resourceYieldByType[kResourceKindCount]; // 0x1e..0x4b — one yield count per resource type
  bool transportLinked;                          // 0x4c
  char enabledFlag;     // 0x4d — verbatim serialized/init byte, not normalized
  bool hasAdjacentCity; // 0x4e
  bool activeFlag;      // 0x4f

  TTown();
  // Mac oracle: ITown(const char*, short, unsigned char, short).
  void ITown(const char* markerName, short tileIndex, unsigned char enabledFlag, short ownerNation);
  int IsUnblockedPort(void) const; // 0x5b7830: Mac name; full-EAX 0/1 return

  ~TTown() override;
};

ASSERT_SIZE(TTown, 0x50);
