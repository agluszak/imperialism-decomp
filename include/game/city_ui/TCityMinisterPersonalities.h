#pragma once

#include "compat.h"

#include "game/city_ui/TCityInteriorMinister.h"

// VTABLE: IMPERIALISM 0x00650a70
class TSteelCityMinister : public TCityInteriorMinister {
public:
  // FUNCTION: IMPERIALISM 0x004c5a50
  ~TSteelCityMinister() override {}
  DECLARE_DYNCREATE(TSteelCityMinister)
  TSteelCityMinister();
  // MacApp two-phase initializer; chains to the base one. Mac oracle:
  // TSteelCityMinister::ISteelCityMinister(TGreatPower*) -- attested, and the body is exactly
  // that chain call (RET 0x4, one stack arg).
  void ISteelCityMinister(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};
ASSERT_SIZE(TSteelCityMinister, 0x1c4);

// VTABLE: IMPERIALISM 0x00650bd0
class TShipBuilderCityMinister : public TCityInteriorMinister {
public:
  // FUNCTION: IMPERIALISM 0x004c5d50
  ~TShipBuilderCityMinister() override {}
  DECLARE_DYNCREATE(TShipBuilderCityMinister)
  TShipBuilderCityMinister();
  // MacApp two-phase initializer; chains to the base one. Mac oracle:
  // TShipBuilderCityMinister::IShipBuilderCityMinister(TGreatPower*) -- attested, and the body is exactly
  // that chain call (RET 0x4, one stack arg).
  void IShipBuilderCityMinister(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};
ASSERT_SIZE(TShipBuilderCityMinister, 0x1c4);

// VTABLE: IMPERIALISM 0x00650d30
class TEvenCityMinister : public TCityInteriorMinister {
public:
  // FUNCTION: IMPERIALISM 0x004c6050
  ~TEvenCityMinister() override {}
  DECLARE_DYNCREATE(TEvenCityMinister)
  TEvenCityMinister();
  // MacApp two-phase initializer; chains to the base one. Mac oracle:
  // TEvenCityMinister::IEvenCityMinister(TGreatPower*) -- attested, and the body is exactly
  // that chain call (RET 0x4, one stack arg).
  void IEvenCityMinister(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};
ASSERT_SIZE(TEvenCityMinister, 0x1c4);

// VTABLE: IMPERIALISM 0x00650e90
class TRailCityMinister : public TCityInteriorMinister {
public:
  // FUNCTION: IMPERIALISM 0x004c6360
  ~TRailCityMinister() override {}
  DECLARE_DYNCREATE(TRailCityMinister)
  TRailCityMinister();
  // MacApp two-phase initializer; chains to the base one. Mac oracle:
  // TRailCityMinister::IRailCityMinister(TGreatPower*) -- attested, and the body is exactly
  // that chain call (RET 0x4, one stack arg).
  void IRailCityMinister(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};
ASSERT_SIZE(TRailCityMinister, 0x1c4);
