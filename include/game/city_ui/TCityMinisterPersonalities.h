#pragma once

#include "game/city_ui/TCityInteriorMinister.h"

// VTABLE: IMPERIALISM 0x00650a70
class TSteelCityMinister : public TCityInteriorMinister {
public:
  DECLARE_DYNCREATE(TSteelCityMinister)
  TSteelCityMinister();
  void InitializeCityInteriorState(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};

// VTABLE: IMPERIALISM 0x00650bd0
class TShipBuilderCityMinister : public TCityInteriorMinister {
public:
  DECLARE_DYNCREATE(TShipBuilderCityMinister)
  TShipBuilderCityMinister();
  void InitializeCityInteriorState(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};

// VTABLE: IMPERIALISM 0x00650d30
class TEvenCityMinister : public TCityInteriorMinister {
public:
  DECLARE_DYNCREATE(TEvenCityMinister)
  TEvenCityMinister();
  void InitializeCityInteriorState(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};

// VTABLE: IMPERIALISM 0x00650e90
class TRailCityMinister : public TCityInteriorMinister {
public:
  DECLARE_DYNCREATE(TRailCityMinister)
  TRailCityMinister();
  void InitializeCityInteriorState(TGreatPower* owner);
  void FillLists() override; // slot 0x20 (byte 0x80) priority preset
};
