#pragma once

#include "game/TCityInteriorMinister.h"

// VTABLE: IMPERIALISM 0x00650a70
class TSteelCityMinister : public TCityInteriorMinister {
public:
  TSteelCityMinister();
  DECLARE_DYNCREATE(TSteelCityMinister)
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};

// VTABLE: IMPERIALISM 0x00650bd0
class TShipBuilderCityMinister : public TCityInteriorMinister {
public:
  TShipBuilderCityMinister();
  DECLARE_DYNCREATE(TShipBuilderCityMinister)
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};

// VTABLE: IMPERIALISM 0x00650d30
class TEvenCityMinister : public TCityInteriorMinister {
public:
  TEvenCityMinister();
  DECLARE_DYNCREATE(TEvenCityMinister)
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};

// VTABLE: IMPERIALISM 0x00650e90
class TRailCityMinister : public TCityInteriorMinister {
public:
  TRailCityMinister();
  DECLARE_DYNCREATE(TRailCityMinister)
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};
