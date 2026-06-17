#pragma once

#include "game/TCityInteriorMinister.h"

// VTABLE: IMPERIALISM 0x00650a70
class TSteelCityMinister : public TCityInteriorMinister {
public:
  TSteelCityMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};

// VTABLE: IMPERIALISM 0x00650bd0
class TShipBuilderCityMinister : public TCityInteriorMinister {
public:
  TShipBuilderCityMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};

// VTABLE: IMPERIALISM 0x00650d30
class TEvenCityMinister : public TCityInteriorMinister {
public:
  TEvenCityMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};

// VTABLE: IMPERIALISM 0x00650e90
class TRailCityMinister : public TCityInteriorMinister {
public:
  TRailCityMinister();
  CRuntimeClass* GetRuntimeClass() const override;
  void CityInteriorSlot20() override; // slot 0x80 priority preset
};
