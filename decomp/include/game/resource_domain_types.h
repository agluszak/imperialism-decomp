#pragma once

enum ResourceKind {
  kResourceCotton = 0,
  kResourceWool = 1,
  kResourceTimber = 2,
  kResourceCoal = 3,
  kResourceIron = 4,
  kResourceHorses = 5,
  kResourceOil = 6,
  kResourceFood = 7,
  kResourceFabric = 8,
  kResourceLumber = 9,
  kResourcePaper = 10,
  kResourceSteel = 11,
  kResourceFuel = 12,
  kResourceClothing = 13,
  kResourceFurniture = 14,
  kResourceHardware = 15,
  kResourceArms = 16,
  kResourceGrain = 17,
  kResourceFruit = 18,
  kResourceFish = 19,
  kResourceLivestock = 20,
  kResourceGems = 21,
  kResourceGold = 22,
  kResourceKindCount = 23
};

enum ResourceKindBand {
  kResourceIndustrialRawFirst = kResourceCotton,
  kResourceIndustrialRawLast = kResourceOil,
  kResourceIndustrialRawCount = 7, // one past kResourceOil
  kResourceManufacturedFirst = kResourceFood,
  kResourceManufacturedLast = kResourceArms,
  kResourceManufacturedEnd = kResourceGrain, // one past kResourceArms
  kResourceManufacturedCount = 10,
  kResourceHarvestedFirst = kResourceGrain,
  kResourceHarvestedLast = kResourceGold
};

enum { kResourceKindNone = -1 };

enum { kIndustryActionSlotCount = 14 };

typedef short IndustryActionSlotStorage;

typedef short ResourceKindStorage;
