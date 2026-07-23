#pragma once

// The resource/commodity kind domain shared by the map, city, trade, transport,
// minister, and navy subsystems.
//
// Evidence: Mac STR# group 10001 (Windows string group 0x2711, consumed by
// TSimMgr::GetStringPrelude 0x0057fe90) names exactly 23 entries in this order,
// and the same order appears in the TCity per-commodity stock block
// (+0xb6..+0xe4), in the resource icon sheet (bitmap ids 700..722), and in every
// short[23]/short[0x17] per-resource table in the source.
//
// The domain is stored in several widths -- signed byte in the strategic terrain
// record's per-edge slots (with -1 meaning "no resource"), signed word in the
// city/minister/trade tables and in most APIs, and full int in loop counters --
// so this header only names the values. Storage widths stay exactly as the
// retail layout and serialization require.
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

// Three contiguous sub-bands partition the domain. They are not stylistic: the
// retail code repeatedly tests them as ranges.
//
//  * Industrial raw materials 0..6 come off the strategic map as tile yields and
//    feed city industry (TCityInteriorMinister::EvaluateResources 0x004c3490
//    scores exactly [0,7)).
//  * Manufactured goods 7..16 are produced by city industry and are the only
//    band with a market price (TMapMgr::CalculateDeveloperTilePurchaseCost
//    0x005155c0 prices `< 17` through the proposal-weight table) and the only
//    band with per-province development counters (TMapMgr's
//    resourceDevelopmentCounts82[10], indexed by kind - 7).
//  * Harvested food and precious metals 17..22 also come off the map, which is
//    why tile-yield loops test the union of the first and last bands
//    (TCityInteriorMinister 0x004c2e50 walks `(0..6) || (17..22)`).
enum ResourceKindBand {
  kResourceIndustrialRawFirst = kResourceCotton, // 0
  kResourceIndustrialRawLast = kResourceOil,     // 6
  kResourceIndustrialRawCount = 7,               // one past kResourceOil
  kResourceManufacturedFirst = kResourceFood,    // 7
  kResourceManufacturedLast = kResourceArms,     // 16
  kResourceManufacturedEnd = kResourceGrain,     // one past kResourceArms
  kResourceManufacturedCount = 10,
  kResourceHarvestedFirst = kResourceGrain, // 17
  kResourceHarvestedLast = kResourceGold    // 22
};

// The strategic terrain record stores two per-edge resource slots as signed
// bytes and uses -1 for "this edge yields nothing"; word-sized APIs pass the
// same sentinel through.
enum { kResourceKindNone = -1 };

// The 14-entry industry / navy-order type domain. It is NOT ResourceKind, even though
// the same `resourceType` parameter name reaches both: TCity::orderCountByType5c and
// TTechMgr::CapRowB::selectedByResourceType are both [0x0e], TTechMgr's slotMap covers
// 0..13, and GetResourceDescriptorWeightWord0ByType is indexed over the same range.
enum { kIndustryActionOrderTypeCount = 14 };

typedef short ResourceKindStorage;
