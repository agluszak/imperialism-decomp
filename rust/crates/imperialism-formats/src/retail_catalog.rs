//! Typed retail picture and atlas mappings for dynamic families.
//!
//! Callers pass a game concept; this module owns the PictureId / atlas-cell
//! relation. Fixed one-off pictures stay as `PictureId::new` at the call site.

use crate::PictureId;
use enum_map::{Enum, EnumMap};
use imperialism_core::{
    CityFacilitySlot, CivilianUnitKind, CivilianUnitTable, MajorNationId, MajorNationTable,
    MilitaryUnitKind, MilitaryUnitTable, MinorNationTable, NationId, ProductionTable, ResourceKind,
    ResourceTable, ShipType, ShipTypeTable, Technology, TechnologyTable, TileContext, TileFlags,
};

const OWNER_FLAG_CELL_WIDTH: i32 = 9;
const SETUP_FLAG_WIDTH: f32 = 32.0;
const SETUP_FLAG_HEIGHT: f32 = 24.0;

const DIALOG_COATS: MajorNationTable<PictureId> = MajorNationTable::from_array([
    PictureId::new(9500),
    PictureId::new(9501),
    PictureId::new(9502),
    PictureId::new(9503),
    PictureId::new(9504),
    PictureId::new(9505),
    PictureId::new(9506),
]);

const SETUP_COATS: MajorNationTable<PictureId> = MajorNationTable::from_array([
    PictureId::new(0x11c6),
    PictureId::new(0x11c7),
    PictureId::new(0x11c8),
    PictureId::new(0x11c9),
    PictureId::new(0x11ca),
    PictureId::new(0x11cb),
    PictureId::new(0x11cc),
]);

const FLEET_ATLAS: EnumMap<FleetVisualEra, MajorNationTable<PictureId>> = EnumMap::from_array([
    MajorNationTable::from_array([
        PictureId::new(1380),
        PictureId::new(1381),
        PictureId::new(1382),
        PictureId::new(1383),
        PictureId::new(1384),
        PictureId::new(1385),
        PictureId::new(1386),
    ]),
    MajorNationTable::from_array([
        PictureId::new(1387),
        PictureId::new(1388),
        PictureId::new(1389),
        PictureId::new(1390),
        PictureId::new(1391),
        PictureId::new(1392),
        PictureId::new(1393),
    ]),
    MajorNationTable::from_array([
        PictureId::new(1394),
        PictureId::new(1395),
        PictureId::new(1396),
        PictureId::new(1397),
        PictureId::new(1398),
        PictureId::new(1399),
        PictureId::new(1400),
    ]),
]);

const ARMY_COUNT_PICTURES: EnumMap<ArmyCountBucket, PictureId> = EnumMap::from_array([
    PictureId::new(570),
    PictureId::new(572),
    PictureId::new(574),
    PictureId::new(576),
]);

const OWNER_FLAG_STRIP: PictureId = PictureId::new(580);
const SETUP_FLAG_STRIP: PictureId = PictureId::new(8699);

const OWNER_FLAG_X: MajorNationTable<i32> =
    MajorNationTable::from_array([0, 9, 18, 27, 36, 45, 54]);
const NEUTRAL_OWNER_FLAG_X: i32 = 63;

const SETUP_FLAG_X: MajorNationTable<f32> =
    MajorNationTable::from_array([0.0, 32.0, 64.0, 96.0, 128.0, 160.0, 192.0]);

const CIVILIAN_IDLE: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(402),
    PictureId::new(403),
    PictureId::new(401),
    PictureId::new(406),
    PictureId::new(400),
    PictureId::new(407),
    PictureId::new(405),
    PictureId::new(404),
    PictureId::new(408),
]);
const CIVILIAN_SELECTED: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(411),
    PictureId::new(412),
    PictureId::new(410),
    PictureId::new(415),
    PictureId::new(409),
    PictureId::new(416),
    PictureId::new(414),
    PictureId::new(413),
    PictureId::new(417),
]);
const CIVILIAN_WORKING: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(420),
    PictureId::new(421),
    PictureId::new(419),
    PictureId::new(424),
    PictureId::new(418),
    PictureId::new(425),
    PictureId::new(423),
    PictureId::new(422),
    PictureId::new(426),
]);
const CIVILIAN_ANIMATED: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(14_000),
    PictureId::new(14_005),
    PictureId::new(14_011),
    PictureId::new(14_015),
    PictureId::new(14_021),
    PictureId::new(14_026),
    PictureId::new(14_030),
    PictureId::new(14_035),
    PictureId::new(14_040),
]);

const RESOURCE_ICONS: ResourceTable<PictureId> = ResourceTable::from_array([
    PictureId::new(700),
    PictureId::new(701),
    PictureId::new(702),
    PictureId::new(703),
    PictureId::new(704),
    PictureId::new(705),
    PictureId::new(706),
    PictureId::new(707),
    PictureId::new(708),
    PictureId::new(709),
    PictureId::new(710),
    PictureId::new(711),
    PictureId::new(712),
    PictureId::new(713),
    PictureId::new(714),
    PictureId::new(715),
    PictureId::new(716),
    PictureId::new(717),
    PictureId::new(718),
    PictureId::new(719),
    PictureId::new(720),
    PictureId::new(721),
    PictureId::new(722),
]);

const OCEAN_FLEET: EnumMap<FleetVisualEra, MajorNationTable<PictureId>> = EnumMap::from_array([
    MajorNationTable::from_array([
        PictureId::new(1401),
        PictureId::new(1402),
        PictureId::new(1403),
        PictureId::new(1404),
        PictureId::new(1405),
        PictureId::new(1406),
        PictureId::new(1407),
    ]),
    MajorNationTable::from_array([
        PictureId::new(1408),
        PictureId::new(1409),
        PictureId::new(1410),
        PictureId::new(1411),
        PictureId::new(1412),
        PictureId::new(1413),
        PictureId::new(1414),
    ]),
    MajorNationTable::from_array([
        PictureId::new(1415),
        PictureId::new(1416),
        PictureId::new(1417),
        PictureId::new(1418),
        PictureId::new(1419),
        PictureId::new(1420),
        PictureId::new(1421),
    ]),
]);

const SHIP_PORTRAITS: ShipTypeTable<PictureId> = ShipTypeTable::from_array([
    PictureId::new(9834),
    PictureId::new(9835),
    PictureId::new(9836),
    PictureId::new(9837),
    PictureId::new(9838),
    PictureId::new(9839),
    PictureId::new(9840),
    PictureId::new(9841),
    PictureId::new(9842),
    PictureId::new(9843),
    PictureId::new(9844),
    PictureId::new(9845),
    PictureId::new(9846),
    PictureId::new(9847),
]);

const SHIPYARD_QUEUE_STRIP: PictureId = PictureId::new(9807);
const DEAL_BOOK_FLAG_STRIP: PictureId = PictureId::new(680);
const RESOURCE_SPECIALTY_STRIP: PictureId = PictureId::new(750);

const CIVILIAN_PORTRAITS: CivilianUnitTable<PictureId> = CivilianUnitTable::from_array([
    PictureId::new(1080),
    PictureId::new(1081),
    PictureId::new(1082),
    PictureId::new(1083),
    PictureId::new(1084),
    PictureId::new(1085),
    PictureId::new(1086),
    PictureId::new(1087),
    PictureId::new(1088),
]);

const NAVY_CLASS_PICTURES: ShipTypeTable<PictureId> = ShipTypeTable::from_array([
    PictureId::new(1510),
    PictureId::new(1511),
    PictureId::new(1512),
    PictureId::new(1513),
    PictureId::new(1514),
    PictureId::new(1515),
    PictureId::new(1516),
    PictureId::new(1517),
    PictureId::new(1518),
    PictureId::new(1519),
    PictureId::new(1520),
    PictureId::new(1521),
    PictureId::new(1522),
    PictureId::new(1523),
]);

const TECH_STORE_IDLE: TechnologyTable<PictureId> = TechnologyTable::from_array([
    PictureId::new(2303),
    PictureId::new(2305),
    PictureId::new(2307),
    PictureId::new(2309),
    PictureId::new(2311),
    PictureId::new(2313),
    PictureId::new(2315),
    PictureId::new(2317),
    PictureId::new(2319),
    PictureId::new(2321),
    PictureId::new(2323),
    PictureId::new(2325),
    PictureId::new(2327),
    PictureId::new(2329),
    PictureId::new(2331),
    PictureId::new(2333),
    PictureId::new(2335),
    PictureId::new(2337),
    PictureId::new(2339),
    PictureId::new(2341),
    PictureId::new(2343),
    PictureId::new(2345),
    PictureId::new(2347),
    PictureId::new(2349),
    PictureId::new(2351),
    PictureId::new(2353),
    PictureId::new(2355),
    PictureId::new(2357),
    PictureId::new(2359),
]);
const TECH_STORE_ACTIVE: TechnologyTable<PictureId> = TechnologyTable::from_array([
    PictureId::new(2304),
    PictureId::new(2306),
    PictureId::new(2308),
    PictureId::new(2310),
    PictureId::new(2312),
    PictureId::new(2314),
    PictureId::new(2316),
    PictureId::new(2318),
    PictureId::new(2320),
    PictureId::new(2322),
    PictureId::new(2324),
    PictureId::new(2326),
    PictureId::new(2328),
    PictureId::new(2330),
    PictureId::new(2332),
    PictureId::new(2334),
    PictureId::new(2336),
    PictureId::new(2338),
    PictureId::new(2340),
    PictureId::new(2342),
    PictureId::new(2344),
    PictureId::new(2346),
    PictureId::new(2348),
    PictureId::new(2350),
    PictureId::new(2352),
    PictureId::new(2354),
    PictureId::new(2356),
    PictureId::new(2358),
    PictureId::new(2360),
]);
const TECH_HISTORY_PICTURES: TechnologyTable<PictureId> = TechnologyTable::from_array([
    PictureId::new(2372),
    PictureId::new(2373),
    PictureId::new(2374),
    PictureId::new(2375),
    PictureId::new(2376),
    PictureId::new(2377),
    PictureId::new(2378),
    PictureId::new(2379),
    PictureId::new(2380),
    PictureId::new(2381),
    PictureId::new(2382),
    PictureId::new(2383),
    PictureId::new(2384),
    PictureId::new(2385),
    PictureId::new(2386),
    PictureId::new(2387),
    PictureId::new(2388),
    PictureId::new(2389),
    PictureId::new(2390),
    PictureId::new(2391),
    PictureId::new(2392),
    PictureId::new(2393),
    PictureId::new(2394),
    PictureId::new(2395),
    PictureId::new(2396),
    PictureId::new(2397),
    PictureId::new(2398),
    PictureId::new(2399),
    PictureId::new(2400),
]);
const TECH_ADVANCE_PICTURES: TechnologyTable<PictureId> = TechnologyTable::from_array([
    PictureId::new(2199),
    PictureId::new(2200),
    PictureId::new(2202),
    PictureId::new(2201),
    PictureId::new(2206),
    PictureId::new(2204),
    PictureId::new(2205),
    PictureId::new(2208),
    PictureId::new(2209),
    PictureId::new(2203),
    PictureId::new(2207),
    PictureId::new(2215),
    PictureId::new(2211),
    PictureId::new(2218),
    PictureId::new(2221),
    PictureId::new(2210),
    PictureId::new(2216),
    PictureId::new(2212),
    PictureId::new(2213),
    PictureId::new(2220),
    PictureId::new(2214),
    PictureId::new(2217),
    PictureId::new(2225),
    PictureId::new(2219),
    PictureId::new(2222),
    PictureId::new(2227),
    PictureId::new(2223),
    PictureId::new(2224),
    PictureId::new(2226),
]);
const TECH_HISTORY_TEXT: TechnologyTable<u16> = TechnologyTable::from_array([
    2300, 2301, 2302, 2303, 2304, 2305, 2306, 2307, 2308, 2309, 2310, 2311, 2312, 2313, 2314, 2315,
    2316, 2317, 2318, 2319, 2320, 2321, 2322, 2323, 2324, 2325, 2326, 2327, 2328,
]);

const ARMORY_ROW_IDLE: MilitaryUnitTable<PictureId> = MilitaryUnitTable::from_array([
    PictureId::new(7520),
    PictureId::new(7522),
    PictureId::new(7524),
    PictureId::new(7526),
    PictureId::new(7528),
    PictureId::new(7530),
    PictureId::new(7532),
    PictureId::new(7534),
    PictureId::new(7536),
    PictureId::new(7538),
    PictureId::new(7540),
    PictureId::new(7542),
    PictureId::new(7544),
    PictureId::new(7546),
    PictureId::new(7548),
    PictureId::new(7550),
    PictureId::new(7552),
    PictureId::new(7554),
    PictureId::new(7556),
    PictureId::new(7558),
    PictureId::new(7560),
    PictureId::new(7562),
    PictureId::new(7564),
    PictureId::new(7566),
    PictureId::new(7536),
    PictureId::new(7552),
    PictureId::new(7568),
    PictureId::new(7574),
    PictureId::new(7576),
    PictureId::new(7578),
]);
const ARMORY_ROW_SELECTED: MilitaryUnitTable<PictureId> = MilitaryUnitTable::from_array([
    PictureId::new(7521),
    PictureId::new(7523),
    PictureId::new(7525),
    PictureId::new(7527),
    PictureId::new(7529),
    PictureId::new(7531),
    PictureId::new(7533),
    PictureId::new(7535),
    PictureId::new(7537),
    PictureId::new(7539),
    PictureId::new(7541),
    PictureId::new(7543),
    PictureId::new(7545),
    PictureId::new(7547),
    PictureId::new(7549),
    PictureId::new(7551),
    PictureId::new(7553),
    PictureId::new(7555),
    PictureId::new(7557),
    PictureId::new(7559),
    PictureId::new(7561),
    PictureId::new(7563),
    PictureId::new(7565),
    PictureId::new(7567),
    PictureId::new(7537),
    PictureId::new(7553),
    PictureId::new(7569),
    PictureId::new(7575),
    PictureId::new(7577),
    PictureId::new(7579),
]);
const ARMORY_PLACARDS: MilitaryUnitTable<PictureId> = MilitaryUnitTable::from_array([
    PictureId::new(7580),
    PictureId::new(7581),
    PictureId::new(7582),
    PictureId::new(7583),
    PictureId::new(7584),
    PictureId::new(7585),
    PictureId::new(7586),
    PictureId::new(7587),
    PictureId::new(7588),
    PictureId::new(7589),
    PictureId::new(7590),
    PictureId::new(7591),
    PictureId::new(7592),
    PictureId::new(7593),
    PictureId::new(7594),
    PictureId::new(7595),
    PictureId::new(7596),
    PictureId::new(7597),
    PictureId::new(7598),
    PictureId::new(7599),
    PictureId::new(7600),
    PictureId::new(7601),
    PictureId::new(7602),
    PictureId::new(7603),
    PictureId::new(7604),
    PictureId::new(7605),
    PictureId::new(7606),
    PictureId::new(7607),
    PictureId::new(7608),
    PictureId::new(7609),
]);
const ARMY_TOOLBAR: MilitaryUnitTable<PictureId> = MilitaryUnitTable::from_array([
    PictureId::new(1220),
    PictureId::new(1221),
    PictureId::new(1222),
    PictureId::new(1223),
    PictureId::new(1224),
    PictureId::new(1225),
    PictureId::new(1226),
    PictureId::new(1227),
    PictureId::new(1228),
    PictureId::new(1229),
    PictureId::new(1230),
    PictureId::new(1231),
    PictureId::new(1232),
    PictureId::new(1233),
    PictureId::new(1234),
    PictureId::new(1235),
    PictureId::new(1236),
    PictureId::new(1237),
    PictureId::new(1238),
    PictureId::new(1239),
    PictureId::new(1240),
    PictureId::new(1241),
    PictureId::new(1242),
    PictureId::new(1243),
    PictureId::new(1244),
    PictureId::new(1245),
    PictureId::new(1246),
    PictureId::new(1247),
    PictureId::new(1248),
    PictureId::new(1249),
]);
const ARMY_TOOLBAR_EMPTY: MilitaryUnitTable<PictureId> = MilitaryUnitTable::from_array([
    PictureId::new(1250),
    PictureId::new(1251),
    PictureId::new(1252),
    PictureId::new(1253),
    PictureId::new(1254),
    PictureId::new(1255),
    PictureId::new(1256),
    PictureId::new(1257),
    PictureId::new(1258),
    PictureId::new(1259),
    PictureId::new(1260),
    PictureId::new(1261),
    PictureId::new(1262),
    PictureId::new(1263),
    PictureId::new(1264),
    PictureId::new(1265),
    PictureId::new(1266),
    PictureId::new(1267),
    PictureId::new(1268),
    PictureId::new(1269),
    PictureId::new(1270),
    PictureId::new(1271),
    PictureId::new(1272),
    PictureId::new(1273),
    PictureId::new(1274),
    PictureId::new(1275),
    PictureId::new(1276),
    PictureId::new(1277),
    PictureId::new(1278),
    PictureId::new(1279),
]);

const CITY_BUILDING_COLUMN: ProductionTable<i16> =
    ProductionTable::from_array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

const OCEAN_TRANSPORT_X: MajorNationTable<i32> =
    MajorNationTable::from_array([352, 368, 384, 400, 416, 432, 448]);
const OCEAN_TRANSPORT_NEUTRAL_X: i32 = 464;
const OCEAN_CITY_X: MajorNationTable<i32> =
    MajorNationTable::from_array([1024, 1056, 1088, 1120, 1152, 1184, 1216]);
const OCEAN_CITY_NEUTRAL_X: i32 = 1248;
const OCEAN_PORT_X: MajorNationTable<i32> =
    MajorNationTable::from_array([608, 624, 640, 656, 672, 688, 704]);
const OCEAN_PORT_NEUTRAL_X: i32 = 720;

const OCEAN_MAJOR_FILL: MajorNationTable<u8> =
    MajorNationTable::from_array([0xf3, 0x2a, 0x25, 0x1d, 0xf6, 0x8c, 0xbd]);
const OCEAN_MINOR_FILL: MinorNationTable<u8> = MinorNationTable::from_array([
    0x0a, 0x0b, 0x0d, 0x29, 0xde, 0xdf, 0xfa, 0x2c, 0x31, 0x33, 0x41, 0x48, 0xd0, 0xcd, 0xce, 0xcf,
]);
const OCEAN_UNOWNED_FILL: u8 = 0x1a;
const OCEAN_MAJOR_BORDER: MajorNationTable<u8> =
    MajorNationTable::from_array([0x15, 0x2d, 0x1e, 0x1c, 0x30, 0xae, 0xca]);
const OCEAN_MINOR_BORDER: MinorNationTable<u8> = MinorNationTable::from_array([
    0x7d, 0x7d, 0x7d, 0x7d, 0xe2, 0xe2, 0xe2, 0xe2, 0x51, 0x51, 0x51, 0x51, 0xf0, 0xf0, 0xf0, 0xf0,
]);
const OCEAN_UNOWNED_BORDER: u8 = 0xc6;

const DEAL_BOOK_FLAG_MAJOR_X: MajorNationTable<f32> =
    MajorNationTable::from_array([0.0, 32.0, 64.0, 96.0, 128.0, 160.0, 192.0]);
const DEAL_BOOK_FLAG_MINOR_X: MinorNationTable<f32> = MinorNationTable::from_array([
    224.0, 256.0, 288.0, 320.0, 352.0, 384.0, 416.0, 448.0, 480.0, 512.0, 544.0, 576.0, 608.0,
    640.0, 672.0, 704.0,
]);
const DEAL_BOOK_FLAG_WIDTH: f32 = 32.0;
const DEAL_BOOK_FLAG_HEIGHT: f32 = 24.0;

const SHIPYARD_QUEUE_X: ShipTypeTable<f32> = ShipTypeTable::from_array([
    0.0, 0.0, 80.0, 160.0, 240.0, 320.0, 400.0, 480.0, 560.0, 640.0, 720.0, 800.0, 880.0, 960.0,
]);
const SHIPYARD_QUEUE_WIDTH: f32 = 80.0;
const SHIPYARD_QUEUE_HEIGHT: f32 = 45.0;

const RESOURCE_NAME_INDEX: ResourceTable<i16> = ResourceTable::from_array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
]);
const CITY_BUILDING_NAME_INDEX: ProductionTable<i16> =
    ProductionTable::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
const SHIP_NAME_INDEX: ShipTypeTable<i16> =
    ShipTypeTable::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
const SHIP_DESCRIPTION_INDEX: ShipTypeTable<i16> =
    ShipTypeTable::from_array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
const NEWS_NATION_NAME_MAJOR: MajorNationTable<i16> =
    MajorNationTable::from_array([1, 2, 3, 4, 5, 6, 7]);
const NEWS_NATION_NAME_MINOR: MinorNationTable<i16> =
    MinorNationTable::from_array([8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]);
const CIVILIAN_NAME_INDEX: CivilianUnitTable<i16> =
    CivilianUnitTable::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
const CIVILIAN_DESCRIPTION_INDEX: CivilianUnitTable<i16> =
    CivilianUnitTable::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
const MILITARY_UNIT_NAME_INDEX: MilitaryUnitTable<i16> = MilitaryUnitTable::from_array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30,
]);
const MILITARY_UNIT_DESCRIPTION_INDEX: MilitaryUnitTable<i16> = MilitaryUnitTable::from_array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30,
]);
const TECHNOLOGY_NAME_INDEX: TechnologyTable<i16> = TechnologyTable::from_array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29,
]);
const TECHNOLOGY_BENEFIT_INDEX: TechnologyTable<i16> = TechnologyTable::from_array([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28,
]);

const RESOURCE_SPECIALTY_WIDTH: f32 = 20.0;
const RESOURCE_SPECIALTY_HEIGHT: f32 = 24.0;
const RESOURCE_SPECIALTY_X: ResourceTable<f32> = ResourceTable::from_array([
    0.0, 20.0, 40.0, 60.0, 80.0, 100.0, 120.0, 140.0, 160.0, 180.0, 200.0, 220.0, 240.0, 260.0,
    280.0, 300.0, 320.0, 340.0, 360.0, 380.0, 400.0, 420.0, 440.0,
]);
const RESOURCE_OVERLAY_WIDTH: f32 = 38.0;
const RESOURCE_OVERLAY_HEIGHT: f32 = 26.0;
const RESOURCE_OVERLAY_BASE_X: ResourceTable<i16> = ResourceTable::from_array([
    0, 798, 114, 228, 342, -114, 684, -114, -114, -114, -114, -114, -114, -114, -114, -114, -114,
    0, 0, -114, 798, 570, 456,
]);

/// Fleet sprite sheet chosen from researched naval-construction techs.
#[derive(Clone, Copy, Debug, Enum, Eq, Hash, PartialEq)]
pub enum FleetVisualEra {
    Early,
    Ironclad,
    Modern,
}

impl FleetVisualEra {
    pub fn from_research(advanced_iron_working: bool, marine_engineering: bool) -> Self {
        if marine_engineering {
            Self::Modern
        } else if advanced_iron_working {
            Self::Ironclad
        } else {
            Self::Early
        }
    }
}

/// Owner strip in the army/civilian flag atlas. Minors and missing owners share Neutral.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OwnerBadge {
    Major(MajorNationId),
    Neutral,
}

impl OwnerBadge {
    pub fn from_tile_owner(owner: Option<TileContext>) -> Self {
        match owner
            .and_then(TileContext::nation)
            .and_then(NationId::as_major)
        {
            Some(id) => Self::Major(id),
            None => Self::Neutral,
        }
    }
}

/// Displayed army-count badge on a province capital.
#[derive(Clone, Copy, Debug, Enum, Eq, Hash, PartialEq)]
pub enum ArmyCountBucket {
    Empty,
    Few,
    Several,
    Many,
}

impl ArmyCountBucket {
    pub fn from_displayed_count(displayed: u16) -> Self {
        match displayed {
            0 => Self::Empty,
            1..=5 => Self::Few,
            6..=10 => Self::Several,
            _ => Self::Many,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CivilianPosePicture {
    Idle,
    Selected,
    Working,
    Animated,
}

/// Dynamic picture families keyed by gameplay identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetailPicture {
    DialogCoat(MajorNationId),
    SetupCoat(MajorNationId),
    FleetAtlas {
        nation: MajorNationId,
        era: FleetVisualEra,
    },
    ArmyCount(ArmyCountBucket),
    OwnerFlagStrip,
    SetupFlagStrip,
    Civilian {
        kind: CivilianUnitKind,
        pose: CivilianPosePicture,
    },
    CivilianAnimation {
        kind: CivilianUnitKind,
        frame: u8,
    },
    ResourceIcon(ResourceKind),
    OceanFleet {
        nation: MajorNationId,
        era: FleetVisualEra,
    },
    ShipPortrait(ShipType),
    DealBookFlagStrip,
    ShipyardQueueStrip,
    CityScene {
        slot: CityFacilitySlot,
        level: i32,
        expanding: bool,
    },
    CityHitMask {
        slot: CityFacilitySlot,
        level: i32,
    },
    CityConstruction {
        slot: CityFacilitySlot,
        stage: u8,
    },
    PowerPlant {
        upgrade_queued: bool,
    },
    CivilianPortrait(CivilianUnitKind),
    ResourceSpecialtyStrip,
    TechnologyStore {
        technology: Technology,
        selected: bool,
    },
    TechnologyHistory(Technology),
    TechnologyAdvance(Technology),
    ArmoryRow {
        unit: MilitaryUnitKind,
        selected: bool,
    },
    ArmoryPlacard(MilitaryUnitKind),
    ArmyToolbar {
        kind: MilitaryUnitKind,
        empty: bool,
    },
    NavyClass(ShipType),
}

pub fn retail_picture(picture: RetailPicture) -> PictureId {
    match picture {
        RetailPicture::DialogCoat(nation) => DIALOG_COATS[nation],
        RetailPicture::SetupCoat(nation) => SETUP_COATS[nation],
        RetailPicture::FleetAtlas { nation, era } => FLEET_ATLAS[era][nation],
        RetailPicture::ArmyCount(bucket) => ARMY_COUNT_PICTURES[bucket],
        RetailPicture::OwnerFlagStrip => OWNER_FLAG_STRIP,
        RetailPicture::SetupFlagStrip => SETUP_FLAG_STRIP,
        RetailPicture::Civilian { kind, pose } => match pose {
            CivilianPosePicture::Idle => CIVILIAN_IDLE[kind],
            CivilianPosePicture::Selected => CIVILIAN_SELECTED[kind],
            CivilianPosePicture::Working => CIVILIAN_WORKING[kind],
            CivilianPosePicture::Animated => CIVILIAN_ANIMATED[kind],
        },
        RetailPicture::CivilianAnimation { kind, frame } => {
            PictureId::new(CIVILIAN_ANIMATED[kind].get() + i16::from(frame))
        }
        RetailPicture::ResourceIcon(resource) => RESOURCE_ICONS[resource],
        RetailPicture::OceanFleet { nation, era } => OCEAN_FLEET[era][nation],
        RetailPicture::ShipPortrait(ship) => SHIP_PORTRAITS[ship],
        RetailPicture::DealBookFlagStrip => DEAL_BOOK_FLAG_STRIP,
        RetailPicture::ShipyardQueueStrip => SHIPYARD_QUEUE_STRIP,
        RetailPicture::CityScene {
            slot,
            level,
            expanding,
        } => city_scene_picture(slot, level, expanding),
        RetailPicture::CityHitMask { slot, level } => {
            PictureId::new(7100 + (level as i16) * 16 + CITY_BUILDING_COLUMN[slot])
        }
        RetailPicture::CityConstruction { slot, stage } => {
            PictureId::new(9250 + CITY_BUILDING_COLUMN[slot] * 5 + i16::from(stage))
        }
        RetailPicture::PowerPlant { upgrade_queued } => {
            PictureId::new(if upgrade_queued { 7011 } else { 7027 })
        }
        RetailPicture::CivilianPortrait(kind) => CIVILIAN_PORTRAITS[kind],
        RetailPicture::ResourceSpecialtyStrip => RESOURCE_SPECIALTY_STRIP,
        RetailPicture::TechnologyStore {
            technology,
            selected,
        } => {
            if selected {
                TECH_STORE_ACTIVE[technology]
            } else {
                TECH_STORE_IDLE[technology]
            }
        }
        RetailPicture::TechnologyHistory(technology) => TECH_HISTORY_PICTURES[technology],
        RetailPicture::TechnologyAdvance(technology) => TECH_ADVANCE_PICTURES[technology],
        RetailPicture::ArmoryRow { unit, selected } => {
            if selected {
                ARMORY_ROW_SELECTED[unit]
            } else {
                ARMORY_ROW_IDLE[unit]
            }
        }
        RetailPicture::ArmoryPlacard(unit) => ARMORY_PLACARDS[unit],
        RetailPicture::ArmyToolbar { kind, empty } => {
            if empty {
                ARMY_TOOLBAR_EMPTY[kind]
            } else {
                ARMY_TOOLBAR[kind]
            }
        }
        RetailPicture::NavyClass(ship) => NAVY_CLASS_PICTURES[ship],
    }
}

fn city_scene_picture(slot: CityFacilitySlot, level: i32, expanding: bool) -> PictureId {
    let column = CITY_BUILDING_COLUMN[slot];
    let expanding_sheet = expanding && level != 0 && column <= 5 && slot.is_capacity_center();
    let base = if expanding_sheet { 7300 } else { 7000 };
    PictureId::new(base + (level as i16) * 16 + column)
}

/// One cell inside a packed retail atlas.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RetailAtlasCell {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

pub fn owner_flag_source_x(badge: OwnerBadge) -> i32 {
    match badge {
        OwnerBadge::Major(nation) => OWNER_FLAG_X[nation],
        OwnerBadge::Neutral => NEUTRAL_OWNER_FLAG_X,
    }
}

pub fn owner_flag_cell_width() -> i32 {
    OWNER_FLAG_CELL_WIDTH
}

pub fn setup_flag_cell(nation: MajorNationId) -> RetailAtlasCell {
    RetailAtlasCell {
        x: SETUP_FLAG_X[nation],
        y: 0.0,
        width: SETUP_FLAG_WIDTH,
        height: SETUP_FLAG_HEIGHT,
    }
}

pub fn deal_book_flag_cell(nation: NationId) -> RetailAtlasCell {
    let x = match nation {
        NationId::Major(id) => DEAL_BOOK_FLAG_MAJOR_X[id],
        NationId::Minor(id) => DEAL_BOOK_FLAG_MINOR_X[id],
    };
    RetailAtlasCell {
        x,
        y: 0.0,
        width: DEAL_BOOK_FLAG_WIDTH,
        height: DEAL_BOOK_FLAG_HEIGHT,
    }
}

pub fn shipyard_queue_cell(ship: ShipType) -> RetailAtlasCell {
    RetailAtlasCell {
        x: SHIPYARD_QUEUE_X[ship],
        y: 0.0,
        width: SHIPYARD_QUEUE_WIDTH,
        height: SHIPYARD_QUEUE_HEIGHT,
    }
}

pub fn resource_specialty_icon_cell(resource: ResourceKind) -> RetailAtlasCell {
    RetailAtlasCell {
        x: RESOURCE_SPECIALTY_X[resource],
        y: 0.0,
        width: RESOURCE_SPECIALTY_WIDTH,
        height: RESOURCE_SPECIALTY_HEIGHT,
    }
}

pub fn resource_overlay_cell(resource: ResourceKind, level: u8) -> Option<RetailAtlasCell> {
    if level == 0 {
        return None;
    }
    let base = RESOURCE_OVERLAY_BASE_X[resource];
    if base < 0 {
        return None;
    }
    Some(RetailAtlasCell {
        x: f32::from(base) - RESOURCE_OVERLAY_WIDTH + f32::from(level) * RESOURCE_OVERLAY_WIDTH,
        y: 0.0,
        width: RESOURCE_OVERLAY_WIDTH,
        height: RESOURCE_OVERLAY_HEIGHT,
    })
}

pub fn technology_history_text_id(technology: Technology) -> u16 {
    TECH_HISTORY_TEXT[technology]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OceanImprovementKind {
    Transport,
    City,
    Port,
}

impl OceanImprovementKind {
    pub fn from_tile_flags(flags: TileFlags) -> Option<Self> {
        if flags.contains(TileFlags::BASE_TRANSPORT) {
            Some(Self::Transport)
        } else if flags.contains(TileFlags::CITY_MARKER) {
            Some(Self::City)
        } else if flags.contains(TileFlags::PORT) {
            Some(Self::Port)
        } else {
            None
        }
    }
}

pub fn ocean_improvement_source_x(kind: OceanImprovementKind, badge: OwnerBadge) -> i32 {
    match (kind, badge) {
        (OceanImprovementKind::Transport, OwnerBadge::Major(nation)) => OCEAN_TRANSPORT_X[nation],
        (OceanImprovementKind::Transport, OwnerBadge::Neutral) => OCEAN_TRANSPORT_NEUTRAL_X,
        (OceanImprovementKind::City, OwnerBadge::Major(nation)) => OCEAN_CITY_X[nation],
        (OceanImprovementKind::City, OwnerBadge::Neutral) => OCEAN_CITY_NEUTRAL_X,
        (OceanImprovementKind::Port, OwnerBadge::Major(nation)) => OCEAN_PORT_X[nation],
        (OceanImprovementKind::Port, OwnerBadge::Neutral) => OCEAN_PORT_NEUTRAL_X,
    }
}

pub fn ocean_fill_palette(owner: Option<TileContext>) -> u8 {
    match owner.and_then(TileContext::nation) {
        Some(NationId::Major(id)) => OCEAN_MAJOR_FILL[id],
        Some(NationId::Minor(id)) => OCEAN_MINOR_FILL[id],
        None => OCEAN_UNOWNED_FILL,
    }
}

pub fn ocean_border_palette(owner: Option<TileContext>) -> u8 {
    match owner.and_then(TileContext::nation) {
        Some(NationId::Major(id)) => OCEAN_MAJOR_BORDER[id],
        Some(NationId::Minor(id)) => OCEAN_MINOR_BORDER[id],
        None => OCEAN_UNOWNED_BORDER,
    }
}

/// Direct `(group, index)` pair for `RetailAssets::string`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetailStringId {
    pub group: i16,
    pub index: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetailString {
    ResourceName(ResourceKind),
    ShipName(ShipType),
    ShipDescription(ShipType),
    CityBuildingName(CityFacilitySlot),
    NewsNationName(NationId),
    CivilianName(CivilianUnitKind),
    CivilianDescription(CivilianUnitKind),
    MilitaryUnitName(MilitaryUnitKind),
    MilitaryUnitDescription(MilitaryUnitKind),
    TechnologyName(Technology),
    TechnologyBenefit(Technology),
}

pub fn retail_string(string: RetailString) -> RetailStringId {
    match string {
        RetailString::ResourceName(resource) => RetailStringId {
            group: 0x2711,
            index: RESOURCE_NAME_INDEX[resource],
        },
        RetailString::ShipName(ship) => RetailStringId {
            group: 0x2716,
            index: SHIP_NAME_INDEX[ship],
        },
        RetailString::ShipDescription(ship) => RetailStringId {
            group: 0x2752,
            index: SHIP_DESCRIPTION_INDEX[ship],
        },
        RetailString::CityBuildingName(slot) => RetailStringId {
            group: 0x2719,
            index: CITY_BUILDING_NAME_INDEX[slot],
        },
        RetailString::NewsNationName(nation) => RetailStringId {
            group: 0x2711,
            index: match nation {
                NationId::Major(id) => NEWS_NATION_NAME_MAJOR[id],
                NationId::Minor(id) => NEWS_NATION_NAME_MINOR[id],
            },
        },
        RetailString::CivilianName(kind) => RetailStringId {
            group: 0x2718,
            index: CIVILIAN_NAME_INDEX[kind],
        },
        RetailString::CivilianDescription(kind) => RetailStringId {
            group: 0x2751,
            index: CIVILIAN_DESCRIPTION_INDEX[kind],
        },
        RetailString::MilitaryUnitName(kind) => RetailStringId {
            group: 0x2717,
            index: MILITARY_UNIT_NAME_INDEX[kind],
        },
        RetailString::MilitaryUnitDescription(kind) => RetailStringId {
            group: 0x2750,
            index: MILITARY_UNIT_DESCRIPTION_INDEX[kind],
        },
        RetailString::TechnologyName(technology) => RetailStringId {
            group: 0x2712,
            index: TECHNOLOGY_NAME_INDEX[technology],
        },
        RetailString::TechnologyBenefit(technology) => RetailStringId {
            group: 0x274e,
            index: TECHNOLOGY_BENEFIT_INDEX[technology],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_and_setup_coats_are_distinct_families() {
        assert_eq!(
            retail_picture(RetailPicture::DialogCoat(MajorNationId::new(0))),
            PictureId::new(9500)
        );
        assert_eq!(
            retail_picture(RetailPicture::DialogCoat(MajorNationId::new(6))),
            PictureId::new(9506)
        );
        assert_eq!(
            retail_picture(RetailPicture::SetupCoat(MajorNationId::new(0))),
            PictureId::new(0x11c6)
        );
        assert_eq!(
            retail_picture(RetailPicture::SetupCoat(MajorNationId::new(6))),
            PictureId::new(0x11cc)
        );
    }

    #[test]
    fn fleet_atlas_is_a_nation_by_era_table() {
        let nation = MajorNationId::new(3);
        assert_eq!(
            retail_picture(RetailPicture::FleetAtlas {
                nation,
                era: FleetVisualEra::Early,
            }),
            PictureId::new(1383)
        );
        assert_eq!(
            retail_picture(RetailPicture::FleetAtlas {
                nation,
                era: FleetVisualEra::Modern,
            }),
            PictureId::new(1397)
        );
    }

    #[test]
    fn owner_badges_do_not_use_a_flat_slot() {
        assert_eq!(
            owner_flag_source_x(OwnerBadge::from_tile_owner(Some(TileContext::from(
                MajorNationId::new(3)
            )))),
            27
        );
        assert_eq!(
            owner_flag_source_x(OwnerBadge::from_tile_owner(Some(TileContext::from(
                imperialism_core::MinorNationId::new(1)
            )))),
            NEUTRAL_OWNER_FLAG_X
        );
        assert_eq!(
            owner_flag_source_x(OwnerBadge::from_tile_owner(None)),
            NEUTRAL_OWNER_FLAG_X
        );
    }

    #[test]
    fn civilian_idle_pictures_follow_kind_not_a_class_offset() {
        assert_eq!(
            retail_picture(RetailPicture::Civilian {
                kind: CivilianUnitKind::Engineer,
                pose: CivilianPosePicture::Idle,
            }),
            PictureId::new(400)
        );
        assert_eq!(
            retail_picture(RetailPicture::Civilian {
                kind: CivilianUnitKind::Farmer,
                pose: CivilianPosePicture::Idle,
            }),
            PictureId::new(401)
        );
        assert_eq!(
            retail_picture(RetailPicture::CivilianAnimation {
                kind: CivilianUnitKind::Engineer,
                frame: 2,
            }),
            PictureId::new(14_023)
        );
    }

    #[test]
    fn resource_icons_are_a_kind_table() {
        assert_eq!(
            retail_picture(RetailPicture::ResourceIcon(ResourceKind::Cotton)),
            PictureId::new(700)
        );
        assert_eq!(
            retail_picture(RetailPicture::ResourceIcon(ResourceKind::Gold)),
            PictureId::new(722)
        );
    }

    #[test]
    fn ocean_fleet_and_improvements_are_nation_tables() {
        assert_eq!(
            retail_picture(RetailPicture::OceanFleet {
                nation: MajorNationId::new(3),
                era: FleetVisualEra::Modern,
            }),
            PictureId::new(1418)
        );
        assert_eq!(
            ocean_improvement_source_x(
                OceanImprovementKind::Port,
                OwnerBadge::Major(MajorNationId::new(1))
            ),
            624
        );
        assert_eq!(
            ocean_fill_palette(Some(TileContext::from(MajorNationId::new(3)))),
            0x1d
        );
    }

    #[test]
    fn city_and_ship_pictures_do_not_use_caller_arithmetic() {
        assert_eq!(
            retail_picture(RetailPicture::CityHitMask {
                slot: CityFacilitySlot::TextileMill,
                level: 1,
            }),
            PictureId::new(7116)
        );
        assert_eq!(
            retail_picture(RetailPicture::CityScene {
                slot: CityFacilitySlot::TextileMill,
                level: 0,
                expanding: true,
            }),
            PictureId::new(7000)
        );
        assert_eq!(
            retail_picture(RetailPicture::CityScene {
                slot: CityFacilitySlot::TextileMill,
                level: 1,
                expanding: true,
            }),
            PictureId::new(7316)
        );
        assert_eq!(
            retail_picture(RetailPicture::CityConstruction {
                slot: CityFacilitySlot::TextileMill,
                stage: 2,
            }),
            PictureId::new(9252)
        );
        assert_eq!(
            retail_picture(RetailPicture::PowerPlant {
                upgrade_queued: true,
            }),
            PictureId::new(7011)
        );
        assert_eq!(
            retail_picture(RetailPicture::ShipPortrait(ShipType::Frigate)),
            PictureId::new(9837)
        );
        assert_eq!(shipyard_queue_cell(ShipType::Frigate).x, 160.0);
        assert_eq!(
            retail_picture(RetailPicture::ArmoryRow {
                unit: MilitaryUnitKind::CombatEngineers,
                selected: false,
            }),
            PictureId::new(7552)
        );
        assert_eq!(
            retail_picture(RetailPicture::ArmoryRow {
                unit: MilitaryUnitKind::Saboteurs,
                selected: false,
            }),
            PictureId::new(7568)
        );
        assert_eq!(
            retail_picture(RetailPicture::TechnologyStore {
                technology: Technology::CottonGin,
                selected: false,
            }),
            PictureId::new(2309)
        );
        assert_eq!(
            retail_string(RetailString::CivilianName(CivilianUnitKind::Engineer)),
            RetailStringId {
                group: 0x2718,
                index: 5,
            }
        );
        assert_eq!(resource_specialty_icon_cell(ResourceKind::Cotton).x, 0.0);
        assert_eq!(
            resource_overlay_cell(ResourceKind::Iron, 1).map(|cell| cell.x),
            Some(228.0)
        );
        assert_eq!(
            retail_string(RetailString::ResourceName(ResourceKind::Cotton)),
            RetailStringId {
                group: 0x2711,
                index: 1,
            }
        );
    }
}
