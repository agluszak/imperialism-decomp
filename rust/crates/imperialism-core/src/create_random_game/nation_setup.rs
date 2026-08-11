use super::*;

pub(super) fn bootstrap_nations(
    human_nation: MajorNationId,
    difficulty: Difficulty,
    foreign_ministers: MajorNationTable<ForeignMinisterPersonality>,
) -> Nations {
    Nations::new(
        MajorNationTable::from_fn(|nation| {
            major_nation(
                difficulty,
                nation == human_nation,
                foreign_ministers[nation],
            )
        }),
        MinorNationTable::from_fn(|nation| Some(minor_nation(nation))),
    )
}
pub(super) fn major_nation(
    difficulty: Difficulty,
    human: bool,
    foreign_minister: ForeignMinisterPersonality,
) -> MajorNation {
    let treasury = if human {
        STARTING_TREASURY_BY_DIFFICULTY[difficulty]
    } else {
        // IAutoGreatPower forces treasury to 10000 after IGreatPower.
        10_000
    };
    // AI majors always use the Normal preset row for their scenario city.
    let preset_difficulty = if human {
        difficulty
    } else {
        Difficulty::Normal
    };
    MajorNation::for_random_start(
        treasury,
        human,
        foreign_minister,
        scenario_city(preset_difficulty, human),
    )
}
/// `TMapMgr::ChooseNationSetupProfilesForOpenSlots` followed by the foreign-minister
/// column of `g_aDefaultNationSetupPolicyProfiles`.
pub(super) fn choose_foreign_ministers(
    map: &GeneratedMap,
    human_nation: MajorNationId,
) -> MajorNationTable<ForeignMinisterPersonality> {
    const PROFILE_ORDER: [usize; 7] = [1, 5, 4, 6, 2, 3, 3];
    const PREFERRED_ISOLATION_BY_PROFILE: [[u8; 3]; 7] = [
        [0, 1, 2],
        [2, 1, 0],
        [0, 1, 2],
        [0, 1, 2],
        [1, 2, 0],
        [1, 2, 0],
        [0, 1, 2],
    ];
    const FOREIGN_MINISTER_BY_PROFILE: [ForeignMinisterPersonality; 7] = [
        ForeignMinisterPersonality::Diplomat,
        ForeignMinisterPersonality::Ted,
        ForeignMinisterPersonality::Bill,
        ForeignMinisterPersonality::Diplomat,
        ForeignMinisterPersonality::Textile,
        ForeignMinisterPersonality::Trader,
        ForeignMinisterPersonality::Bill,
    ];

    let mut region_class_by_nation = [None; NATION_COUNT];
    for province in map.provinces() {
        region_class_by_nation[usize::from(province.owner.get())] = Some(province.terrain);
    }

    let major_count = usize::from(MajorNationId::COUNT);
    let isolation_by_major = MajorNationTable::from_fn(|nation| {
        let class = region_class_by_nation[usize::from(nation.get())]
            .expect("accepted random maps assign a region class to every major nation");
        if (0..major_count).any(|other| {
            other != usize::from(nation.get()) && region_class_by_nation[other] == Some(class)
        }) {
            0
        } else if (major_count..NATION_COUNT)
            .any(|other| region_class_by_nation[other] == Some(class))
        {
            1
        } else {
            2
        }
    });

    let mut profile_by_major = MajorNationTable::from_fn(|_| None);
    for &profile in PROFILE_ORDER.iter().take(major_count - 1) {
        let nation = PREFERRED_ISOLATION_BY_PROFILE[profile]
            .iter()
            .find_map(|&isolation| {
                (0..major_count).find_map(|slot| {
                    let nation = MajorNationId::new(slot as u8);
                    (nation != human_nation
                        && profile_by_major[nation].is_none()
                        && isolation_by_major[nation] == isolation)
                        .then_some(nation)
                })
            })
            .expect("each generated-map AI profile has an eligible open nation slot");
        profile_by_major[nation] = Some(profile);
    }

    MajorNationTable::from_fn(|nation| {
        if nation == human_nation {
            ForeignMinisterPersonality::Base
        } else {
            let profile =
                profile_by_major[nation].expect("every AI nation receives a setup profile");
            FOREIGN_MINISTER_BY_PROFILE[profile]
        }
    })
}
pub(super) fn minor_nation(nation: MinorNationId) -> MinorNation {
    let first_member = MinorNationId::FIRST + (nation.get() - MinorNationId::FIRST) / 4 * 4;
    MinorNation {
        common: NationCommonState::from_parts(
            String::new(),
            CountryStatus::Independent,
            Vec::new(),
            5_000,
            None,
            NationTable::default(),
        ),
        consortium_members: std::array::from_fn(|offset| {
            MinorNationId::new(first_member + offset as u8)
        }),
        trade: MinorTradeState {
            thresholds: MINOR_TRADE_THRESHOLDS[nation.table_index()],
            ..MinorTradeState::default()
        },
    }
}
pub(super) const MINOR_TRADE_THRESHOLDS: [MinorTradeThresholds; MINOR_NATION_COUNT] = [
    minor_trade_thresholds(0x44c, 0x23a, 0xc3, 0x5a, 0x69, 0x8a, 0x90),
    minor_trade_thresholds(0x47e, 0x249, 0xaf, 0x52, 0x75, 0x72, 0x84),
    minor_trade_thresholds(0x4b0, 0x258, 0x9b, 0x4a, 0x81, 0x7e, 0x78),
    minor_trade_thresholds(0x4e2, 0x267, 0x87, 0x42, 0x8d, 0x90, 0x6f),
    minor_trade_thresholds(0x514, 0x276, 0xbe, 0x58, 0x6c, 0x8d, 0x93),
    minor_trade_thresholds(0x546, 0x285, 0xaa, 0x50, 0x78, 0x69, 0x87),
    minor_trade_thresholds(0x578, 0x294, 0x96, 0x48, 0x84, 0x7b, 0x75),
    minor_trade_thresholds(0x5aa, 0x2a3, 0x82, 0x40, 0x90, 0x81, 0x72),
    minor_trade_thresholds(0x5dc, 0x2b2, 0xb9, 0x56, 0x6f, 0x93, 0x96),
    minor_trade_thresholds(0x60e, 0x2c1, 0xa5, 0x4e, 0x7b, 0x6c, 0x8a),
    minor_trade_thresholds(0x640, 0x2d0, 0x91, 0x46, 0x87, 0x78, 0x7e),
    minor_trade_thresholds(0x672, 0x2df, 0x7d, 0x3e, 0x93, 0x84, 0x69),
    minor_trade_thresholds(0x6a4, 0x2ee, 0xb4, 0x54, 0x72, 0x96, 0x8d),
    minor_trade_thresholds(0x6d6, 0x2fd, 0xa0, 0x4c, 0x7e, 0x6f, 0x81),
    minor_trade_thresholds(0x708, 0x302, 0x8c, 0x44, 0x8a, 0x7b, 0x75),
    minor_trade_thresholds(0x73a, 0x311, 0x78, 0x3c, 0x96, 0x87, 0x6c),
];
pub(super) const fn minor_trade_thresholds(
    primary_manufactured_price: i16,
    secondary_manufactured_price: i16,
    general_offer_price: i16,
    random_offer_price: i16,
    coal_offer_price: i16,
    iron_offer_price: i16,
    oil_offer_price: i16,
) -> MinorTradeThresholds {
    MinorTradeThresholds {
        primary_manufactured_price,
        secondary_manufactured_price,
        general_offer_price,
        random_offer_price,
        coal_offer_price,
        iron_offer_price,
        oil_offer_price,
    }
}
pub(super) fn initialize_minor_trade_state(
    world: &StrategicMap,
    tile_subtypes: &[i8],
    nations: &mut Nations,
) {
    for nation in (MinorNationId::FIRST..NationId::COUNT).map(MinorNationId::new) {
        let Some(minor) = nations.minors[nation].as_mut() else {
            continue;
        };
        let owner = TileOwnerTag::from_nation(nation.nation());
        let mut counts = ResourceTable::default();
        for (index, tile) in world.iter().enumerate() {
            if tile.owner_nation != Some(owner) || tile_subtypes[index] == 0xf {
                continue;
            }
            for resource in tile.edge_resources.into_iter().flatten() {
                counts[resource] += 1;
            }
        }
        minor.trade.current_supply = counts;
        minor.trade.current_supply[ResourceKind::Food] = 5;
        minor.trade.independent_resource_counts = counts;
    }
}
pub(super) fn scenario_city(difficulty: Difficulty, human: bool) -> CityState {
    // Intro (preset 0) uses SetPopulation(2, 3, 2); every other level uses (4, 2, 1).
    let labor = if difficulty == Difficulty::Introductory {
        LaborPool::new(2, 3, 2)
    } else {
        LaborPool::new(4, 2, 1)
    };
    let production = if human && difficulty < Difficulty::Normal {
        LOW_DIFFICULTY_HUMAN_PRODUCTION
    } else {
        SCENARIO_FORCED_PRODUCTION
    };
    CityState::for_random_start(
        CITY_STOCK_PRESET_BY_DIFFICULTY[difficulty],
        production,
        labor,
        human,
    )
}
