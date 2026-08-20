use crate::create_random_game::nation_setup::{major_nation, minor_nation};
use crate::*;
use enum_map::Enum;
use indexmap::IndexMap;

/// Semantic form of one command from a retail `Scenario/sN.scn` program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScenarioInstruction {
    Labor {
        nation: NationId,
        counts: [i16; 3],
    },
    Capacity {
        nation: MajorNationId,
        slot: i16,
        value: i16,
    },
    Warehouse {
        nation: MajorNationId,
        resource: i16,
        amount: i16,
    },
    Army {
        province: ProvinceId,
        unit: i16,
        count: i32,
    },
    Civilian {
        unit: i16,
        tile: TileId,
    },
    Ship {
        nation: MajorNationId,
        ship: i16,
        zone: i16,
        count: i32,
    },
    Transport {
        nation: MajorNationId,
        amount: i16,
    },
    Development {
        tile: TileId,
        level: u8,
    },
    Rail {
        tile: TileId,
    },
    Port {
        tile: TileId,
    },
    Technology {
        nation: MajorNationId,
        technology: i32,
    },
    Price {
        resource: i16,
        value: i16,
    },
    Embassy {
        first: NationId,
        second: NationId,
        level: i16,
    },
    Subsidy {
        owner: MajorNationId,
        target: NationId,
        level: i16,
    },
    Treaty {
        source: NationId,
        target: NationId,
        relationship: i32,
    },
    Year(i16),
    ProvinceOwner {
        province: ProvinceId,
        nation: NationId,
    },
    ZoneName {
        zone: i16,
        name: String,
    },
    CountryName {
        nation: NationId,
        name: String,
    },
    Standing {
        source: NationId,
        target: NationId,
        value: i16,
    },
    ProvinceName {
        province: ProvinceId,
        name: String,
    },
    Cash {
        nation: NationId,
        amount: i32,
    },
    Flag(i16),
    CapabilityTier {
        slot: i32,
        value: i32,
    },
    NeedTarget {
        nation: MajorNationId,
        resource: i32,
        value: i32,
    },
    ClearNeedTargets {
        nation: MajorNationId,
    },
    DecadeState {
        decade: i32,
        state: i32,
    },
}

/// Retail scenario inputs after file-format decoding and before gameplay construction.
#[derive(Clone, Debug)]
pub struct ScenarioGameInput {
    pub scenario: ScenarioMapId,
    pub map: MapMgr,
    pub instructions: Vec<ScenarioInstruction>,
}

/// Constructs a single-player scenario at the strategic-map boundary.
pub fn create_scenario_game(
    mut input: ScenarioGameInput,
    human: MajorNationId,
    difficulty: Difficulty,
    runtime_seed: u32,
) -> GameState {
    // Scenario province assignments run against the loaded map before nation objects are built.
    for instruction in &input.instructions {
        let ScenarioInstruction::ProvinceOwner { province, nation } = *instruction else {
            continue;
        };
        input.map.provinces[province].set_owner(Some(nation));
        let linked = input.map.provinces[province].linked_tiles.clone();
        for tile in linked {
            input.map[tile].owner_nation = Some(TileOwnerTag::from_nation(nation));
        }
    }

    let counts = NationTable::from_fn(|nation| {
        input
            .map
            .provinces
            .as_array()
            .iter()
            .filter(|province| province.owner() == Some(nation))
            .count()
    });
    let majors = MajorNationId::all()
        .map(|nation| {
            (
                nation,
                major_nation(
                    nation,
                    difficulty,
                    nation == human,
                    if nation == human {
                        ForeignMinisterPersonality::Base
                    } else {
                        ForeignMinisterPersonality::Diplomat
                    },
                    counts[nation.nation()],
                    String::new(),
                ),
            )
        })
        .collect::<IndexMap<_, _>>();
    let minors = MinorNationId::all()
        .map(|nation| (nation, minor_nation(nation, String::new())))
        .collect::<IndexMap<_, _>>();
    let mut nations = Nations::new(majors, minors);
    for province in ProvinceId::all() {
        if let Some(owner) = input.map.provinces[province].owner() {
            nations.append_owned_region_during_construction(owner, province);
            if nations
                .common(owner)
                .is_some_and(|nation| nation.home_tile.is_none())
                && let Some(tile) = input.map.provinces[province].city_tile()
            {
                nations
                    .common_mut(owner)
                    .expect("scenario nation is present")
                    .home_tile = Some(tile);
            }
        }
    }
    for nation in MajorNationId::all() {
        let major = nations.major_mut(nation);
        if let Some(home) = major.common.home_tile {
            major.towns.clear();
            major
                .towns
                .insert(home, TownState::for_frog_city(home, nation.nation()));
        }
    }

    let mut crt_rand = RetailCrtRng::from_state(runtime_seed);
    let diplomacy = DiplomacyState::for_random_start(human, difficulty, &mut crt_rand);
    let mut state = GameState {
        turn: TurnState {
            scenario_map: Some(input.scenario),
            economic_turn: 0,
            diplomacy_year_term_raw: 1914,
            phase: PhaseCode::STRATEGIC_MAP,
            turn_flow_status_flags: 0,
            quarter_gate_by_decade: DecadeTable::from_array([false; 10]),
            difficulty,
            active_nation: human.nation(),
            last_turn_alert_tick: 0,
            turn_alert_mask: 0,
            turn_cooldown_defer_counter: 0,
        },
        unit_ids: UnitIdAllocator::default(),
        ocean: scenario_ocean(&input.map),
        map: input.map,
        rng: RngState {
            crt_rand,
            map_generation: RetailLcg::from_state(runtime_seed),
            zone_status: RetailLcg::from_state(runtime_seed),
        },
        market: TradeMarketState::default(),
        technology: TechnologyState::default(),
        diplomacy,
        nations,
        military_units: IndexMap::new(),
        civilian_units: IndexMap::new(),
        object_ids: ObjectIdAllocator::default(),
        ships: IndexMap::new(),
        admirals: IndexMap::new(),
        task_forces: IndexMap::new(),
        missions: IndexMap::new(),
        news: NewsState::default(),
        pending: PendingWorkState::default(),
        battle_reports: Vec::new(),
        continuation: TurnContinuation::None,
    };
    for instruction in input.instructions {
        state.apply_scenario_instruction(instruction);
    }
    state.map.map_data_ready = true;
    state.map.recruit_search_active = true;
    state
}

fn scenario_ocean(map: &MapMgr) -> Ocean {
    const SEA_OWNER_BIAS: u8 = 0x17;
    let count = map
        .tiles
        .iter()
        .filter_map(|tile| tile.owner_nation)
        .map(TileOwnerTag::get)
        .filter(|&owner| owner >= SEA_OWNER_BIAS)
        .map(|owner| usize::from(owner - SEA_OWNER_BIAS) + 1)
        .max()
        .unwrap_or(0);
    let zones = (0..count)
        .map(|ordinal| {
            let owner = TileOwnerTag::new(SEA_OWNER_BIAS + ordinal as u8);
            ZoneKind::Zone(Zone {
                display_name: String::new(),
                status_code: None,
                target_tile: map
                    .tiles
                    .iter()
                    .position(|tile| tile.owner_nation == Some(owner))
                    .map(|tile| TileId::new(tile as u16)),
                seed_owner: Some(owner),
                active_tile: None,
                primary_neighbors: Vec::new(),
                secondary_neighbors: Vec::new(),
            })
        })
        .collect();
    Ocean {
        zones,
        routes: Vec::new(),
    }
}

impl GameState {
    fn apply_scenario_instruction(&mut self, instruction: ScenarioInstruction) {
        match instruction {
            ScenarioInstruction::Labor { nation, counts } => {
                if let Some(nation) = MajorNationId::from_nation(nation) {
                    self.nations.city_mut(nation).population =
                        PopulationState::from_labor(LaborPool::from(counts));
                }
            }
            ScenarioInstruction::Capacity {
                nation,
                slot,
                value,
            } => {
                if let Ok(slot) = usize::try_from(slot)
                    && slot < enum_map::enum_len::<CityFacilitySlot>()
                {
                    let slot = CityFacilitySlot::from_usize(slot);
                    let city = self.nations.city_mut(nation);
                    city.production_accum[slot] = city.production_accum[slot]
                        .wrapping_add(value.wrapping_sub(city.production_orders[slot]));
                    city.production_orders[slot] = value;
                }
            }
            ScenarioInstruction::Warehouse {
                nation,
                resource,
                amount,
            } => {
                if let Ok(resource) = u8::try_from(resource)
                    && let Some(resource) = ResourceKind::from_index(resource)
                {
                    self.nations.city_mut(nation).stockpile[resource] = amount;
                    self.nations.city_mut(nation).stockpile.verify_stocks();
                }
            }
            ScenarioInstruction::Army {
                province,
                unit,
                count,
            } => {
                let Some(owner) = self.map.provinces[province].owner() else {
                    return;
                };
                let Some(unit) = u8::try_from(unit)
                    .ok()
                    .and_then(MilitaryUnitKind::from_index)
                else {
                    return;
                };
                for _ in 0..count.max(0) {
                    let id = self.unit_ids.next_military();
                    self.military_units.insert(
                        id,
                        MilitaryUnitState::new(
                            owner,
                            unit,
                            Some(province),
                            MilitaryOrder::retail(
                                MilitaryOrderCode::Sleep,
                                None,
                                [None; 3],
                                [None; 3],
                            ),
                            owner,
                            id.get() as i16,
                            true,
                            String::new(),
                            100,
                            unit.spawn_era(),
                            0,
                            0,
                        ),
                    );
                }
            }
            ScenarioInstruction::Civilian { unit, tile } => {
                let Some(owner) = self.map[tile].owner_nation.and_then(TileOwnerTag::nation) else {
                    return;
                };
                let Some(unit) = u8::try_from(unit)
                    .ok()
                    .and_then(CivilianUnitKind::from_index)
                else {
                    return;
                };
                let id = self.unit_ids.next_civilian();
                if let Some(state) = CivilianUnitState::new(
                    owner,
                    unit,
                    CivilianLocation::OnMap(tile),
                    CivilianWorkOrder::Idle,
                    owner,
                    id.get() as i16,
                    true,
                ) {
                    self.civilian_units.insert(id, state);
                }
            }
            ScenarioInstruction::Ship {
                nation,
                ship,
                zone,
                count,
            } => {
                if let Some(ship) = u8::try_from(ship).ok().and_then(ShipType::from_index) {
                    let city = self.nations.city_mut(nation);
                    city.ship_order_count_by_type[ship] =
                        city.ship_order_count_by_type[ship].wrapping_add(count as i16);
                    if crate::city::ship_creates_navy_object(ship)
                        && let Ok(zone) = u16::try_from(zone)
                        && usize::from(zone) < self.ocean.zones.len()
                    {
                        let location = OceanZoneId::new(zone);
                        for _ in 0..count.max(0) {
                            self.insert_named_ship(ShipState {
                                ship_type: ship,
                                location,
                                aggression: NavalAggression::Balanced,
                                nation: nation.nation(),
                                name: String::new(),
                                strength: crate::city::ship_stock_cap(ship),
                                experience: 0,
                                selection: ShipSelection::Available,
                            });
                        }
                    }
                }
            }
            ScenarioInstruction::Transport { nation, amount } => {
                self.nations.majors[&nation].economy.capacities.transport = amount;
            }
            ScenarioInstruction::Development { tile, level } => {
                let extractive = self.map[tile].edge_resources[0].is_some_and(|resource| {
                    matches!(
                        resource,
                        ResourceKind::Gold
                            | ResourceKind::Gems
                            | ResourceKind::Iron
                            | ResourceKind::Coal
                            | ResourceKind::Oil
                    )
                });
                if extractive {
                    self.map[tile].development.extractive = DevelopmentLevel::new(level);
                } else {
                    self.map[tile].development.surface = DevelopmentLevel::new(level);
                }
            }
            ScenarioInstruction::Rail { tile } => {
                let Some(nation) = self.map[tile]
                    .owner_nation
                    .and_then(TileOwnerTag::nation)
                    .and_then(MajorNationId::from_nation)
                else {
                    return;
                };
                self.queue_depot_construction(tile, nation);
                if !self.nations.major(nation).economy.diplomacy_eligible {
                    self.nations.major_mut(nation).common.treasury += 2_000;
                }
            }
            ScenarioInstruction::Port { tile } => {
                let Some(nation) = self.map[tile]
                    .owner_nation
                    .and_then(TileOwnerTag::nation)
                    .and_then(MajorNationId::from_nation)
                else {
                    return;
                };
                self.queue_port_construction(tile, nation);
                if !self.nations.major(nation).economy.diplomacy_eligible {
                    self.nations.major_mut(nation).common.treasury += 3_000;
                }
            }
            ScenarioInstruction::Technology { nation, technology } => {
                if let Ok(index) = usize::try_from(technology)
                    && index < Technology::LENGTH
                {
                    let technology = Technology::from_usize(index);
                    self.technology.global_unlocks_by_technology[technology] = true;
                    self.technology.research_status_by_nation[nation][technology] =
                        TechnologyResearchStatus::Researched;
                }
            }
            ScenarioInstruction::Price { resource, value } => {
                if let Some(resource) = TradeCommodity::from_retail(resource) {
                    self.market.rows[resource].price = i32::from(value);
                }
            }
            ScenarioInstruction::Embassy {
                first,
                second,
                level,
            } => {
                if let Some(level) = DiplomaticMissionLevel::try_from_retail(level) {
                    self.diplomacy.mission_levels[first][second] = level;
                    self.diplomacy.mission_levels[second][first] = level;
                }
            }
            ScenarioInstruction::Subsidy {
                owner,
                target,
                level,
            } => {
                self.nations.majors[&owner].common.trade_policy_by_nation[target] =
                    TradePolicyScore::new(i32::from(level));
            }
            ScenarioInstruction::Treaty {
                source,
                target,
                relationship,
            } => {
                if let Some(relationship) = i16::try_from(relationship)
                    .ok()
                    .and_then(DiplomaticRelationship::try_from_retail)
                {
                    self.diplomacy.relationships[source][target] = relationship;
                    self.diplomacy.relationships[target][source] = relationship;
                    if relationship == DiplomaticRelationship::JoinedEmpire {
                        self.nations
                            .set_country_status(target, CountryStatus::ColonyOf(source));
                    }
                }
            }
            ScenarioInstruction::Year(year) => {
                self.turn.economic_turn = i32::from(year).wrapping_mul(4)
            }
            ScenarioInstruction::ProvinceOwner { .. } => {}
            ScenarioInstruction::ZoneName { zone, name } => {
                if let Ok(zone) = usize::try_from(zone)
                    && let Some(zone) = self.ocean.zones.get_mut(zone)
                {
                    match zone {
                        ZoneKind::Zone(zone) => zone.display_name = name,
                        ZoneKind::PortZone(port) => port.zone.display_name = name,
                    }
                }
            }
            ScenarioInstruction::CountryName { nation, name } => {
                if let Some(country) = self.nations.common_mut(nation) {
                    country.display_name = name;
                }
            }
            ScenarioInstruction::Standing {
                source,
                target,
                value,
            } => {
                self.diplomacy.standings[source][target] = value;
                self.diplomacy.standings[target][source] = value;
            }
            ScenarioInstruction::ProvinceName { province, name } => {
                self.map.provinces[province].name = name;
            }
            ScenarioInstruction::Cash { nation, amount } => {
                if let Some(country) = self.nations.common_mut(nation) {
                    country.treasury = amount;
                }
            }
            ScenarioInstruction::Flag(_) => {}
            ScenarioInstruction::CapabilityTier { slot, value } => {
                if let Ok(slot) = usize::try_from(slot)
                    && slot < Technology::LENGTH
                {
                    self.technology.scheduled_unlock_turn_by_technology
                        [Technology::from_usize(slot)] = value.wrapping_add(1) as i16 * 4;
                }
            }
            ScenarioInstruction::NeedTarget {
                nation,
                resource,
                value,
            } => {
                if let Ok(resource) = u8::try_from(resource)
                    && let Some(resource) = ResourceKind::from_index(resource)
                {
                    self.nations.majors[&nation].economy.need_target_by_type[resource] =
                        value as i16;
                }
            }
            ScenarioInstruction::ClearNeedTargets { nation } => {
                self.nations.majors[&nation].economy.need_target_by_type = ResourceTable::default();
            }
            ScenarioInstruction::DecadeState { decade, state } => {
                if let Ok(decade) = usize::try_from(decade)
                    && decade < 10
                {
                    self.turn.quarter_gate_by_decade[Decade::from_usize(decade)] = state != 0;
                    if state == 2 {
                        self.turn.diplomacy_year_term_raw = decade as i16 * 10 + 0x717;
                    }
                }
            }
        }
    }
}
