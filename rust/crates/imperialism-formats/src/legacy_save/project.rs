use super::PROVINCE_COUNT;
use super::conversions::*;
use super::model::*;
use super::*;
use imperialism_core::*;
use indexmap::IndexMap;

fn optional_region_id(value: i8) -> Option<RegionId> {
    optional_u8(value).map(RegionId::new)
}

fn optional_resource_kind(value: i8) -> Option<ResourceKind> {
    optional_u8(value).map(|value| ResourceKind::from_index(value).expect("retail resource kind"))
}

fn optional_tile_owner_tag(value: i8) -> Option<TileOwnerTag> {
    optional_u8(value).map(TileOwnerTag::new)
}

fn optional_major_nation_id(value: i8) -> Option<MajorNationId> {
    optional_u8(value).map(MajorNationId::new)
}

fn optional_province_id(value: i16) -> Option<ProvinceId> {
    optional_u16(value).map(ProvinceId::new)
}

fn optional_province_array(values: [i16; 3]) -> [Option<ProvinceId>; 3] {
    values.map(optional_province_id)
}

fn optional_ocean_zone_id(value: i16) -> Option<OceanZoneId> {
    optional_u16(value).map(OceanZoneId::new)
}

fn optional_nation_id(value: i16) -> Option<NationId> {
    optional_u16(value).map(|value| NationId::new(value as u8))
}

fn optional_tile_id(value: i32) -> Option<TileId> {
    optional_u16_from_i32(value).map(TileId::new)
}

fn civilian_work_order(
    value: i32,
    tile: Option<TileId>,
    target: Option<TileId>,
    remaining: i16,
    topology: MapTopology,
) -> CivilianWorkOrder {
    let turns = || remaining;
    let required_tile = || tile.expect("retail work order has a tile");
    match value {
        0 => CivilianWorkOrder::Idle,
        1 => CivilianWorkOrder::Redeploy {
            source: target.expect("retail redeploy order has a source"),
            turns: turns(),
        },
        2 => CivilianWorkOrder::Sleep,
        5 => CivilianWorkOrder::LayRail {
            segment: RailSegment::between(
                topology,
                target.expect("retail rail order has a source"),
                required_tile(),
            )
            .expect("retail rail order tiles are adjacent"),
            turns: turns(),
        },
        6 => {
            required_tile();
            CivilianWorkOrder::BuildDepot {
                source: target.expect("retail depot order has a source"),
                turns: turns(),
            }
        }
        7 => {
            required_tile();
            CivilianWorkOrder::BuildPort {
                source: target.expect("retail port order has a source"),
                turns: turns(),
            }
        }
        8 => {
            required_tile();
            CivilianWorkOrder::Prospect {
                source: target.expect("retail prospecting order has a source"),
                turns: turns(),
            }
        }
        10 => {
            required_tile();
            CivilianWorkOrder::DevelopResource {
                source: target.expect("retail development order has a source"),
                turns: turns(),
            }
        }
        12 => {
            required_tile();
            CivilianWorkOrder::BuildFort {
                source: target.expect("retail fort order has a source"),
                turns: turns(),
            }
        }
        13 => {
            required_tile();
            CivilianWorkOrder::PurchaseLand {
                source: target.expect("retail land-purchase order has a source"),
                turns: turns(),
            }
        }
        _ => panic!("unrecovered civilian work order {value}"),
    }
}

fn nation_id_from_retail_i16(value: i16) -> NationId {
    NationId::new(value as u8)
}

fn minor_nation_id_from_retail_i16(value: i16) -> MinorNationId {
    MinorNationId::new(value as u8)
}

/// Mirrors the live, language-table-loaded `NormalizeRuntimeCredentialNameToken`
/// pass used by the Diplomacy map on `TCountry::identitySharedString1`.
fn normalize_nation_display_name(raw: &str) -> String {
    let mut characters = raw.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    if first == '(' || first.is_ascii_uppercase() {
        raw.to_owned()
    } else {
        characters.as_str().to_owned()
    }
}

impl LegacyCountryBase {
    fn military_unit_states(&self, nation: NationId) -> Vec<(MilitaryUnitId, MilitaryUnitState)> {
        self.military_units
            .iter()
            .map(|unit| {
                let id = MilitaryUnitId::from_serialized(unit.persistent_id);
                let unit_type = MilitaryUnitKind::from_index(unit.unit_type as u8)
                    .expect("retail military unit type");
                let targets = optional_province_array(unit.order_target_tiles);
                let target_mirrors = optional_province_array(unit.order_target_mirrors);
                let target = optional_province_id(unit.order_target);
                let order = if unit.order == 0 && target.is_none() {
                    MilitaryOrder::idle(targets, target_mirrors)
                } else {
                    MilitaryOrder::retail(
                        MilitaryOrderCode::from_retail(unit.order),
                        target,
                        targets,
                        target_mirrors,
                    )
                };
                let state = MilitaryUnitState::new(
                    nation,
                    unit_type,
                    optional_province_id(unit.stationed_province),
                    order,
                    nation_id_from_retail_i16(unit.owner_nation),
                    unit.roster_id,
                    unit.registered != 0,
                    unit.name.clone(),
                    unit.strength,
                    MilitaryEra::from_retail(unit.era).expect("retail military era"),
                    unit.experience,
                    unit.battle_flags,
                );
                (id, state)
            })
            .collect()
    }
}

impl LegacyGreatPowerPostCity {
    fn civilian_unit_states(
        &self,
        nation: NationId,
        topology: MapTopology,
    ) -> Vec<(CivilianUnitId, CivilianUnitState)> {
        self.civilian_units
            .iter()
            .map(|unit| {
                let id = CivilianUnitId::from_serialized(unit.persistent_id);
                let unit_type = CivilianUnitKind::from_index(unit.unit_type as u8)
                    .expect("retail civilian unit type");
                let tile = optional_tile_id(i32::from(unit.tile_index));
                let target = optional_tile_id(i32::from(unit.order_target));
                let state = CivilianUnitState::new(
                    nation,
                    unit_type,
                    tile.map_or(CivilianLocation::OffMap, CivilianLocation::OnMap),
                    civilian_work_order(unit.order, tile, target, unit.remaining_turns, topology),
                    nation_id_from_retail_i16(unit.owner_nation),
                    unit.roster_id,
                    unit.registered != 0,
                )
                .expect("retail civilian order agrees with its location");
                (id, state)
            })
            .collect()
    }
}

impl LegacyMission {
    fn mission_state(
        &self,
        nation: NationId,
        military_units: &[LegacyMilitaryUnit],
    ) -> MissionState {
        let (common, data) = match self {
            Self::DefendProvince { common, army } => {
                let (province, army) = army_mission_state(army, military_units);
                (
                    common,
                    MissionData::DefendProvince {
                        province: province.expect("retail defend mission has a province"),
                        army,
                    },
                )
            }
            Self::AttackProvince {
                common,
                army,
                target_province,
                amassing_province,
            } => (
                common,
                MissionData::AttackProvince(attack_mission_state(
                    army,
                    *target_province,
                    *amassing_province,
                    military_units,
                )),
            ),
            Self::Invade {
                common,
                army,
                target_province,
                amassing_province,
                beachhead,
            } => (
                common,
                MissionData::Invade {
                    attack: attack_mission_state(
                        army,
                        *target_province,
                        *amassing_province,
                        military_units,
                    ),
                    beachhead: Some(navy_mission_state(beachhead)),
                },
            ),
            Self::ControlSeaZone { common, navy } => (
                common,
                MissionData::ControlSeaZone(navy_mission_state(navy)),
            ),
            Self::Escort { common, navy } => {
                (common, MissionData::Escort(navy_mission_state(navy)))
            }
            Self::ScatteredShips { common, navy } => (
                common,
                MissionData::ScatteredShips(navy_mission_state(navy)),
            ),
            Self::Beachhead { common, navy } => {
                (common, MissionData::Beachhead(navy_mission_state(navy)))
            }
            Self::BlockadePort {
                common,
                navy,
                blockade_port_zone,
            } => (
                common,
                MissionData::BlockadePort {
                    navy: navy_mission_state(navy),
                    port_zone: optional_ocean_zone_id(*blockade_port_zone)
                        .expect("retail blockade mission has a port zone"),
                },
            ),
        };
        MissionState {
            nation,
            data,
            path_nation: optional_nation_id(common.path_marker),
            state: common.state,
            importance_bits: common.importance_bits,
            held: common.flag != 0,
            marker: common.marker,
        }
    }
}

fn army_mission_state(
    mission: &LegacyArmyMission,
    military_units: &[LegacyMilitaryUnit],
) -> (Option<ProvinceId>, ArmyMissionState) {
    let units = mission
        .unit_ordinals
        .iter()
        .rev()
        .map(|ordinal| {
            let unit = &military_units[(*ordinal - 1) as usize];
            MilitaryUnitId::from_serialized(unit.persistent_id)
        })
        .collect();
    (
        optional_province_id(mission.present_location),
        ArmyMissionState {
            required_equipage_bits: mission.required_equipage_bits,
            units,
        },
    )
}

fn attack_mission_state(
    mission: &LegacyArmyMission,
    target_province: i16,
    amassing_province: i16,
    military_units: &[LegacyMilitaryUnit],
) -> AttackMissionState {
    let (present_province, army) = army_mission_state(mission, military_units);
    AttackMissionState {
        army,
        present_province,
        target_province: optional_province_id(target_province)
            .expect("retail attack mission has a target province"),
        amassing_province: optional_province_id(amassing_province),
    }
}

fn navy_mission_state(mission: &LegacyNavyMission) -> NavyMissionState {
    assert!(
        mission.ship_ordinals.is_empty(),
        "semantic projection of navy mission ship references is not implemented"
    );
    NavyMissionState {
        target_zone: optional_ocean_zone_id(mission.target_zone),
        resolved_port_zone: optional_ocean_zone_id(mission.resolved_port_zone),
        // TNavyMission::ReadFrom rebuilds these runtime-only links as null.
        selected_ship: None,
        task_force: None,
        state: NavyMissionSelection::from_retail(mission.state)
            .expect("retail navy mission selection"),
        required_equipage_bits: mission.required_equipage_bits,
        ships: Default::default(),
    }
}

fn ship_states(
    navy: &LegacyNavyState,
    object_ids: &mut ObjectIdAllocator,
) -> IndexMap<ShipId, ShipState> {
    navy.ships
        .iter()
        .rev()
        .map(|ship| {
            let id = object_ids.ship();
            (
                id,
                ShipState {
                    ship_type: ShipType::from_index(ship.ship_type as u8)
                        .expect("retail ship type is in the descriptor table"),
                    location: OceanZoneId::new(
                        u16::try_from(ship.zone_ordinal)
                            .expect("retail ship zone ordinal is non-negative"),
                    ),
                    aggression: NavalAggression::from_retail(ship.aggression)
                        .expect("retail ship aggression is in 0..=2"),
                    nation: nation_id_from_retail_i16(ship.nation),
                    name: ship.name.clone(),
                    strength: ship.strength,
                    experience: ship.experience,
                    selection: ShipSelection::from_retail(ship.selection)
                        .expect("retail ship selection"),
                },
            )
        })
        .collect()
}

fn admiral_states(
    navy: &LegacyNavyState,
    ship_ids: &[ShipId],
    object_ids: &mut ObjectIdAllocator,
) -> IndexMap<AdmiralId, AdmiralState> {
    navy.admirals
        .iter()
        .rev()
        .map(|admiral| {
            (
                object_ids.admiral(),
                AdmiralState {
                    nation: nation_id_from_retail_i16(admiral.nation),
                    name: admiral.name.clone(),
                    experience: admiral.experience,
                    ship: (admiral.ship_index >= 0)
                        .then(|| ship_ids.get(admiral.ship_index as usize).copied())
                        .flatten(),
                },
            )
        })
        .collect()
}

fn task_force_states(
    navy: &LegacyNavyState,
    ship_ids: &[ShipId],
    object_ids: &mut ObjectIdAllocator,
) -> IndexMap<TaskForceId, TaskForceState> {
    navy.task_forces
        .iter()
        .rev()
        .filter_map(|force| {
            let ships = force
                .ships
                .iter()
                .map(|pair| {
                    let ship = ship_ids
                        .get(usize::try_from(pair[0]).expect("retail ship ordinal is non-negative"))
                        .copied()
                        .expect("task-force ship ordinal is in the primary ship list");
                    (ship, pair[1] != 0)
                })
                .collect::<IndexMap<_, _>>();
            if ships.is_empty() {
                return None;
            }
            let order = TaskForceOrder::from_retail(force.order);
            let target = if order == TaskForceOrder::Marines {
                TaskForceTarget::Province(
                    optional_province_id(force.target_ordinal)
                        .expect("retail marines order has a province target"),
                )
            } else {
                optional_ocean_zone_id(force.target_ordinal)
                    .map(TaskForceTarget::Zone)
                    .unwrap_or(TaskForceTarget::None)
            };
            Some((
                object_ids.task_force(),
                TaskForceState::from_parts(
                    NavalAggression::from_retail(force.aggression)
                        .expect("retail task-force aggression is in 0..=2"),
                    order,
                    target,
                    optional_ocean_zone_id(force.location_ordinal)
                        .expect("retail task force has a location"),
                    nation_id_from_retail_i16(force.nation),
                    force.defeated != 0,
                    force.ingot_tile,
                    ships,
                ),
            ))
        })
        .collect()
}

fn production_progress(order: &LegacyProductionOrder) -> ProductionProgress {
    ProductionProgress {
        quantity: order.quantity,
        limiting_constraint: production_constraint_from_retail(order.limiting_constraint),
    }
}

fn requested_city_order(order: &LegacyItemOrder) -> RequestedCityOrderState {
    RequestedCityOrderState {
        progress: production_progress(&order.order),
        requested_quantity: order.requested_quantity,
        tracking_by_resource: ResourceTable::from_array(order.order.tracking_slots),
        accumulated_value: order.order.accumulated_value,
    }
}

impl LegacyCityOrders {
    fn city_orders(&self) -> CityOrders {
        CityOrders {
            items: ItemOrderTable::from_array(self.items.each_ref().map(requested_city_order)),
            civilian_recruitment: CivilianUnitTable::from_array(std::array::from_fn(|index| {
                production_progress(&self.civilian_recruitment[index].order)
            })),
            military_recruitment: MilitaryRecruitOrderTable::from_array(std::array::from_fn(
                |index| {
                    let order = &self.military_recruitment[index];
                    MilitaryRecruitOrderState {
                        unit_kind: MilitaryUnitKind::from_index(
                            order.order.resource_type_index as u8,
                        )
                        .expect("retail military recruitment unit kind"),
                        progress: production_progress(&order.order),
                    }
                },
            )),
            ships: ShipOrderTable::from_array(std::array::from_fn(|index| {
                let order = &self.ships[index];
                let tracking = ResourceTable::from_array(order.tracking_slots);
                ShipOrderState {
                    ship_type: ShipType::from_index(
                        u8::try_from(order.resource_type_index).expect("retail ship type"),
                    )
                    .expect("retail ship type"),
                    progress: production_progress(order),
                    materials: ShipMaterials {
                        lumber: tracking[ResourceKind::Lumber],
                        fabric: tracking[ResourceKind::Fabric],
                        arms: tracking[ResourceKind::Arms],
                        steel: tracking[ResourceKind::Steel],
                        coal: tracking[ResourceKind::Coal],
                        fuel: tracking[ResourceKind::Fuel],
                    },
                }
            })),
            training: TrainingOrderTable::from_array(
                self.training.each_ref().map(production_progress),
            ),
            expansions: ExpansionOrderTable::from_array(
                self.expansions.each_ref().map(requested_city_order),
            ),
            food_processing: production_progress(&self.food_processing),
            power_plant: PowerPlantOrderState {
                progress: production_progress(&self.power_plant.order),
                desired_quantity: self.power_plant.desired_quantity,
            },
            transport_capacity: requested_city_order(&self.transport_capacity),
            population_growth: production_progress(&self.population_growth),
        }
    }
}

impl LegacyCityState {
    fn city_state(&self) -> CityState {
        assert!(
            self.tasks.is_empty(),
            "semantic projection of city tasks is not implemented"
        );
        assert!(
            self.transport_requests.records.is_empty(),
            "semantic projection of city transport requests is not implemented"
        );

        let strike_phase = StrikePhase::from_retail(self.population.phase_value)
            .expect("retail population strike phase");
        let accumulator =
            PopulationAccumulator::new(f32::from_bits(self.population.count_float_bits))
                .expect("retail population accumulator is finite");

        CityState {
            orders: self.orders.city_orders(),
            power_plant_upgrade_queued: self.power_plant_upgrade_queued != 0,
            food_substitution_count: self.food_substitution_count,
            starvation_population_loss: self.starvation_population_loss,
            serialized_state: self.serialized_state,
            phase_counter: self.phase_counter,
            military_recruit_count_by_kind: MilitaryUnitTable::from_array(
                self.military_recruit_count_by_kind,
            ),
            civilian_recruit_count_by_kind: CivilianUnitTable::from_array(
                self.civilian_recruit_count_by_kind,
            ),
            ship_order_count_by_type: ShipTypeTable::from_array(self.order_count_by_type),
            rolling_item_production_score: self.rolling_item_production_score,
            low_production: self.low_production != 0,
            low_stock: self.low_stock != 0,
            reserved_by_type: ResourceTable::from_array(self.reserved_by_type),
            power_available: self.power_available,
            stockpile: Stockpile::from_table(ResourceTable::from_array(self.stockpile)),
            production_orders: ProductionTable::from_array(self.production_orders),
            production_accum: ProductionTable::from_array(self.production_accum),
            building_windows: city_windows_from_retail(
                self.production_flags,
                self.production_current,
                self.production_progress,
            ),
            // This constructed cache is not persisted by TCity::ReadFrom.
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::from_array(self.unmet_resource_retries),
            consumed_production_input_by_type: ResourceTable::from_array(
                self.consumed_production_input_by_type,
            ),
            population: PopulationState::new(
                self.population.count,
                accumulator,
                self.population.strength,
                self.population.extra,
                strike_phase,
                LaborPool::from(self.population.baseline_labor),
                LaborPool::from(self.population.production_labor),
                LaborPool::from(self.population.pending_labor_delta),
                ResourceTable::from_array(self.population.predicted_need_by_resource),
            ),
        }
    }
}

impl LegacyTerrainTile {
    fn tile_state(&self) -> TileState {
        let rendering = TileRendering::from_retail(
            self.sprite_variant,
            self.river_sprite,
            self.adjacency_mask_a,
            self.adjacency_mask_b,
        )
        .expect("retail tile rendering state");
        TileState {
            terrain: TerrainKind::from_retail(self.terrain_kind).expect("retail terrain kind"),
            rendering,
            owner_nation: optional_tile_owner_tag(self.owner_nation),
            former_owner_nation: optional_tile_owner_tag(self.former_owner_nation),
            secondary_owner_nation: optional_major_nation_id(self.secondary_owner_nation),
            owner_border_mask: self.owner_border_mask,
            city_border_mask: self.city_border_mask,
            water_adjacency_mask: self.water_adjacency_mask,
            province: optional_province_id(self.city_record_index),
            gate: self.gate,
            recruit_search_visited: self.recruit_search_visited,
            per_tile_visited: self.per_tile_visited,
            tile_action_ordinal: self.tile_action_ordinal,
            development: TileDevelopment {
                surface: DevelopmentLevel::new((self.development_classes as u8) & 0x0f),
                extractive: DevelopmentLevel::new((self.development_classes as u8) >> 4),
                resource_visible_to_majors: MajorNationTable::from_fn(|nation| {
                    self.pending_development_visibility & (1 << nation.get()) != 0
                }),
            },
            edge_resources: [
                optional_resource_kind(self.edge_resources[0]),
                optional_resource_kind(self.edge_resources[1]),
            ],
            transport_links: TileTransportLinks::from_bits_retain(self.adjacency_bits),
            pending_rail_links: TileTransportLinks::from_bits_retain(self.rail_flags),
            action: TileAction::try_from_retail(i16::from(self.action_state)),
            flags: TileFlags::from_bits_retain(self.active_flags),
            region: optional_region_id(self.region),
        }
    }
}

impl LegacyMapState {
    const fn topology(&self) -> MapTopology {
        if self.no_horizontal_wrap == 0 {
            MapTopology::Wrapping
        } else {
            MapTopology::Bounded
        }
    }

    fn map_mgr(&self) -> MapMgr {
        let mut map = MapMgr::from_parts(
            self.topology(),
            self.tiles
                .iter()
                .map(LegacyTerrainTile::tile_state)
                .collect::<Vec<_>>(),
            self.province_states(),
        );
        map.map_data_ready = self.map_data_ready != 0;
        map.recruit_search_active = self.recruit_search_active != 0;
        map.city_score_total = self.city_score_total;
        map.scenario_tag.clone_from(&self.scenario_tag);
        map.pending_river_mouth_tile = optional_tile_id(i32::from(self.pending_river_mouth_tile));
        map
    }

    fn province_states(&self) -> ProvinceTable<ProvinceState> {
        ProvinceTable::from_array(std::array::from_fn(|index| {
            province_state(&self.provinces[index])
        }))
    }
}

fn trade_market_state(market: &LegacyTradeMarketState) -> TradeMarketState {
    TradeMarketState {
        rows: TradeCommodityTable::from_array(std::array::from_fn(|index| {
            let row = &market.rows[index];
            TradeMarketRow {
                previous_price: i32::from(row.previous_price),
                price: i32::from(row.price),
                base_price: i32::from(row.base_price),
                request_count: i32::from(row.request_count),
                offer_count: i32::from(row.offer_count),
                amount_offered: i32::from(row.amount_offered),
                adjusted_offer_count: row.adjusted_offer_count,
                current_offer_by_nation: NationTable::from_array(row.current_offer_by_nation),
                accumulated_offer_by_nation: NationTable::from_array(
                    row.accumulated_offer_by_nation,
                ),
                maximum_offer_by_nation: NationTable::from_array(row.maximum_offer_by_nation),
            }
        })),
    }
}

fn nation_pair_table<T: Copy>(
    values: [T; NATION_COUNT * NATION_COUNT],
) -> NationTable<NationTable<T>> {
    NationTable::from_array(std::array::from_fn(|source| {
        NationTable::from_array(std::array::from_fn(|target| {
            values[source * NATION_COUNT + target]
        }))
    }))
}

fn optional_major_nation_from_i16(value: i16) -> Option<MajorNationId> {
    optional_u16(value).map(|value| MajorNationId::new(value as u8))
}

fn diplomacy_state(diplomacy: &LegacyDiplomacyState) -> DiplomacyState {
    DiplomacyState {
        standings: nation_pair_table(diplomacy.relation_standing_scores),
        relationships: nation_pair_table(diplomacy.relation_propagation_matrix.map(|value| {
            DiplomaticRelationship::try_from_retail(value).expect("retail diplomatic relationship")
        })),
        relationship_turns: nation_pair_table(
            diplomacy
                .relation_turn_stamp_matrix
                .map(|value| (value != -1).then_some(value)),
        ),
        influence_thresholds: ProvinceTable::from_array(diplomacy.relation_code_matrix),
        influence_sides: ProvinceTable::from_array(
            diplomacy
                .pending_policy_code_matrix
                .map(optional_major_nation_id),
        ),
        last_diplomatic_effort_turn: diplomacy.last_diplomatic_effort_turn,
        mission_levels: nation_pair_table(diplomacy.relation_side_effect_matrix.map(|value| {
            DiplomaticMissionLevel::try_from_retail(value).expect("retail diplomatic mission level")
        })),
        congress: DiplomaticCongressState {
            chairman: optional_major_nation_from_i16(diplomacy.congress_leadership[0]),
            counterpart: optional_major_nation_from_i16(diplomacy.congress_leadership[1]),
            chairman_support: diplomacy.congress_support[0],
            counterpart_support: diplomacy.congress_support[1],
            neutral_support: diplomacy.congress_support[2],
        },
        special_relation_sources: MinorNationTable::from_array(
            diplomacy
                .special_relation_source_slots
                .map(optional_major_nation_from_i16),
        ),
        special_relation_targets: MinorNationTable::from_array(
            diplomacy
                .special_relation_target_slots
                .map(optional_major_nation_from_i16),
        ),
        // The retail constructor restores both values before ReadFrom consumes the payload.
        last_processed_nation: None,
        proposal_rejection: None,
    }
}

fn military_capability_kind(value: i16) -> MilitaryUnitKind {
    MilitaryUnitKind::from_index(
        u8::try_from(value).expect("retail nationCapRows slot is a military unit kind"),
    )
    .expect("retail nationCapRows slot is a military unit kind")
}

fn technology_state(legacy: &LegacyTechnologyState) -> TechnologyState {
    let status = |nation: usize, tech: Technology| {
        legacy.research_status_by_nation[nation][usize::from(tech.retail())]
    };
    let researched = |nation: usize, tech: Technology| status(nation, tech) == 2;
    let city_capabilities_by_nation = std::array::from_fn(|nation| CityTechnologyCapabilities {
        advanced_iron_working: researched(nation, Technology::AdvancedIronWorking),
        oil_drilling: researched(nation, Technology::OilDrilling),
        university: UniversityTechnologyState {
            available: CivilianUnitTable::from_array(
                legacy.university_recruitment_availability[nation].map(|value| value != 0),
            ),
            requirement_levels: ResourceTable::from_array(
                legacy.capability_value_by_nation_and_resource[nation].map(|value| {
                    UniversityRequirementLevel::from_retail(
                        u8::try_from(value).expect("retail university requirement level"),
                    )
                    .expect("retail university requirement level")
                }),
            ),
        },
        primary_civilian_distance_terrain: CivilianTerrainAccess {
            hills: researched(nation, Technology::CompoundSteamEngine),
            mountain: researched(nation, Technology::Dynamite),
            swamp: researched(nation, Technology::IronRailroadBridge),
        },
        secondary_civilian_hills: researched(nation, Technology::BessemerConverter),
        secondary_civilian_swamp: researched(nation, Technology::SquareSetTimbering),
        fort_level_cap: if status(nation, Technology::LargeArtillery) != 0 {
            FortLevelCap::Three
        } else if status(nation, Technology::BessemerConverter) != 0 {
            FortLevelCap::Two
        } else {
            FortLevelCap::One
        },
    });

    TechnologyState {
        advanced_iron_working: legacy.resource_type_enabled
            [usize::from(IndustryCapabilitySlot::Armory.retail())]
            != 0,
        marine_engineering: legacy.resource_type_enabled
            [usize::from(IndustryCapabilitySlot::PowerPlant.retail())]
            != 0,
        scheduled_unlock_turn_by_technology: TechnologyTable::from_array(legacy.priority_slots),
        global_unlocks_by_technology: TechnologyTable::from_array(
            legacy.per_technology_unlock_flags.map(|value| value != 0),
        ),
        latest_global_unlock: u8::try_from(legacy.marker)
            .ok()
            .and_then(Technology::from_index)
            .unwrap_or(Technology::SeedDrill),
        research_status_by_nation: MajorNationTable::from_array(
            legacy.research_status_by_nation.map(|row| {
                TechnologyTable::from_array(row.map(technology_research_status_from_retail))
            }),
        ),
        completion_year_by_nation: MajorNationTable::from_array(
            legacy
                .completion_year_offsets
                .map(TechnologyTable::from_array),
        ),
        industry_enabled_by_slot: IndustryCapabilityTable::from_array(
            legacy.resource_type_enabled.map(|value| value != 0),
        ),
        military_unit_ability_active_by_nation: MajorNationTable::from_array(
            legacy
                .ability_active_by_nation
                .map(|row| MilitaryUnitTable::from_array(row.map(|value| value != 0))),
        ),
        selected_capability_slots: MajorNationTable::from_array(
            legacy
                .nation_capability_slots
                .map(|row| ArmyCategoryTable::from_array(row.map(military_capability_kind))),
        ),
        city_capabilities_by_nation: MajorNationTable::from_array(city_capabilities_by_nation),
        navy_growth_ship_type: ShipType::from_index(legacy.active_zone_index as u8)
            .expect("retail activeZoneIndex1d4 is a ship type"),
    }
}

impl LegacySaveV62 {
    /// Projects persistable save fields into construction parts. Runtime-only RNG and
    /// selection state must be supplied because the retail stream does not contain them.
    pub fn game_state_parts(&self, context: LegacyGameStateContext) -> GameStateParts {
        let mut object_ids = ObjectIdAllocator::default();
        let ships = ship_states(&self.navy, &mut object_ids);
        let ship_ids = ships.keys().rev().copied().collect::<Vec<_>>();
        let admirals = admiral_states(&self.navy, &ship_ids, &mut object_ids);
        let task_forces = task_force_states(&self.navy, &ship_ids, &mut object_ids);

        let mut minors = IndexMap::new();
        let mut military_units = IndexMap::new();
        let mut civilian_units = IndexMap::new();
        let mut missions = IndexMap::new();
        let mut pending = PendingWorkState::default();
        let map = self.map.map_mgr();
        let map_view_origin = TileId::new(self.map.view_origin_tile as u16);
        let ocean = ocean_state(&self.ocean, &map);
        let live_ocean_context_count = ocean.zones.len();
        let mut majors = IndexMap::new();
        for (&major_id, nation) in &self.major_nations {
            let slot = usize::from(major_id.get());
            let nation_id = major_id.nation();
            let great_power = nation.great_power();
            let city = great_power
                .city
                .as_ref()
                .expect("retail great power has a city");
            let towns = great_power
                .post_city
                .towns
                .iter()
                .map(|town| {
                    let tile = optional_tile_id(i32::from(town.tile_index))
                        .expect("retail town has a tile");
                    (
                        tile,
                        TownState {
                            name: town.name.clone(),
                            created_turn: town.created_turn,
                            owner_nation: NationId::new(town.owner_nation as u8),
                            resource_yield_by_type: ResourceTable::from_array(
                                town.resource_yield_by_type,
                            ),
                            transport_linked: town.transport_linked != 0,
                            enabled: town.enabled,
                            has_adjacent_city: town.has_adjacent_city,
                            active: town.active != 0,
                        },
                    )
                })
                .collect();
            let city = city.city_state();
            let foreign_minister_personality = foreign_minister_personality(
                nation,
                self.simulation.game_setup.foreign_minister_policy_ids[slot],
            );
            let auto = match nation {
                LegacyMajorNationState::Auto(auto) => Some(AutoGreatPowerState {
                    zone_targets: ai_zone_targets(
                        &auto.auto_prefix.port_zone_state_flags,
                        live_ocean_context_count,
                    ),
                    province_targets: ai_province_targets(&auto.auto_prefix.map_node_state_flags),
                    trade: AiTradeState {
                        temporary_processed_stock: ProcessedTradeCommodityTable::from_array(
                            auto.auto_prefix.action_metric_by_quarter,
                        ),
                    },
                }),
                LegacyMajorNationState::Other(_) => None,
            };
            let major = MajorNation {
                auto,
                common: country_common(&great_power.country),
                economy: great_power_state(great_power, foreign_minister_personality),
                city,
                towns,
            };
            military_units.extend(great_power.country.military_unit_states(nation_id));
            civilian_units.extend(
                great_power
                    .post_city
                    .civilian_unit_states(nation_id, self.map.topology()),
            );
            if let LegacyMajorNationState::Auto(auto) = nation {
                for mission in &auto.missions {
                    missions.insert(
                        object_ids.mission(),
                        mission.mission_state(nation_id, &great_power.country.military_units),
                    );
                }
            }
            pending.nations[major_id].turn_events =
                diplomacy_notices(&great_power.prefix.turn_event_queue);
            pending.nations[major_id].proposals =
                diplomacy_proposals(&great_power.prefix.proposal_queue);
            majors.insert(major_id, major);
        }
        for (&minor_id, nation) in &self.minor_nations {
            let nation_id = minor_id.nation();
            minors.insert(
                minor_id,
                MinorNation {
                    common: country_common(&nation.country),
                    consortium_members: nation
                        .diplomacy_save_fields
                        .map(minor_nation_id_from_retail_i16),
                    trade: minor_trade_state(nation),
                },
            );
            military_units.extend(nation.country.military_unit_states(nation_id));
        }

        // The retail load path restores this counter before deserializing units.
        // Every TUnit constructor increments it once, even though ReadFrom then
        // replaces the unit's generated ID with the persisted ID.
        let loaded_unit_count = (military_units.len() + civilian_units.len()) as i32;
        let persistent_unit_id_counter =
            self.simulation.persistent_unit_id_counter + loaded_unit_count;

        GameStateParts {
            turn: TurnState::new(
                (self.simulation.game_setup.scenario_map_index_plus_one > 0).then(|| {
                    ScenarioMapId::new(
                        (self.simulation.game_setup.scenario_map_index_plus_one - 1) as u16,
                    )
                }),
                i32::from(self.simulation.economic_turn),
                self.simulation.diplomacy_year_term_raw,
                PhaseCode::from_retail(i32::from(self.simulation.turn_state_code)),
                self.simulation.turn_flow_status_flags,
                DecadeTable::from_array(std::array::from_fn(|index| {
                    self.simulation.phase_state_by_decade[index] != 0
                })),
                Difficulty::try_from(self.simulation.difficulty).expect("retail difficulty"),
                nation_id_from_retail_i16(self.simulation.active_nation),
                context.selected_nation,
            ),
            unit_ids: UnitIdAllocator::from_retail(persistent_unit_id_counter),
            map,
            map_view_origin,
            ocean,
            rng: RngState {
                crt_rand: RetailCrtRng::from_state(context.crt_rand_state),
                map_generation: RetailLcg::from_state(context.map_generation_lcg),
                zone_status: RetailLcg::from_state(context.zone_status_lcg),
            },
            market: trade_market_state(&self.market),
            technology: technology_state(&self.technology),
            diplomacy: diplomacy_state(&self.diplomacy),
            nations: Nations::new(majors, minors),
            military_units,
            civilian_units,
            object_ids,
            ships,
            admirals,
            task_forces,
            missions,
            news: NewsState::default(),
            pending,
            battle_reports: battle_reports(&self.army_reports),
            continuation: TurnContinuation::default(),
        }
    }

    pub fn game_state(&self, context: LegacyGameStateContext) -> GameState {
        GameState::from_parts(self.game_state_parts(context))
    }
}

fn diplomacy_notices(list: &LegacyFixedRecordList) -> Vec<DiplomacyNotice> {
    relationship_records(list)
        .into_iter()
        .map(|(code, source)| DiplomacyNotice { source, code })
        .collect()
}

fn diplomacy_proposals(list: &LegacyFixedRecordList) -> Vec<DiplomacyProposal> {
    relationship_records(list)
        .into_iter()
        .map(|(entry, source)| DiplomacyProposal {
            source,
            policy: diplomacy_policy_from_retail(entry),
        })
        .collect()
}

fn relationship_records(list: &LegacyFixedRecordList) -> Vec<(i16, NationId)> {
    let mut records = list
        .records
        .iter()
        .map(|record| {
            let value = i16::from_le_bytes([record[0], record[1]]);
            let source = nation_id_from_retail_i16(i16::from_le_bytes([record[2], record[3]]));
            (value, source)
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|(_, source)| *source);
    records
}

fn deal_book_state(
    lists: &[LegacyFixedRecordList; TRADE_CATEGORY_COUNT],
) -> TradeCommodityTable<Vec<TradeDealBookEntry>> {
    TradeCommodityTable::from_array(lists.each_ref().map(deal_book_entries))
}

fn deal_book_entries(list: &LegacyFixedRecordList) -> Vec<TradeDealBookEntry> {
    let mut entries = list
        .records
        .iter()
        .map(|record| {
            let nation_raw = i16::from_le_bytes([record[2], record[3]]);
            let nation = nation_id_from_retail_i16(nation_raw);
            let amount = i16::from_le_bytes([record[4], record[5]]);
            TradeDealBookEntry {
                kind: deal_book_entry_kind_from_retail(i16::from_le_bytes([record[0], record[1]])),
                nation,
                amount,
                unit_price: i32::from_le_bytes([record[8], record[9], record[10], record[11]]),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.nation);
    entries
}

fn ai_zone_targets(flags: &[u8; AI_ZONE_TARGET_CAPACITY], live_count: usize) -> Vec<AiTargetState> {
    flags[..live_count]
        .iter()
        .copied()
        .map(ai_target_from_retail)
        .collect()
}

fn ai_province_targets(flags: &[u8; PROVINCE_COUNT]) -> ProvinceTable<AiTargetState> {
    ProvinceTable::from_array(std::array::from_fn(|index| {
        ai_target_from_retail(flags[index])
    }))
}

fn ocean_state(ocean: &LegacyOceanState, map: &MapMgr) -> Ocean {
    let live_count = ocean.zones.len() + ocean.port_zones.len();
    let mut zones = vec![None; live_count];

    for context in &ocean.zones {
        let ordinal = context.context_ordinal as usize;
        zones[ordinal] = Some(ZoneKind::Zone(zone_state(context)));
    }
    for context in &ocean.port_zones {
        let ordinal = context.zone.context_ordinal as usize;
        let port_tile = optional_tile_id(i32::from(context.port_tile_index))
            .expect("retail port-zone tile is present");
        zones[ordinal] = Some(ZoneKind::PortZone(PortZone {
            zone: zone_state(&context.zone),
            port_tile,
        }));
    }

    let zones = zones
        .into_iter()
        .map(|zone| zone.expect("retail ocean context ordinals are contiguous"))
        .collect();
    let routes = ocean
        .route_segments
        .iter()
        .map(
            |&[start_row, start_column, end_row, end_column]| OceanRoute {
                start_column,
                start_row,
                end_column,
                end_row,
            },
        )
        .collect();
    let mut ocean = Ocean { zones, routes };
    rebuild_ocean_neighbors(&mut ocean, map);
    ocean
}

fn zone_state(context: &LegacyZone) -> Zone {
    let seed_owner = match context.seed_nation_id {
        -1 => None,
        value => Some(TileOwnerTag::new(value as u8)),
    };
    Zone {
        display_name: context.display_name.clone(),
        status_code: (context.status_code != -1).then_some(context.status_code),
        target_tile: optional_tile_id(context.tile_or_terrain_id),
        seed_owner,
        active_tile: optional_tile_id(i32::from(context.active_tile_index)),
        primary_neighbors: Vec::new(),
        secondary_neighbors: Vec::new(),
    }
}

fn rebuild_ocean_neighbors(ocean: &mut Ocean, map: &MapMgr) {
    let geometry = map.geometry();
    for tile in TileId::all() {
        let Some(zone_index) = ocean_zone_for_tile(ocean, map, tile) else {
            continue;
        };
        if matches!(ocean.zones[zone_index], ZoneKind::PortZone(_)) {
            let has_primary = match &ocean.zones[zone_index] {
                ZoneKind::PortZone(port) => !port.zone.primary_neighbors.is_empty(),
                ZoneKind::Zone(_) => unreachable!(),
            };
            if has_primary {
                continue;
            }
            let target_tile = match &ocean.zones[zone_index] {
                ZoneKind::PortZone(port) => port.zone.target_tile,
                ZoneKind::Zone(_) => unreachable!(),
            }
            .expect("retail port zone has a target tile");
            let owner = map[target_tile]
                .owner_nation
                .map(TileOwnerTag::get)
                .filter(|&owner| owner >= 0x17)
                .expect("retail port-zone target tile has a base ocean zone");
            let base_index = usize::from(owner - 0x17);
            let port_id = OceanZoneId::new(zone_index as u16);
            let base_id = OceanZoneId::new(base_index as u16);
            let ZoneKind::PortZone(port) = &mut ocean.zones[zone_index] else {
                unreachable!()
            };
            port.zone.primary_neighbors.push(base_id);
            let ZoneKind::Zone(base) = &mut ocean.zones[base_index] else {
                unreachable!()
            };
            base.primary_neighbors.push(port_id);
            continue;
        }

        for neighbor in geometry.neighbors(tile).into_iter().flatten() {
            if let Some(province) = map[neighbor].province {
                let ZoneKind::Zone(zone) = &mut ocean.zones[zone_index] else {
                    unreachable!()
                };
                if !zone.secondary_neighbors.contains(&province) {
                    zone.secondary_neighbors.push(province);
                }
                continue;
            }
            let Some(candidate) = ocean_zone_for_tile(ocean, map, neighbor) else {
                continue;
            };
            if candidate == zone_index || matches!(ocean.zones[candidate], ZoneKind::PortZone(_)) {
                continue;
            }
            let candidate = OceanZoneId::new(candidate as u16);
            let ZoneKind::Zone(zone) = &mut ocean.zones[zone_index] else {
                unreachable!()
            };
            if !zone.primary_neighbors.contains(&candidate) {
                zone.primary_neighbors.push(candidate);
            }
        }
    }
}

fn ocean_zone_for_tile(ocean: &Ocean, map: &MapMgr, tile: TileId) -> Option<usize> {
    if map[tile]
        .action
        .is_some_and(|action| matches!(action.retail(), 3 | 14))
    {
        return ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(ordinal, zone)| match zone {
                ZoneKind::PortZone(port)
                    if port.port_tile == tile
                        || port.zone.target_tile == Some(tile)
                        || port.zone.active_tile == Some(tile) =>
                {
                    Some(ordinal)
                }
                _ => None,
            });
    }
    let ordinal = map[tile]
        .owner_nation
        .map(TileOwnerTag::get)?
        .checked_sub(0x17)?;
    let ordinal = usize::from(ordinal);
    matches!(ocean.zones.get(ordinal), Some(ZoneKind::Zone(_))).then_some(ordinal)
}

fn foreign_minister_personality(
    nation: &LegacyMajorNationState,
    setup_policy_id: i16,
) -> ForeignMinisterPersonality {
    foreign_minister_personality_from_retail(
        matches!(nation, LegacyMajorNationState::Auto(_)),
        setup_policy_id,
    )
}

fn trade_commodity_from_retail(value: i16) -> TradeCommodity {
    TradeCommodity::from_retail(value).expect("retail trade commodity")
}

fn optional_trade_commodity_from_retail(value: i16) -> Option<TradeCommodity> {
    if value == -10 {
        return None;
    }
    Some(trade_commodity_from_retail(value))
}

fn foreign_trade_state(minister: &LegacyForeignMinisterState) -> ForeignTradeState {
    let interior_bid =
        optional_trade_commodity_from_retail(minister.scalar_fields[0]).map(|commodity| {
            ForeignTradeBid {
                commodity,
                amount: minister.scalar_fields[1],
            }
        });
    let requested_ship = match minister.scalar_fields[6] {
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        value => panic!("unrecovered foreign-minister ship order kind {value}"),
    };
    let preferred_resources = minister
        .preferred_resource_slots
        .map(optional_trade_commodity_from_retail);
    ForeignTradeState {
        interior_bid,
        phase_counter: minister.scalar_fields[4],
        refresh_interval: minister.scalar_fields[5],
        requested_ship,
        purchase_priority: TradeCommodityTable::from_array(minister.purchase_priority_by_resource),
        preferred_resources,
        capability_flag_14: minister.scalar_fields[2],
        capability_flag_16: minister.scalar_fields[3],
        trade_partner_enabled: TradePartnerCommodityTable::from_array(
            minister.trade_partner_enabled.map(|flag| flag != 0),
        ),
    }
}

fn pending_ship(minister: &LegacyInteriorMinisterState) -> Option<ShipType> {
    match minister.order_scalars[1] {
        0 => None,
        1 => Some(ShipType::Trader),
        2 => Some(ShipType::Indiaman),
        value => panic!("unrecovered pending ship type {value}"),
    }
}

fn minor_trade_state(nation: &LegacyMinorState) -> MinorTradeState {
    MinorTradeState {
        current_supply: ResourceTable::from_array(nation.need_current_by_type),
        offers: ResourceTable::from_array(nation.trade_offers_by_resource),
        grant_deltas: ResourceTable::from_array(nation.grant_amounts_by_resource),
        thresholds: MinorTradeThresholds {
            primary_manufactured_price: nation.diplomacy_thresholds[0],
            secondary_manufactured_price: nation.diplomacy_thresholds[1],
            general_offer_price: nation.diplomacy_thresholds[2],
            random_offer_price: nation.diplomacy_thresholds[3],
            coal_offer_price: nation.diplomacy_thresholds[4],
            iron_offer_price: nation.diplomacy_thresholds[5],
            oil_offer_price: nation.diplomacy_thresholds[6],
        },
        primary_manufactured_request: optional_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[0],
        ),
        secondary_manufactured_request: optional_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[1],
        ),
        primary_request_fulfilled: nation.diplomacy_policy_fields[2],
        secondary_request_fulfilled: nation.diplomacy_policy_fields[3],
        independent_resource_counts: ResourceTable::from_array(nation.diplomacy_save_extension),
    }
}

fn great_power_state(
    nation: &LegacyGreatPowerState,
    foreign_minister_personality: ForeignMinisterPersonality,
) -> GreatPowerState {
    let prefix = &nation.prefix;
    let post = &nation.post_city;
    let foreign_minister = nation
        .ministers
        .foreign
        .as_ref()
        .expect("retail great power has a foreign minister");
    let defense_minister = nation
        .ministers
        .defense
        .as_ref()
        .expect("retail great power has a defense minister");
    let interior_minister = nation
        .ministers
        .interior
        .as_ref()
        .expect("retail great power has an interior minister");
    GreatPowerState {
        diplomacy_eligible: prefix.diplomacy_eligible != 0,
        foreign_minister_personality,
        foreign_minister_skill_index: foreign_minister.skill_index,
        foreign_trade: foreign_trade_state(foreign_minister),
        development_grant_by_nation: NationTable::from_array(
            foreign_minister.development_grant_by_nation,
        ),
        defense_minister_skill_index: defense_minister.skill_index,
        capacities: NationCapacities::from_array(prefix.capacities),
        grant_total_cost: prefix.grant_total_cost,
        unfilled_trade_offer_count: prefix.unfilled_trade_offer_count,
        diplomacy_policy_by_nation: diplomacy_policies_from_retail_entries(
            prefix.diplomacy_policy_by_nation,
        ),
        diplomacy_grants_by_nation: diplomacy_grants_from_retail_entries(
            prefix.diplomacy_grant_by_nation,
        ),
        need_current_by_type: ResourceTable::from_array(prefix.need_current_by_type),
        need_target_by_type: ResourceTable::from_array(prefix.need_target_by_type),
        relation_delta_current: ResourceTable::from_array(prefix.relation_delta_current),
        purchased_items_by_resource: ResourceTable::from_array(prefix.purchased_items_by_resource),
        item_potentials: ResourceTable::from_array(prefix.item_potentials),
        unfilled_trade_turns_by_resource: ResourceTable::from_array(
            prefix.unfilled_trade_turns_by_resource,
        ),
        transported_items_by_resource: ResourceTable::from_array(
            prefix.transported_items_by_resource,
        ),
        remembered_trade_offers_by_resource: ResourceTable::from_array(
            prefix.remembered_trade_offers_by_resource,
        ),
        deal_book: deal_book_state(&prefix.diplomacy_tracked_slots),
        pending_ship: pending_ship(interior_minister),
        interior_civilian: Box::new(interior_civilian_state(interior_minister)),
        aid_allocation_by_minor_nation: MinorNationTable::from_array(
            prefix
                .aid_allocation_by_minor_nation
                .map(ResourceTable::from_array),
        ),
        budget_pool_base: prefix.budget_pool_base,
        budget_pool_delta: prefix.budget_pool_delta,
        special_resource_trade_balance: post.special_resource_trade_balance,
        // scenarioInitFlag is constructed as zero and is not part of the save stream.
        scenario_initialized: false,
        turn_finished: post.turn_finished_flag != 0,
        pending_actions: PendingActionTable::from_array(std::array::from_fn(|action| {
            pending_action_from_retail(
                prefix.pending_action_status[action],
                prefix.pending_action_payload_by_action[action],
            )
        })),
        candidate_nation_flags: NationTable::from_array(post.candidate_nation_flags),
        colony_boycott_flags: NationTable::from_array(post.colony_boycott_flags),
        diplomacy_budget_base: post.diplomacy_budget_base,
        escalation_counter: i16::from(post.escalation_counter),
        pending_commitment_cost: post.pending_commitment_cost,
        pressure_counter: i16::from(post.pressure_counter),
        army_movement_budget: post.army_movement_budget,
        aid_allocation_total: post.aid_allocation_total,
        military_expenses: post.military_expenses,
    }
}

fn interior_civilian_state(minister: &LegacyInteriorMinisterState) -> InteriorCivilianState {
    let pending_recruitment = match minister.order_scalars[3] {
        -1 => None,
        value => Some(
            CivilianUnitKind::from_index(value as u8)
                .expect("retail pending civilian recruitment kind"),
        ),
    };
    let resource_order_metrics =
        ResourceTable::from_array(std::array::from_fn(|index| minister.order_metrics[index]));
    let city_order_demand = AiCityOrderDemand::from_parts(
        TrainingOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[23 + index]
        })),
        MilitaryRecruitOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[25 + index]
        })),
        CivilianUnitTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[34 + index]
        })),
        ShipOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[43 + index]
        })),
        minister.order_metrics[51],
        ExpansionOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[53 + index]
        })),
        minister.order_metrics[60],
    );
    let pending_development_actions = minister.integer_lists[2]
        .iter()
        .map(|&value| match value {
            0..=29 => PendingDevelopmentAction::LandUnit {
                unit_type: MilitaryUnitKind::from_index(value as u8)
                    .expect("retail pending military development action"),
            },
            30..=43 => PendingDevelopmentAction::Industry {
                slot: CityFacilitySlot::from_index(
                    u8::try_from(value - 30).expect("retail city facility slot fits u8"),
                )
                .expect("retail pending industry development action"),
            },
            _ => panic!("unrecovered pending development action {value}"),
        })
        .collect();
    InteriorCivilianState::from_parts(
        pending_recruitment,
        optional_tile_id(i32::from(minister.order_scalars[6])),
        resource_order_metrics,
        city_order_demand,
        minister.deferred_labor_shortfall,
        ProductionTable::from_array(minister.order_short_table),
        minister.temporarily_reserved_ship_arms,
        ResourceTable::from_array(minister.order_type_tables[0]),
        ResourceTable::from_array(minister.order_type_tables[1]),
        ResourceTable::from_array(minister.order_type_tables[2]),
        ResourceTable::from_array(minister.civilian_order_demand_by_resource),
        // Retail constructs this transient table as zero and does not deserialize it.
        // The city-and-transport phase rebuilds it only after this loaded-save turn slice.
        0,
        pending_development_actions,
    )
}

fn pending_action_from_retail(status: i8, payload: i16) -> PendingActionState {
    PendingActionState::new(
        PendingActionStatus::from_retail(status),
        (payload != -1).then_some(payload),
    )
}

fn diplomacy_grants_from_retail_entries(
    entries: [i16; NATION_COUNT],
) -> NationTable<Option<DiplomacyGrant>> {
    NationTable::from_array(entries.map(|entry| {
        if entry == -1 {
            None
        } else {
            Some(DiplomacyGrant {
                amount: i32::from(entry & 0x3fff),
                recurring: entry & 0x4000 != 0,
            })
        }
    }))
}

fn diplomacy_policies_from_retail_entries(
    entries: [i16; NATION_COUNT],
) -> NationTable<Option<DiplomacyPolicy>> {
    NationTable::from_array(entries.map(|entry| match entry {
        -1 => None,
        _ => Some(diplomacy_policy_from_retail(entry)),
    }))
}

fn diplomacy_policy_from_retail(entry: i16) -> DiplomacyPolicy {
    match entry {
        0x12d => DiplomacyPolicy::JoinEmpire,
        0x12e => DiplomacyPolicy::Alliance,
        0x12f => DiplomacyPolicy::NonAggressionPact,
        0x130 => DiplomacyPolicy::PeaceTreaty,
        0x131 => DiplomacyPolicy::DeclareWar,
        0x132 => DiplomacyPolicy::JoinEmpireWithWarEntanglements,
        0x133 => DiplomacyPolicy::BuildConsulate,
        0x134 => DiplomacyPolicy::BuildEmbassy,
        _ => panic!("unrecovered diplomacy policy {entry:#06x}"),
    }
}

fn owned_region_id_from_retail(value: i32) -> ProvinceId {
    ProvinceId::new(value as u16)
}

fn province_state(province: &LegacyProvince) -> ProvinceState {
    let count = province.adjacent_region_count as usize;
    let adjacency = province.adjacent_region_ids[..count]
        .iter()
        .copied()
        .map(|value| ProvinceId::new(value as u16))
        .collect();
    let adjacency_anchor_tiles = province.adjacent_region_anchor_tiles[..count]
        .iter()
        .copied()
        .map(|value| {
            optional_tile_id(i32::from(value)).expect("retail adjacency anchor tile is present")
        })
        .collect();
    let linked_count = province.linked_region_count as usize;
    let linked_tiles = province.linked_tile_indices[..linked_count]
        .iter()
        .copied()
        .map(|value| optional_tile_id(i32::from(value)).expect("retail linked tile is present"))
        .collect();

    let optional_owner = |value: i8| {
        if value == -1 {
            return None;
        }
        Some(NationId::new(value as u8))
    };
    let region_class = match province.region_class {
        -1 => None,
        value => Some(value as u8),
    };
    let mut resource_development_by_type = ResourceTable::default();
    for (offset, amount) in province
        .resource_development_by_type
        .iter()
        .copied()
        .enumerate()
    {
        let resource = ResourceKind::from_index(
            ResourceKind::Food.retail()
                + u8::try_from(offset).expect("province resource-development index fits u8"),
        )
        .expect("province resource-development table spans food through arms");
        resource_development_by_type[resource] = amount;
    }
    let explored_by_majors = MajorNationTable::from_fn(|nation| {
        province.explored_by_nation_mask & (1 << nation.get()) != 0
    });

    ProvinceState::new(
        optional_owner(province.owner_nation),
        optional_owner(province.former_owner_nation),
        ProvinceDevelopmentStage::from_retail(province.development_stage)
            .expect("retail province development stage"),
        adjacency,
        adjacency_anchor_tiles,
        region_class,
        FortLevel::from_retail(province.fort_level).expect("retail province fort level"),
        optional_tile_id(i32::from(province.city_tile)),
        province.last_turn_tick,
        optional_tile_id(i32::from(province.secondary_neighbor_tile)),
        optional_tile_id(i32::from(province.primary_neighbor_tile)),
        linked_tiles,
        resource_development_by_type,
        explored_by_majors,
        province.city_score,
        province.navy_order_reachable != 0,
        province.resource_presence_mask,
        province.name.clone(),
    )
}

fn country_common(country: &LegacyCountryBase) -> NationCommonState {
    let mut common = NationCommonState::from_parts(
        normalize_nation_display_name(&country.alternate_identity),
        country_status_from_retail(country.encoded_country_status),
        country
            .owned_regions
            .iter()
            .copied()
            .map(owned_region_id_from_retail)
            .collect(),
        country.treasury,
        optional_tile_id(country.home_tile),
        NationTable::from_array(
            country
                .need_level_by_nation
                .map(|score| TradePolicyScore::new(i32::from(score))),
        ),
    );
    common.unit_name_ordinal_by_type =
        MilitaryUnitTable::from_array(country.unit_name_ordinal_by_type);
    common.unit_name_counter = country.unit_name_counter;
    common
}

fn battle_reports(reports: &[LegacyBattleReport]) -> Vec<BattleReport> {
    reports
        .iter()
        .filter_map(|report| {
            let kind = BattleReportKind::from_retail(report.kind)?;
            let location = if kind.is_land() {
                BattleReportLocation::Province(ProvinceId::try_new(report.node_id as u16)?)
            } else {
                BattleReportLocation::Zone(OceanZoneId::new(report.node_id as u16))
            };
            let [left, right] = &report.sides;
            Some(BattleReport {
                participant: BattleReportSideSlot::from_retail(report.participant_index)?,
                displayed_participant: BattleReportSideSlot::from_retail(
                    report.displayed_participant,
                )?,
                kind,
                location,
                sides: BattleReportSideTable::from_array([left, right].map(|side| {
                    BattleReportSide {
                        nation: NationId::try_new(side.nation).unwrap_or(NationId::new(0)),
                        name: side.name.clone(),
                        overlay: side.overlay.clone(),
                        children: side
                            .children
                            .iter()
                            .map(|child| BattleReportUnit {
                                kind: match kind {
                                    BattleReportKind::LandBattle
                                    | BattleReportKind::PreemptedLandBattle
                                    | BattleReportKind::UncontestedTakeover => {
                                        BattleReportUnitKind::Military(
                                            MilitaryUnitKind::from_index(
                                                u8::try_from(child.resource_type)
                                                    .expect("retail military report type"),
                                            )
                                            .expect("retail military report type"),
                                        )
                                    }
                                    BattleReportKind::SeaBattle => BattleReportUnitKind::Ship(
                                        ShipType::from_index(
                                            u8::try_from(child.resource_type)
                                                .expect("retail ship report type"),
                                        )
                                        .expect("retail ship report type"),
                                    ),
                                    BattleReportKind::MerchantInterception => {
                                        BattleReportUnitKind::Resource(
                                            ResourceKind::from_index(
                                                u8::try_from(child.resource_type)
                                                    .expect("retail merchant report type"),
                                            )
                                            .expect("retail merchant report type"),
                                        )
                                    }
                                },
                                stock_or_required: child.stock_or_required,
                                name: child.name.clone(),
                                strength_bucket: child.strength_bucket,
                                detail_identity: child.detail_identity,
                            })
                            .collect(),
                    }
                })),
            })
        })
        .collect()
}
