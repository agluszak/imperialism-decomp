mod city;
mod diplomacy;
mod map;
mod military;
mod nations;
mod technology;
mod units;

use super::model::*;
use super::*;
use city::town_state;
use diplomacy::{diplomacy_dto, diplomacy_notices, diplomacy_proposals, diplomacy_state};
use enum_map::Enum;
use imperialism_core::*;
use map::{map_dto, ocean_dto, ocean_state};
use nations::{
    ai_province_targets, ai_zone_targets, country_common, foreign_minister_personality,
    foreign_policy_id, great_power_state, major_nation_dto, minor_nation_dto, minor_trade_state,
};
use technology::{technology_dto, technology_state};
use units::{admiral_states, navy_dto, ship_states};

pub(super) use nations::country_status_from_retail;

fn optional_region_id(value: i8) -> Option<RegionId> {
    (value != -1).then(|| RegionId::new(value as u8))
}

fn optional_resource_kind(value: i8) -> Option<ResourceKind> {
    (value != -1).then(|| ResourceKind::from_index(value as u8).expect("retail resource kind"))
}

fn optional_tile_owner_tag(value: i8) -> Option<TileOwnerTag> {
    (value != -1).then(|| TileOwnerTag::new(value as u8))
}

fn optional_major_nation_id(value: i8) -> Option<MajorNationId> {
    (value != -1).then(|| MajorNationId::new(value as u8))
}

fn optional_province_id(value: i16) -> Option<ProvinceId> {
    (value != -1).then(|| ProvinceId::new(value as u16))
}

fn optional_province_array(values: [i16; 3]) -> [Option<ProvinceId>; 3] {
    values.map(optional_province_id)
}

fn optional_ocean_zone_id(value: i16) -> Option<OceanZoneId> {
    (value != -1).then(|| OceanZoneId::new(value as u16))
}

fn optional_nation_id(value: i16) -> Option<NationId> {
    (value != -1).then(|| nation_id_from_retail_i16(value))
}

fn optional_tile_id(value: i32) -> Option<TileId> {
    (value != -1).then(|| TileId::new(value as u16))
}

fn nation_id_from_retail_i16(value: i16) -> NationId {
    NationId::new(value as u8)
}

fn minor_nation_id_from_retail_i16(value: i16) -> MinorNationId {
    MinorNationId::new(value as u8)
}

fn option_i8(value: Option<u8>) -> i8 {
    value.map(|value| value as i8).unwrap_or(-1)
}

fn option_i16(value: Option<u16>) -> i16 {
    value.map(|value| value as i16).unwrap_or(-1)
}

fn option_i32(value: Option<u16>) -> i32 {
    value.map(i32::from).unwrap_or(-1)
}

fn resource_i16<T: Copy + Into<i16>>(table: &ResourceTable<T>) -> [i16; RESOURCE_KIND_COUNT] {
    std::array::from_fn(|index| {
        table[ResourceKind::from_index(index as u8).expect("resource index")].into()
    })
}

fn resource_i16_from_stockpile(stockpile: &Stockpile) -> [i16; RESOURCE_KIND_COUNT] {
    std::array::from_fn(|index| {
        stockpile[ResourceKind::from_index(index as u8).expect("resource index")]
    })
}

fn resource_i32(table: &ResourceTable<i32>) -> [i32; RESOURCE_KIND_COUNT] {
    std::array::from_fn(|index| {
        table[ResourceKind::from_index(index as u8).expect("resource index")]
    })
}

fn enum_i16<K: Enum + Copy, const N: usize>(table: &enum_map::EnumMap<K, i16>) -> [i16; N] {
    std::array::from_fn(|index| table[K::from_usize(index)])
}

fn enum_u8<K: Enum + Copy, const N: usize>(table: &enum_map::EnumMap<K, bool>) -> [u8; N] {
    std::array::from_fn(|index| u8::from(table[K::from_usize(index)]))
}

fn nation_i16_table<T: Copy>(
    table: &NationTable<T>,
    map: impl Fn(T) -> i16,
) -> [i16; NATION_COUNT] {
    std::array::from_fn(|index| map(table.as_array()[index]))
}

fn flatten_nation_pairs<T: Copy, U: Copy>(
    table: &NationTable<NationTable<T>>,
    map: impl Fn(T) -> U,
) -> [U; NATION_COUNT * NATION_COUNT] {
    std::array::from_fn(|index| {
        let source = NationId::new((index / NATION_COUNT) as u8);
        let target = NationId::new((index % NATION_COUNT) as u8);
        map(table[source][target])
    })
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

fn trade_commodity_i16(commodity: TradeCommodity) -> i16 {
    commodity.into_usize() as i16
}

fn optional_commodity_i16(commodity: Option<TradeCommodity>) -> i16 {
    commodity.map(trade_commodity_i16).unwrap_or(-10)
}

fn empty_records() -> LegacyFixedRecordList {
    LegacyFixedRecordList {
        record_size: 0,
        records: Vec::new(),
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

fn market_dto(market: &TradeMarketState) -> LegacyTradeMarketState {
    LegacyTradeMarketState {
        rows: std::array::from_fn(|index| {
            let row = &market.rows[TradeCommodity::from_usize(index)];
            LegacyTradeMarketRow {
                previous_price: row.previous_price as i16,
                price: row.price as i16,
                request_count: row.request_count as i16,
                offer_count: row.offer_count as i16,
                adjusted_offer_count: row.adjusted_offer_count,
                amount_offered: row.amount_offered as i16,
                base_price: row.base_price as i16,
                current_offer_by_nation: *row.current_offer_by_nation.as_array(),
                accumulated_offer_by_nation: *row.accumulated_offer_by_nation.as_array(),
                maximum_offer_by_nation: *row.maximum_offer_by_nation.as_array(),
            }
        }),
        history: std::array::from_fn(|_| empty_records()),
    }
}

impl LegacySaveV62 {
    /// Projects persistable save fields into construction parts. Runtime-only RNG and
    /// selection state must be supplied because the retail stream does not contain them.
    pub fn game_state_parts(&self, context: LegacyGameStateContext) -> GameStateParts {
        assert!(
            self.navy.task_forces.is_empty(),
            "semantic projection of retail navy task forces is not implemented"
        );

        let ships = ship_states(&self.navy);
        let admirals = admiral_states(&self.navy, ships.len());

        let mut minors = MinorNationTable::default();
        let mut military_units = Vec::new();
        let mut civilian_units = Vec::new();
        let mut missions = Vec::new();
        let mut pending = PendingWorkState {
            combat_reports_pending: self.army_report_count != 0,
            ..PendingWorkState::default()
        };
        let map = self.map.map_mgr();
        let map_view_origin = TileId::new(self.map.view_origin_tile as u16);
        let ocean = ocean_state(&self.ocean, &map);
        let live_ocean_context_count = ocean.zones.len();
        let majors = MajorNationTable::from_array(std::array::from_fn(|slot| {
            let major_id = MajorNationId::new(slot as u8);
            let nation_id = major_id.nation();
            let nation = &self.major_nations[slot];
            let great_power = nation.great_power();
            let city = great_power
                .city
                .as_ref()
                .expect("retail great power has a city");
            let towns = great_power.post_city.towns.iter().map(town_state).collect();
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
                    missions.push(
                        mission.mission_state(nation_id, &great_power.country.military_units),
                    );
                }
            }
            pending.nations[major_id].turn_events =
                diplomacy_notices(&great_power.prefix.turn_event_queue);
            pending.nations[major_id].proposals =
                diplomacy_proposals(&great_power.prefix.proposal_queue);
            major
        }));
        for nation in &self.minor_nations {
            let nation_id = NationId::new(nation.country.nation_slot as u8);
            let minor_id = MinorNationId::new(nation_id.get());
            minors[minor_id] = Some(MinorNation {
                common: country_common(&nation.country),
                consortium_members: nation
                    .diplomacy_save_fields
                    .map(minor_nation_id_from_retail_i16),
                trade: minor_trade_state(nation),
            });
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
                std::array::from_fn(|index| self.simulation.phase_state_by_decade[index]),
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
            ships,
            admirals,
            task_forces: Vec::new(),
            missions,
            news: NewsState::default(),
            pending,
            continuation: TurnContinuation::default(),
        }
    }

    pub fn game_state(&self, context: LegacyGameStateContext) -> GameState {
        GameState::from_parts(self.game_state_parts(context))
    }

    pub fn from_game_state(state: &GameState, label: &str, session_slot: i32) -> Self {
        let turn = state.turn();
        let loaded_unit_count =
            (state.military_units().len() + state.civilian_units().len()) as i32;
        let mut nation_availability = [0_u8; NATION_COUNT];
        let mut nation_control_modes = [0_i16; MAJOR_NATION_COUNT];
        let mut foreign_minister_policy_ids = [0_i16; MAJOR_NATION_COUNT];
        let mut nation_names = vec![String::new(); NATION_COUNT];
        let mut major_nations = Vec::with_capacity(MAJOR_NATION_COUNT);
        let mut minor_nations = Vec::new();

        for slot in 0..MAJOR_NATION_COUNT {
            let major_id = MajorNationId::new(slot as u8);
            let nation = state.nations().major(major_id);
            nation_availability[slot] = 1;
            nation_names[slot] = nation.common.display_name.clone();
            nation_control_modes[slot] = if nation.auto.is_some() { 2 } else { 0 };
            foreign_minister_policy_ids[slot] =
                foreign_policy_id(nation.economy.foreign_minister_personality);
            let military = state
                .military_units()
                .iter()
                .filter(|unit| unit.nation() == major_id.nation())
                .cloned()
                .collect::<Vec<_>>();
            let civilians = state
                .civilian_units()
                .iter()
                .filter(|unit| unit.nation() == major_id.nation())
                .cloned()
                .collect::<Vec<_>>();
            let missions = state
                .missions()
                .iter()
                .filter(|mission| mission.nation == major_id.nation())
                .cloned()
                .collect::<Vec<_>>();
            let pending = &state.pending().nations[major_id];
            major_nations.push(major_nation_dto(
                nation,
                major_id,
                &military,
                &civilians,
                &missions,
                pending,
                state.map().topology,
            ));
        }

        for index in 0..MINOR_NATION_COUNT {
            let minor_id = MinorNationId::new(MajorNationId::COUNT + index as u8);
            let Some(minor) = state.nations().minor(minor_id) else {
                continue;
            };
            let slot = usize::from(minor_id.get());
            nation_availability[slot] = 1;
            nation_names[slot] = minor.common.display_name.clone();
            let military = state
                .military_units()
                .iter()
                .filter(|unit| unit.nation() == minor_id.nation())
                .cloned()
                .collect::<Vec<_>>();
            minor_nations.push(minor_nation_dto(minor, minor_id, &military));
        }

        let active_name = state
            .nations()
            .display_name(turn.active_nation)
            .unwrap_or("")
            .to_owned();
        let header = LegacySaveHeader {
            format_version: super::slots::SAVE_FORMAT_VERSION,
            saved_session_slot: session_slot,
            save_label: super::slots::normalize_save_label(label),
            preview_owner_nation_by_tile: state
                .map()
                .tiles
                .iter()
                .map(|tile| option_i8(tile.owner_nation.map(TileOwnerTag::get)))
                .collect(),
            preview_economic_year_offset: turn.economic_turn as i16,
            preview_difficulty: turn.difficulty as u8,
            preview_active_nation: turn.active_nation.get(),
            preview_active_nation_name: active_name,
        };

        let mut phase_state_by_decade = [0_u8; 12];
        phase_state_by_decade[..10].copy_from_slice(&turn.quarter_gate_by_decade);

        let simulation = LegacySimulationPrefix {
            language_code: 0,
            economic_turn: turn.economic_turn as i16,
            active_nation: i16::from(turn.active_nation.get()),
            turn_state_code: turn.phase().retail() as i16,
            mode: 0,
            previous_turn_state_code: 0,
            previous_mode: 0,
            nation_count: state
                .nations()
                .majors()
                .filter(|major| matches!(major.common.status(), CountryStatus::Independent))
                .count() as i32,
            minor_nation_count: MINOR_NATION_COUNT as i32,
            turn_flow_status_flags: turn.turn_flow_status_flags,
            difficulty: turn.difficulty as u8,
            game_setup: LegacyGameSetup {
                multiplayer_game_active: 0,
                nation_control_modes,
                city_minister_policy_ids: [0; MAJOR_NATION_COUNT],
                foreign_minister_policy_ids,
                defense_minister_policy_ids: [0; MAJOR_NATION_COUNT],
                reload_political_map_state: 0,
                scenario_map_index_plus_one: turn
                    .scenario_map
                    .map(|id| id.index() as i16 + 1)
                    .unwrap_or(0),
            },
            persistent_unit_id_counter: state.unit_ids().current() - loaded_unit_count,
            nation_availability,
            saved_multiplayer_role: 0,
            preference_slot_10: 0,
            selected_asset_set: 0,
            diplomacy_year_term_raw: turn.diplomacy_year_term_raw,
            phase_state_by_decade,
            nation_names,
        };

        Self {
            header,
            simulation,
            animator_idle_frequency: 0,
            market: market_dto(state.market()),
            diplomacy: diplomacy_dto(state.diplomacy()),
            technology: technology_dto(state.technology()),
            map: map_dto(state.map(), state.map_view_origin()),
            ocean: ocean_dto(state.ocean()),
            navy: navy_dto(state),
            army_report_count: u16::from(state.pending().combat_reports_pending),
            major_nations,
            minor_nations,
            help: LegacyHelpState {
                index_records: empty_records(),
                civilian_completion_counters: [0; 5],
                help_index_ready: 0,
            },
        }
    }
}
