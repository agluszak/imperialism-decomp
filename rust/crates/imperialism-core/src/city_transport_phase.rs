//! City and transport resolution (`TSimMgr::DoCityAndTransport`).

use crate::create_random_game::{name_units_for_nation, resource_capability_requirement_level};
use crate::*;

const COMPILE_DELTA_RESOURCE_ORDER: [ResourceKind; 17] = [
    ResourceKind::Hardware,
    ResourceKind::Furniture,
    ResourceKind::Clothing,
    ResourceKind::Arms,
    ResourceKind::Fuel,
    ResourceKind::Fabric,
    ResourceKind::Paper,
    ResourceKind::Lumber,
    ResourceKind::Steel,
    ResourceKind::Oil,
    ResourceKind::Coal,
    ResourceKind::Iron,
    ResourceKind::Horses,
    ResourceKind::Cotton,
    ResourceKind::Wool,
    ResourceKind::Timber,
    ResourceKind::Food,
];

const COMPILE_THRESHOLD_BY_DIFFICULTY: [i32; 5] = [5, 5, 5, 5, 5];

impl GameState {
    /// Retail `TSimMgr::DoCityAndTransport`.
    pub fn do_city_and_transport(&mut self) {
        for index in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(index);
            if !self.nation_eligible_for_optional_phase(nation) {
                continue;
            }
            self.fill_interior_minister_orders(nation);
            self.calculate_potentials(nation);
            self.execute_nation_pending_action_state_machine(nation);
            self.refresh_great_power_relation_panels_and_dispatch_delta_summary(nation);
            self.refresh_merchant_capacity(nation);
        }
    }

    pub(crate) fn nation_eligible_for_optional_phase(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.major(nation).common.status(),
            CountryStatus::ProtectorateOf(_)
        )
    }

    /// `TGreatPower::FillInteriorMinisterOrders` / `TAutoGreatPower` override.
    fn fill_interior_minister_orders(&mut self, nation: MajorNationId) {
        if self.nations.major(nation).kind != MajorNationKind::AutoGreatPower {
            return;
        }
        for resource in all_resources() {
            self.nations.majors[nation]
                .economy
                .update_need_target(resource, 0);
        }
        self.rebalance_ai_transport(nation);
        self.end_city_phase(nation);
        self.clear_ai_city_orders(nation);
        self.process_ai_pending_ship(nation);
        let temporary_lumber = self.rebalance_ai_labor(nation);
        self.choose_ai_expansion(nation);
        self.compute_ai_item_demands(nation);
        if temporary_lumber != 0 {
            self.nations
                .city_mut(nation)
                .adjust_stock(ResourceKind::Lumber, temporary_lumber);
        }
        self.issue_ai_item_orders(nation);
        self.fill_ai_transport_capacity(nation);
        self.rebuild_ai_allocation_average(nation);
        self.determine_ai_trade_bid(nation);
    }

    fn calculate_potentials(&mut self, nation: MajorNationId) {
        self.nations.city_mut(nation).refresh_local_summary_flags();
    }

    /// `TGreatPower::ExecuteNationPendingActionStateMachine`.
    fn execute_nation_pending_action_state_machine(&mut self, nation: MajorNationId) {
        self.produce_city_units(nation);

        let army_queued = self.nations.major(nation).economy.pending_actions
            [PendingActionKind::ArmyGrowthReward]
            .status()
            == PendingActionStatus::Queued;
        if army_queued {
            self.spawn_pending_army_growth_unit(nation);
        }

        // NavyGrowthReward creates a named ship, bumps the active-zone ship counter, and
        // constructs a TAdmiral. Admirals and active_zone_index are not in GameState, so
        // this branch is not seeded by the city/transport differentials.

        let overseas = self.nations.major(nation).economy.pending_actions
            [PendingActionKind::OverseasDeveloperReward]
            .status();
        if overseas < PendingActionStatus::Level3 && self.needs_overseas_developer(nation) {
            self.spawn_pending_overseas_developer(nation);
            self.nations.majors[nation].economy.pending_actions
                [PendingActionKind::OverseasDeveloperReward]
                .queue(-1);
        }

        let monument_queued = self.nations.major(nation).economy.pending_actions
            [PendingActionKind::ColonyMonumentMerchantCapacity]
            .status()
            == PendingActionStatus::Queued;
        if monument_queued {
            let count =
                &mut self.nations.city_mut(nation).ship_order_count_by_type[ShipType::Clipper];
            *count = count.wrapping_add(2);
            self.announce_later(nation, 1, 6, 2);
        }

        self.name_units(nation);
    }

    fn spawn_pending_army_growth_unit(&mut self, nation: MajorNationId) {
        let nation_id = nation.nation();
        let home = self
            .nations
            .major(nation)
            .common
            .home_tile
            .expect("army-growth pending requires a home tile");
        let province = self.map[home]
            .province
            .expect("army-growth pending requires the home tile's province");
        let unit_kind = MilitaryUnitKind::GeneralEra1;
        let id = self.unit_ids.next_military();
        let unit = MilitaryUnitState {
            id,
            nation: nation_id,
            unit_type: unit_kind,
            stationed_province: Some(province),
            order: crate::MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            owner_nation: nation_id,
            roster_id: 0,
            registered: true,
            name: String::new(),
            strength: 500,
            era: unit_kind.spawn_era(),
            experience: 0,
            battle_flags: 0,
        };
        let insert_at = self
            .military_units
            .partition_point(|existing| existing.nation.get() <= nation_id.get());
        self.military_units.insert(insert_at, unit);
        self.announce_later(nation, 3, unit_kind as i16, 1);
    }

    fn needs_overseas_developer(&self, nation: MajorNationId) -> bool {
        let nation_id = nation.nation();
        for slot in 7..NationId::COUNT {
            let minor_id = NationId::new(slot);
            if self.diplomacy.standings[nation_id][minor_id] <= 0xa9 {
                continue;
            }
            if let Some(common) = self.nations.common(minor_id)
                && matches!(
                    common.status(),
                    CountryStatus::ProtectorateOf(master) if master == nation_id
                )
            {
                continue;
            }
            return true;
        }
        false
    }

    fn spawn_pending_overseas_developer(&mut self, nation: MajorNationId) {
        let nation_id = nation.nation();
        let home = self
            .nations
            .major(nation)
            .common
            .home_tile
            .expect("overseas-developer pending requires a home tile");
        let Some(tile) =
            self.map
                .find_reachable_recruit_spawn_tile(&self.civilian_units, home, false)
        else {
            return;
        };
        let id = self.unit_ids.next_civilian();
        let unit = CivilianUnitState {
            id,
            nation: nation_id,
            unit_type: CivilianUnitKind::Developer,
            location: crate::CivilianLocation::OnMap(tile),
            order: CivilianWorkOrder::Idle,
            owner_nation: nation_id,
            roster_id: 0,
            registered: false,
        };
        let insert_at = self
            .civilian_units
            .partition_point(|existing| existing.nation.get() <= nation_id.get());
        self.civilian_units.insert(insert_at, unit);
    }

    fn name_units(&mut self, nation: MajorNationId) {
        let mut name_ordinals = [0_i16; MilitaryUnitKind::LENGTH];
        let mut next_roster_id = 1;
        name_units_for_nation(
            &mut self.military_units,
            nation.nation(),
            &mut name_ordinals,
            &mut next_roster_id,
        );
    }

    /// `TGreatPower::RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary`
    /// and the `TAutoGreatPower` override.
    fn refresh_great_power_relation_panels_and_dispatch_delta_summary(
        &mut self,
        nation: MajorNationId,
    ) {
        self.rebuild_nation_resource_yields(nation);
        self.advance_owned_region_development_counters_and_handle_events(nation);
        if self.nations.major(nation).kind == MajorNationKind::GreatPower {
            self.add_created_items(nation);
            self.compile_great_power_relationship_delta_lines(nation);
            self.end_city_phase(nation);
        }
    }

    /// Retail `TGreatPower::AdvanceOwnedRegionDevelopmentCountersAndHandleEvents`.
    pub fn advance_owned_region_development_counters_and_handle_events(
        &mut self,
        nation: MajorNationId,
    ) {
        let home_tile = self.nations.major(nation).common.home_tile;
        let owned: Vec<ProvinceId> = self.nations.major(nation).common.owned_regions().to_vec();
        let economic_turn = self.turn.economic_turn;
        let oil_drilling = self.technology.oil_drilling_available();
        let clothing_limit = building_type_limit(
            self.nations.city(nation).production_orders[CityFacilitySlot::ClothingFactory],
        );
        let furniture_limit = building_type_limit(
            self.nations.city(nation).production_orders[CityFacilitySlot::FurnitureFactory],
        );
        let steel_limit = building_type_limit(
            self.nations.city(nation).production_orders[CityFacilitySlot::Metalworks],
        );

        for province_id in owned {
            let city_tile = self.map.provinces[province_id].city_tile();
            if city_tile == home_tile {
                continue;
            }

            let last_turn_tick = self.map.provinces[province_id].last_turn_tick;
            let turn_delta = economic_turn.wrapping_sub(i32::from(last_turn_tick)) as u32;
            if turn_delta <= 4 {
                continue;
            }

            let linked_tiles = self.map.provinces[province_id].linked_tiles.clone();
            let mut resource_sums = ResourceTable::<i32>::default();
            for tile in linked_tiles {
                let tile_state = &self.map[tile];
                for edge in 0..2 {
                    if let Some(resource) = tile_state.edge_resources[edge] {
                        resource_sums[resource] +=
                            resource_capability_requirement_level(tile_state, edge);
                    }
                }
            }

            let mut pending_stage: i8 = 0;
            let current_stage = self.map.provinces[province_id].development_stage();
            {
                let development =
                    self.map.provinces[province_id].resource_development_by_type_mut();

                if turn_delta & 1 == 0 {
                    let cotton_wool =
                        resource_sums[ResourceKind::Cotton] + resource_sums[ResourceKind::Wool];
                    if cotton_wool != 0
                        && i32::from(development[ResourceKind::Fabric]) < clothing_limit
                        && i32::from(development[ResourceKind::Fabric]) < cotton_wool / 2
                    {
                        pending_stage = 1;
                        development[ResourceKind::Fabric] += 1;
                    }
                    if resource_sums[ResourceKind::Timber] != 0
                        && i32::from(development[ResourceKind::Lumber]) < furniture_limit
                        && i32::from(development[ResourceKind::Lumber])
                            < resource_sums[ResourceKind::Timber] / 2
                    {
                        pending_stage = 1;
                        development[ResourceKind::Lumber] += 1;
                    }
                    if resource_sums[ResourceKind::Coal] != 0
                        && i32::from(development[ResourceKind::Steel]) < steel_limit
                        && i32::from(development[ResourceKind::Steel])
                            < resource_sums[ResourceKind::Coal] / 2
                    {
                        pending_stage = 1;
                        development[ResourceKind::Steel] += 1;
                    }
                    if resource_sums[ResourceKind::Oil] != 0
                        && oil_drilling
                        && i32::from(development[ResourceKind::Fuel])
                            < resource_sums[ResourceKind::Oil] / 2
                    {
                        pending_stage = 1;
                        development[ResourceKind::Fuel] += 1;
                    }
                }

                if turn_delta > 9 && turn_delta & 1 != 0 {
                    if development[ResourceKind::Fabric] != 0
                        && i32::from(development[ResourceKind::Clothing])
                            < i32::from(development[ResourceKind::Fabric]) / 2
                    {
                        pending_stage = 2;
                        development[ResourceKind::Clothing] += 1;
                    }
                    if development[ResourceKind::Lumber] != 0
                        && i32::from(development[ResourceKind::Furniture])
                            < i32::from(development[ResourceKind::Lumber]) / 2
                    {
                        pending_stage = 2;
                        development[ResourceKind::Furniture] += 1;
                    }
                    if development[ResourceKind::Steel] != 0
                        && i32::from(development[ResourceKind::Hardware])
                            < i32::from(development[ResourceKind::Steel]) / 2
                    {
                        pending_stage = 2;
                        development[ResourceKind::Hardware] += 1;
                    }
                }
            }

            if current_stage < pending_stage {
                self.map.provinces[province_id].set_development_stage(pending_stage);
            } else {
                pending_stage = 0;
            }

            if pending_stage == 2 {
                self.nations.majors[nation].economy.pending_actions
                    [PendingActionKind::TownDevelopment]
                    .queue(province_id.get() as i16);
            } else if pending_stage == 1 {
                self.nations.majors[nation].economy.pending_actions
                    [PendingActionKind::VillageDevelopment]
                    .queue(province_id.get() as i16);
                if self.nations.majors[nation].economy.pending_actions
                    [PendingActionKind::RailyardExpansion]
                    .status()
                    < PendingActionStatus::Level3
                {
                    self.nations.majors[nation].economy.pending_actions
                        [PendingActionKind::RailyardExpansion]
                        .queue(-1);
                }
            }
        }
    }

    /// `TGreatPower::CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage`.
    fn compile_great_power_relationship_delta_lines(&mut self, nation: MajorNationId) {
        let pressure = i32::from(self.nations.major(nation).economy.pressure_counter);
        let threshold = COMPILE_THRESHOLD_BY_DIFFICULTY[self.turn.difficulty as usize];
        if threshold > pressure {
            return;
        }

        let mut interaction_score = 0_i32;
        let treasury = self.nations.major(nation).common.treasury;
        for resource in COMPILE_DELTA_RESOURCE_ORDER {
            if interaction_score + treasury >= 0 {
                break;
            }
            let stock = self.nations.city(nation).stockpile[resource];
            if stock <= 0 {
                continue;
            }
            self.nations.city_mut(nation).stockpile[resource] = 0;
            self.nations.city_mut(nation).stockpile.verify_stocks();
            let Some(commodity) = TradeCommodity::from_retail(resource as i16) else {
                continue;
            };
            let price = self.market.rows[commodity].price;
            interaction_score =
                (interaction_score as f32 - (price * i32::from(stock)) as f32 * -0.25) as i32;
        }
        self.nations.majors[nation].common.treasury += interaction_score;
    }

    fn announce_later(&mut self, nation: MajorNationId, order_kind: i16, payload: i16, flags: i16) {
        if self.nations.major(nation).kind == MajorNationKind::AutoGreatPower {
            return;
        }
        let turn_tick = self.turn.economic_turn;
        let record = if order_kind == 3 {
            TurnSummary::MilitaryRecruit {
                turn_tick,
                unit_type: MilitaryUnitKind::from_index(payload as u8)
                    .expect("pending army-growth announce payload is a military unit kind"),
                count: flags,
            }
        } else {
            TurnSummary::Retail {
                turn_tick,
                order_kind,
                payload,
                flags,
            }
        };
        crate::recruitment::insert_turn_summary(
            &mut self.rng,
            &mut self.pending.nations[nation].turn_summary,
            record,
        );
    }
}

fn building_type_limit(production: i16) -> i32 {
    i32::from(production) / 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn seed_owned_province(
        state: &mut GameState,
        nation: MajorNationId,
        province: ProvinceId,
        city_tile: TileId,
        linked: TileId,
        last_turn_tick: i16,
    ) {
        state
            .nations
            .append_owned_region_during_construction(nation.nation(), province);
        let mut development = ResourceTable::default();
        development[ResourceKind::Fabric] = 0;
        state.map.provinces[province] = ProvinceState::new(
            Some(nation.nation()),
            Some(nation.nation()),
            0,
            Vec::new(),
            Vec::new(),
            Some(0),
            0,
            Some(city_tile),
            last_turn_tick,
            None,
            None,
            vec![linked],
            development,
            MajorNationTable::default(),
            0,
            false,
            0,
            String::new(),
        );
        state.map[linked].province = Some(province);
        state.map[linked].edge_resources = [Some(ResourceKind::Cotton), None];
        state.map[linked].development.surface = crate::DevelopmentLevel::new(3);
    }

    #[test]
    fn owned_region_development_skips_the_capital_and_leaves_last_turn_tick() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        let home = TileId::new(1);
        state.nations.majors[nation].common.home_tile = Some(home);
        state.turn.economic_turn = 10;
        state.nations.city_mut(nation).production_orders[CityFacilitySlot::ClothingFactory] = 4;

        let capital = ProvinceId::new(0);
        let other = ProvinceId::new(1);
        seed_owned_province(&mut state, nation, capital, home, TileId::new(20), 0);
        seed_owned_province(
            &mut state,
            nation,
            other,
            TileId::new(50),
            TileId::new(21),
            4,
        );

        state.advance_owned_region_development_counters_and_handle_events(nation);

        assert_eq!(state.map.provinces[capital].last_turn_tick, 0);
        assert_eq!(
            state.map.provinces[capital].resource_development_by_type()[ResourceKind::Fabric],
            0
        );
        assert_eq!(state.map.provinces[other].last_turn_tick, 4);
        assert_eq!(
            state.map.provinces[other].resource_development_by_type()[ResourceKind::Fabric],
            1
        );
        assert_eq!(state.map.provinces[other].development_stage(), 1);
        let village = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::VillageDevelopment];
        assert_eq!(village.status(), PendingActionStatus::Queued);
        assert_eq!(village.payload(), Some(1));
        let railyard = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::RailyardExpansion];
        assert_eq!(railyard.status(), PendingActionStatus::Queued);
        assert_eq!(railyard.payload(), None);
    }

    #[test]
    fn owned_region_development_odd_delta_advances_stage_two() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        let home = TileId::new(1);
        state.nations.majors[nation].common.home_tile = Some(home);
        state.turn.economic_turn = 20;

        let other = ProvinceId::new(1);
        seed_owned_province(
            &mut state,
            nation,
            other,
            TileId::new(50),
            TileId::new(21),
            9,
        );
        state.map.provinces[other].resource_development_by_type_mut()[ResourceKind::Fabric] = 2;

        state.advance_owned_region_development_counters_and_handle_events(nation);

        assert_eq!(state.map.provinces[other].last_turn_tick, 9);
        assert_eq!(
            state.map.provinces[other].resource_development_by_type()[ResourceKind::Clothing],
            1
        );
        assert_eq!(state.map.provinces[other].development_stage(), 2);
        let town = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::TownDevelopment];
        assert_eq!(town.status(), PendingActionStatus::Queued);
        assert_eq!(town.payload(), Some(1));
    }
}
