//! End-of-phase city production resolution.

use super::*;
use crate::*;
use enum_map::Enum;

impl GameState {
    /// Resolves the city's retained production orders and starts its next
    /// production cycle. This is retail `TCity::EndCityPhase`; unit objects are
    /// committed after the city borrow is released.
    pub fn end_city_phase(&mut self, nation: MajorNationId) {
        let owned_region_count = self
            .nations
            .owned_region_count(nation.nation())
            .expect("city production requires a present major nation");
        let mut produced_civilians = CivilianUnitTable::default();
        {
            let MajorNation { economy, city, .. } = &mut self.nations.majors[nation];

            city.phase_counter += 1;
            city.stockpile.verify_stocks();
            if !economy.diplomacy_eligible {
                for resource in all_resources() {
                    city.stockpile
                        .wrapping_add(resource, city.reserved_by_type[resource]);
                }
            }
            city.stockpile.verify_stocks();
            for resource in all_resources() {
                city.stockpile
                    .wrapping_add(resource, city.consumed_production_input_by_type[resource]);
                city.consumed_production_input_by_type[resource] = 0;
            }

            let previous_production_score = city.rolling_item_production_score;
            city.rolling_item_production_score = 0;
            {
                let CityState {
                    orders,
                    stockpile,
                    population,
                    production_accum,
                    production_orders,
                    rolling_item_production_score,
                    ..
                } = city;
                produce_food_processing(&mut orders.food_processing, stockpile);
                for output in ManufacturedItem::ALL {
                    produce_item(
                        &mut orders.items[output],
                        stockpile,
                        production_accum,
                        rolling_item_production_score,
                        output,
                    );
                }
                for level in
                    (0..enum_map::enum_len::<TrainingLevel>()).map(TrainingLevel::from_usize)
                {
                    produce_training(level, &mut orders.training[level], population, economy);
                }
                *rolling_item_production_score =
                    previous_production_score * 9 / 10 + *rolling_item_production_score * 10;

                for kind in (0..CivilianUnitKind::LENGTH).map(CivilianUnitKind::from_usize) {
                    let progress = &mut orders.civilian_recruitment[kind];
                    produced_civilians[kind] = progress.quantity;
                    progress.quantity = 0;
                }

                let (transport_primary, transport_secondary) = TRANSPORT_CAPACITY_INPUTS;
                produce_transport_capacity(
                    &mut orders.transport_capacity,
                    economy,
                    transport_primary,
                    transport_secondary,
                );
                for facility in ExpandableFacility::ALL {
                    let (primary, secondary) = EXPANSION_INPUTS;
                    produce_expansion(
                        &mut orders.expansions[facility],
                        production_orders,
                        production_accum,
                        facility,
                        primary,
                        secondary,
                    );
                }
                produce_population_growth(
                    &mut orders.population_growth,
                    population,
                    production_accum,
                    economy,
                    owned_region_count,
                );
            }

            if city.power_plant_upgrade_queued {
                city.power_plant_upgrade_queued = false;
                city.production_accum[CityFacilitySlot::PowerPlant] +=
                    999 - city.production_orders[CityFacilitySlot::PowerPlant];
                city.production_orders[CityFacilitySlot::PowerPlant] = 999;
            }
            for resource in all_resources() {
                if city.stockpile[resource] > 9_999 {
                    city.stockpile[resource] = 9_999;
                }
            }

            city.power_available = 0;
            city.start_production_phase();
            {
                let CityState {
                    orders,
                    stockpile,
                    population,
                    production_accum,
                    power_available,
                    ..
                } = city;
                restock_power_plant(
                    &mut orders.power_plant,
                    stockpile,
                    population,
                    power_available,
                );
                for output in ManufacturedItem::ALL {
                    restock_item(
                        &mut orders.items[output],
                        stockpile,
                        population,
                        production_accum,
                        output,
                    );
                }
            }
            city.production_accum[CityFacilitySlot::RegionalPopulation] =
                retail_region_capacity(economy, owned_region_count);
            city.production_accum[CityFacilitySlot::Transport] =
                city.production_orders[CityFacilitySlot::Transport];
        }

        for (kind, quantity) in produced_civilians {
            self.produce_civilian_recruits(nation, kind, quantity);
        }
    }

    /// Resolves the Armory and Shipyard orders after potential calculation.
    pub fn produce_city_units(&mut self, nation: MajorNationId) {
        let mut civilian_qty = CivilianUnitTable::default();
        let military = {
            let city = self.nations.city_mut(nation);
            let military = MilitaryRecruitOrderTable::from_fn(|category| {
                let order = &mut city.orders.military_recruitment[category];
                let produced = (order.unit_kind, order.progress.quantity);
                order.progress.quantity = 0;
                produced
            });
            for kind in (0..CivilianUnitKind::LENGTH).map(CivilianUnitKind::from_usize) {
                let order = &mut city.orders.civilian_recruitment[kind];
                civilian_qty[kind] = order.quantity;
                order.quantity = 0;
            }
            military
        };

        for (_, (unit_kind, quantity)) in military {
            self.produce_military_recruits(nation, unit_kind, quantity);
        }
        for (unit_kind, quantity) in civilian_qty {
            self.produce_civilian_recruits(nation, unit_kind, quantity);
        }
        for slot in (0..enum_map::enum_len::<ShipOrderSlot>()).map(ShipOrderSlot::from_usize) {
            self.produce_ship_order(nation, slot);
        }
    }

    /// Retail `TShipOrder::LaunchShip`: bump the type counter, create navy
    /// objects for warships, clear the order, then queue navy-growth pending.
    fn produce_ship_order(&mut self, nation: MajorNationId, slot: ShipOrderSlot) {
        let (ship_type, quantity) = {
            let order = &self.nations.city(nation).orders.ships[slot];
            (order.ship_type, order.progress.quantity)
        };
        if ship_type == ShipType::NoShip || quantity == 0 {
            return;
        }

        {
            let count = &mut self.nations.city_mut(nation).ship_order_count_by_type[ship_type];
            *count = count.wrapping_add(quantity);
        }

        if ship_creates_navy_object(ship_type) {
            let location = self.port_zone_for_city_home(nation);
            let nation_id = nation.nation();
            let strength = ship_stock_cap(ship_type);
            for _ in 0..quantity {
                self.insert_ship_at_head(ShipState {
                    ship_type,
                    location,
                    task_force: None,
                    aggression: 1,
                    nation: nation_id,
                    name: String::new(),
                    strength,
                    experience: 0,
                    selection: 0,
                });
            }
        }

        {
            let order = &mut self.nations.city_mut(nation).orders.ships[slot];
            order.progress.quantity = 0;
            order.materials = ShipMaterials::default();
        }

        self.queue_navy_growth_pending(nation);
    }

    fn port_zone_for_city_home(&self, nation: MajorNationId) -> OceanZoneId {
        let home = self
            .nations
            .major(nation)
            .common
            .home_tile
            .expect("a city that launches a warship has a home tile");
        self.ocean
            .zones
            .iter()
            .enumerate()
            .find_map(|(index, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (port.port_tile == home
                    || port.zone.active_tile == Some(home)
                    || port.zone.target_tile == Some(home))
                .then(|| OceanZoneId::new(index as u16))
            })
            .expect("a city that launches a warship has a port zone for its home tile")
    }

    fn queue_navy_growth_pending(&mut self, nation: MajorNationId) {
        let pending =
            self.nations.major(nation).economy.pending_actions[PendingActionKind::NavyGrowthReward];
        let Some(desired) = pending.growth_reward_level() else {
            return;
        };
        let nation_id = nation.nation();
        let arms: i32 = self
            .ships
            .iter()
            .filter(|ship| ship.nation == nation_id)
            .map(|ship| i32::from(ship_order_costs(ship.ship_type).arms))
            .sum();
        if arms < 25 {
            return;
        }
        let payload = if arms < 50 {
            (desired == 0).then_some(1)
        } else if arms < 100 {
            (desired < 2).then_some(2)
        } else if arms < 200 {
            (desired < 3).then_some(3)
        } else if arms < 300 {
            (desired < 4).then_some(4)
        } else if arms < 400 {
            (desired < 5).then_some(5)
        } else if arms < 500 {
            (desired < 6).then_some(6)
        } else {
            None
        };
        if let Some(payload) = payload {
            set_pending_action(
                &mut self.nations.majors[nation].economy,
                PendingActionKind::NavyGrowthReward,
                payload,
            );
        }
    }
}

pub(crate) fn set_pending_action(
    owner: &mut GreatPowerState,
    action: PendingActionKind,
    payload: i16,
) {
    owner.pending_actions[action].queue_with_payload(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_zone() -> Zone {
        Zone {
            display_name: String::new(),
            status_code: None,
            target_tile: None,
            seed_owner: None,
            active_tile: None,
            primary_neighbors: Vec::new(),
            secondary_neighbors: Vec::new(),
        }
    }

    #[test]
    fn launched_warship_uses_the_home_port_zone_not_zone_zero() {
        let mut state = crate::test_support::game_state();
        let home = TileId::new(1);
        state.ocean.zones = vec![
            ZoneKind::Zone(empty_zone()),
            ZoneKind::PortZone(PortZone {
                zone: empty_zone(),
                port_tile: home,
            }),
        ];
        let nation = MajorNationId::new(0);
        state.nations.city_mut(nation).orders.ships[ShipOrderSlot::WarshipEarlyPrimary]
            .progress
            .quantity = 1;

        state.produce_city_units(nation);

        assert_eq!(state.ships.len(), 1);
        assert_eq!(state.ships[0].ship_type, ShipType::Frigate);
        assert_eq!(state.ships[0].location, OceanZoneId::new(1));
    }

    fn test_frigate(nation: MajorNationId) -> ShipState {
        ShipState {
            ship_type: ShipType::Frigate,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 0,
            nation: nation.nation(),
            name: String::new(),
            strength: 100,
            experience: 0,
            selection: 0,
        }
    }

    #[test]
    fn navy_growth_reward_advances_through_newspaper_levels() {
        let mut state = crate::test_support::game_state();
        let nation = MajorNationId::new(0);
        for _ in 0..13 {
            state.ships.push(test_frigate(nation));
        }
        assert_eq!(
            state.nations.majors[nation].economy.pending_actions
                [PendingActionKind::NavyGrowthReward]
                .growth_reward_level(),
            Some(0)
        );
        state.queue_navy_growth_pending(nation);
        let pending = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::NavyGrowthReward];
        assert_eq!(pending.status(), PendingActionStatus::QUEUED);
        assert_eq!(pending.payload(), Some(1));

        state.mark_all_pending_status_flags_handled();
        let pending = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::NavyGrowthReward];
        assert_eq!(pending.status(), PendingActionStatus::from_retail(0x34));
        assert_eq!(pending.growth_reward_level(), Some(1));

        for _ in 0..12 {
            state.ships.push(test_frigate(nation));
        }
        state.queue_navy_growth_pending(nation);
        let pending = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::NavyGrowthReward];
        assert_eq!(pending.status(), PendingActionStatus::QUEUED);
        assert_eq!(pending.payload(), Some(2));

        state.mark_all_pending_status_flags_handled();
        let pending = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::NavyGrowthReward];
        assert_eq!(pending.status(), PendingActionStatus::from_retail(0x35));
        assert_eq!(pending.growth_reward_level(), Some(2));

        for _ in 0..25 {
            state.ships.push(test_frigate(nation));
        }
        state.queue_navy_growth_pending(nation);
        state.mark_all_pending_status_flags_handled();
        let pending = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::NavyGrowthReward];
        assert_eq!(pending.status(), PendingActionStatus::from_retail(0x36));
        assert_eq!(pending.growth_reward_level(), Some(3));
    }
}
