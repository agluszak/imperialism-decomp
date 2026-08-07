use crate::{
    GameCommand, GameEvent, GameState, MajorNationState, NationCommonState, NationId, ResourceKind,
    StepOutcome,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuleError {
    #[error("nation {} is not present", .nation.get())]
    MissingNation { nation: NationId },
    #[error("nation {} is not a major nation", .nation.get())]
    NotMajorNation { nation: NationId },
    #[error("nation {} has no city state", .nation.get())]
    MissingCity { nation: NationId },
    #[error("city slot {} belongs to nation {}", .nation.get(), .actual.get())]
    CityNationMismatch { nation: NationId, actual: NationId },
    #[error("random-game setup commands require Simulation::apply")]
    SetupCommandRequiresSimulation,
}

impl GameState {
    pub fn apply_command(&mut self, command: GameCommand) -> Result<StepOutcome, RuleError> {
        match command {
            GameCommand::PlaceTradeBid {
                nation,
                resource,
                amount,
            } => {
                let (_, major) = self.major_nation_parts_mut(nation)?;
                major.set_item_potential(resource, amount);
                let applied = major.item_potentials[resource];
                Ok(StepOutcome {
                    events: vec![GameEvent::TradeBidPlaced {
                        nation,
                        resource,
                        amount: applied,
                    }],
                })
            }
            GameCommand::PurchaseItem {
                nation,
                resource,
                amount,
                price,
            } => {
                let (common, major) = self.major_nation_parts_mut(nation)?;
                settle_purchase(common, major, resource, amount, price);
                Ok(StepOutcome {
                    events: vec![GameEvent::TradeSettled {
                        nation,
                        resource,
                        amount,
                        price,
                    }],
                })
            }
            _ => Err(RuleError::SetupCommandRequiresSimulation),
        }
    }

    pub fn remember_trade_bids(&mut self, nation: NationId) -> Result<StepOutcome, RuleError> {
        self.major_nation_parts_mut(nation)?.1.remember_trade_bids();
        Ok(StepOutcome {
            events: vec![GameEvent::TradeBidsRemembered { nation }],
        })
    }

    pub fn commit_purchased_items(&mut self, nation: NationId) -> Result<StepOutcome, RuleError> {
        let index = self.major_nation_index(nation)?;
        let city = self
            .cities
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuleError::MissingCity { nation })?;
        if city.nation != nation {
            return Err(RuleError::CityNationMismatch {
                nation,
                actual: city.nation,
            });
        }

        let major = self.nations[index]
            .as_mut()
            .and_then(|state| state.major_mut())
            .expect("major-nation presence was checked before committing purchases");
        let city = self.cities[index]
            .as_mut()
            .expect("city presence was checked before committing purchases");
        major.settle_purchased_items(city);
        Ok(StepOutcome {
            events: vec![GameEvent::PurchasedItemsCommitted { nation }],
        })
    }

    fn major_nation_parts_mut(
        &mut self,
        nation: NationId,
    ) -> Result<(&mut NationCommonState, &mut MajorNationState), RuleError> {
        let state = self
            .nations
            .get_mut(usize::from(nation.get()))
            .and_then(Option::as_mut)
            .ok_or(RuleError::MissingNation { nation })?;
        state
            .major_parts_mut()
            .ok_or(RuleError::NotMajorNation { nation })
    }

    fn major_nation_index(&self, nation: NationId) -> Result<usize, RuleError> {
        let index = usize::from(nation.get());
        let state = self
            .nations
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuleError::MissingNation { nation })?;
        if state.major().is_none() {
            return Err(RuleError::NotMajorNation { nation });
        }
        Ok(index)
    }
}

fn settle_purchase(
    common: &mut NationCommonState,
    major: &mut MajorNationState,
    resource: ResourceKind,
    amount: i16,
    price: i16,
) {
    major.purchased_items_by_resource[resource] =
        major.purchased_items_by_resource[resource].wrapping_add(amount);
    let cost = i32::from(price).wrapping_mul(i32::from(amount));
    common.treasury = common.treasury.wrapping_sub(cost);

    if amount > 0 {
        major.capacities[0] = major.capacities[0].wrapping_sub(amount);
        major.budget_pool_delta = major.budget_pool_delta.wrapping_sub(cost);
    } else {
        major.budget_pool_base = major.budget_pool_base.wrapping_sub(cost);
        if is_special_nation_interaction_resource(resource) {
            major.special_resource_trade_balance = major
                .special_resource_trade_balance
                .wrapping_sub(i32::from(amount));
        }
    }
}

const fn is_special_nation_interaction_resource(resource: ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Clothing
            | ResourceKind::Furniture
            | ResourceKind::Hardware
            | ResourceKind::Arms
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CityState, LaborPool, NationData, NationState, PendingWorkState, PopulationState, RngState,
        TurnState, WorldState,
    };

    fn major() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: [10, 4, 0, 0],
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: crate::NationTable::default(),
            diplomacy_grant_by_nation: crate::NationTable::default(),
            need_current_by_type: crate::ResourceTable::default(),
            need_target_by_type: crate::ResourceTable::default(),
            relation_delta_current: crate::ResourceTable::default(),
            purchased_items_by_resource: crate::ResourceTable::default(),
            item_potentials: crate::ResourceTable::default(),
            unfilled_trade_turns_by_resource: crate::ResourceTable::default(),
            transported_items_by_resource: crate::ResourceTable::default(),
            remembered_trade_offers_by_resource: crate::ResourceTable::default(),
            aid_allocation_matrix: vec![0; 23 * 23],
            budget_pool_base: 200,
            budget_pool_delta: 100,
            special_resource_trade_balance: 30,
            candidate_nation_flags: vec![0; 23],
            scenario_initialized: false,
            turn_finished: false,
            pending_action_status: crate::PendingActionTable::default(),
            pending_action_payload_by_action: crate::PendingActionTable::default(),
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: vec![0; 23],
            military_expenses: 0,
        }
    }

    fn state(is_major: bool) -> GameState {
        let nation = NationId::new(6);
        let mut nations = vec![None; 23];
        nations[6] = Some(NationState {
            id: nation,
            common: NationCommonState {
                encoded_nation_slot: 6,
                owner_nation: 6,
                treasury: 1_000,
                home_tile: 0,
                need_level_by_nation: crate::NationTable::default(),
            },
            data: if is_major {
                NationData::Major(major())
            } else {
                NationData::Minor
            },
        });
        let mut cities = vec![None; 7];
        cities[6] = Some(city(nation));
        GameState {
            turn: TurnState {
                scenario_map_index_plus_one: 0,
                economic_turn: 1,
                phase_code: 5,
                difficulty: 1,
                active_nation: 6,
                selected_nation: 6,
            },
            persistent_unit_id_counter: 0,
            world: WorldState {
                width: 0,
                height: 0,
                wraps_horizontally: false,
                tiles: vec![],
            },
            rng: RngState {
                crt_rand: 1,
                map_generation: 1,
                zone_status: 1,
            },
            nations,
            cities,
            military_units: vec![],
            civilian_units: vec![],
            ships: vec![],
            task_forces: vec![],
            missions: vec![],
            pending: PendingWorkState {
                turn_flow_status_flags: 0,
                nations: crate::MajorNationTable::from_fn(|nation| crate::NationPendingWork {
                    nation: NationId::new(nation as u8),
                    turn_events: vec![],
                    proposals: vec![],
                    turn_summary: vec![],
                    turn_start_events: vec![],
                }),
                war_transitions: vec![],
            },
        }
    }

    fn city(nation: NationId) -> CityState {
        CityState {
            nation,
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            metrics_0e: vec![0; 30],
            metrics_4a: vec![0; 9],
            order_count_by_type: vec![0; 14],
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: crate::ResourceTable::default(),
            home_town_tile: 0,
            power_available: 0,
            stock_by_type: crate::ResourceTable::default(),
            production_orders: crate::ProductionTable::default(),
            production_accum: crate::ProductionTable::default(),
            production_flags: crate::ProductionTable::default(),
            production_current: crate::ProductionTable::default(),
            production_progress: crate::ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: crate::ResourceTable::default(),
            consumed_production_input_by_type: crate::ResourceTable::default(),
            population: PopulationState {
                count: 0,
                count_float_bits: 0,
                strength: 0,
                extra: 0,
                phase_value: 0,
                baseline_labor: Some(LaborPool::default()),
                production_labor: Some(LaborPool::default()),
                pending_labor_delta: Some(LaborPool::default()),
                predicted_need_by_resource: crate::ResourceTable::default(),
            },
        }
    }

    fn bid(nation: NationId, resource: ResourceKind, amount: i16) -> GameCommand {
        GameCommand::PlaceTradeBid {
            nation,
            resource,
            amount,
        }
    }

    fn purchase(nation: NationId, resource: ResourceKind, amount: i16, price: i16) -> GameCommand {
        GameCommand::PurchaseItem {
            nation,
            resource,
            amount,
            price,
        }
    }

    #[test]
    fn buyer_uses_merchant_capacity_and_delta_budget() {
        let nation = NationId::new(6);
        let mut game = state(true);
        let outcome = game
            .apply_command(purchase(nation, ResourceKind::Fabric, 3, 7))
            .unwrap();
        let state = game.nations[6].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(state.common.treasury, 979);
        assert_eq!(major.purchased_items_by_resource[ResourceKind::Fabric], 3);
        assert_eq!(major.capacities[0], 7);
        assert_eq!(major.budget_pool_delta, 79);
        assert_eq!(major.budget_pool_base, 200);
        assert_eq!(major.special_resource_trade_balance, 30);
        assert_eq!(
            outcome.events,
            vec![GameEvent::TradeSettled {
                nation,
                resource: ResourceKind::Fabric,
                amount: 3,
                price: 7,
            }]
        );
    }

    #[test]
    fn trade_bid_clamps_to_merchant_capacity_and_reports_the_applied_amount() {
        let nation = NationId::new(6);
        let mut game = state(true);
        let outcome = game
            .apply_command(bid(nation, ResourceKind::Fabric, 9))
            .unwrap();
        assert_eq!(
            game.nations[6]
                .as_ref()
                .unwrap()
                .major()
                .unwrap()
                .item_potentials[ResourceKind::Fabric],
            4
        );
        assert_eq!(
            outcome.events,
            vec![GameEvent::TradeBidPlaced {
                nation,
                resource: ResourceKind::Fabric,
                amount: 4,
            }]
        );
    }

    #[test]
    fn remembered_bids_and_purchased_items_commit_as_one_trade_phase() {
        let nation = NationId::new(6);
        let mut game = state(true);
        game.apply_command(bid(nation, ResourceKind::Fabric, -1))
            .unwrap();
        game.apply_command(bid(nation, ResourceKind::Clothing, -1))
            .unwrap();
        assert_eq!(
            game.remember_trade_bids(nation).unwrap().events,
            vec![GameEvent::TradeBidsRemembered { nation }]
        );
        game.apply_command(purchase(nation, ResourceKind::Fabric, 3, 7))
            .unwrap();
        game.apply_command(purchase(nation, ResourceKind::Food, -30, 1))
            .unwrap();
        game.cities[6].as_mut().unwrap().stock_by_type[ResourceKind::Food] = 20;

        assert_eq!(
            game.commit_purchased_items(nation).unwrap().events,
            vec![GameEvent::PurchasedItemsCommitted { nation }]
        );
        let major = game.nations[6].as_ref().unwrap().major().unwrap();
        assert!(
            major
                .purchased_items_by_resource
                .iter()
                .all(|(_, amount)| *amount == 0)
        );
        assert_eq!(
            major.unfilled_trade_turns_by_resource[ResourceKind::Fabric],
            0
        );
        assert_eq!(
            major.unfilled_trade_turns_by_resource[ResourceKind::Clothing],
            1
        );
        let city = game.cities[6].as_ref().unwrap();
        assert_eq!(city.stock_by_type[ResourceKind::Fabric], 3);
        assert_eq!(city.stock_by_type[ResourceKind::Food], 0);
    }

    #[test]
    fn special_resource_seller_uses_base_budget_and_balance() {
        let nation = NationId::new(6);
        let mut game = state(true);
        game.apply_command(purchase(nation, ResourceKind::Clothing, -2, 5))
            .unwrap();
        let state = game.nations[6].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(state.common.treasury, 1_010);
        assert_eq!(
            major.purchased_items_by_resource[ResourceKind::Clothing],
            -2
        );
        assert_eq!(major.capacities[0], 10);
        assert_eq!(major.budget_pool_base, 210);
        assert_eq!(major.budget_pool_delta, 100);
        assert_eq!(major.special_resource_trade_balance, 32);
    }

    #[test]
    fn ordinary_resource_seller_does_not_change_special_balance() {
        let nation = NationId::new(6);
        let mut game = state(true);
        game.apply_command(purchase(nation, ResourceKind::Fabric, -2, 5))
            .unwrap();
        assert_eq!(
            game.nations[6]
                .as_ref()
                .unwrap()
                .major()
                .unwrap()
                .special_resource_trade_balance,
            30
        );
    }

    #[test]
    fn command_rejects_missing_and_minor_nations_without_mutation() {
        let nation = NationId::new(6);
        let mut game = state(false);
        let before = game.clone();
        assert_eq!(
            game.apply_command(purchase(nation, ResourceKind::Food, 1, 1)),
            Err(RuleError::NotMajorNation { nation })
        );
        assert_eq!(game, before);
        assert_eq!(
            game.apply_command(purchase(NationId::new(5), ResourceKind::Food, 1, 1)),
            Err(RuleError::MissingNation {
                nation: NationId::new(5)
            })
        );
        assert_eq!(game, before);
    }
}
