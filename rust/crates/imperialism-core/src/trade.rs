use crate::{
    CityState, DiplomacyGrant, DiplomacyGrantFlags, GameEvent, GameState, MajorNationId,
    MajorNationState, MinorNationId, NationCapacity, NationCommonState, NationId, ResourceKind,
    StepOutcome, all_resources,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuleError {
    #[error("nation {} is not present", .nation.get())]
    MissingNation { nation: NationId },
    #[error("nation {} is not a major nation", .nation.get())]
    NotMajorNation { nation: NationId },
    #[error("nation {} has no city state", .nation.get())]
    MissingCity { nation: NationId },
}

impl GameState {
    pub fn place_trade_bid(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        amount: i16,
    ) -> Result<StepOutcome, RuleError> {
        let (_, major) = self.major_nation_parts_mut(nation)?;
        major.set_item_potential(resource, amount);
        let applied = major.item_potentials[resource];
        Ok(StepOutcome {
            events: vec![GameEvent::TradeBidPlaced {
                nation: nation.nation(),
                resource,
                amount: applied,
            }],
        })
    }

    pub fn purchase_item(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        amount: i16,
        price: i16,
    ) -> Result<StepOutcome, RuleError> {
        let (common, major) = self.major_nation_parts_mut(nation)?;
        settle_purchase(common, major, resource, amount, price);
        Ok(StepOutcome {
            events: vec![GameEvent::TradeSettled {
                nation: nation.nation(),
                resource,
                amount,
                price,
            }],
        })
    }

    pub fn remember_trade_bids(&mut self, nation: MajorNationId) -> Result<StepOutcome, RuleError> {
        self.major_nation_parts_mut(nation)?.1.remember_trade_bids();
        Ok(StepOutcome {
            events: vec![GameEvent::TradeBidsRemembered {
                nation: nation.nation(),
            }],
        })
    }

    pub fn commit_purchased_items(
        &mut self,
        nation: MajorNationId,
    ) -> Result<StepOutcome, RuleError> {
        let (_, major, city) = self.major_nation_city_parts_mut(nation)?;
        major.settle_purchased_items(city);
        Ok(StepOutcome {
            events: vec![GameEvent::PurchasedItemsCommitted {
                nation: nation.nation(),
            }],
        })
    }

    /// Settles the nation's transported-item ledger into city stock.
    pub fn settle_transported_items(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (_, major, city) = self.major_nation_city_parts_mut(nation)?;
        major.settle_transported_items(city);
        Ok(())
    }

    /// Mirrors `TGreatPower::AddCreatedItems` at the city-and-transport phase
    /// boundary. Commodity targets remain available for the rest of the phase;
    /// only the city's settled stock changes here.
    pub fn add_created_items(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (common, major, city) = self.major_nation_city_parts_mut(nation)?;

        common.treasury += i32::from(major.need_target_by_type[ResourceKind::Gems]) * 500;
        city.stock_by_type[ResourceKind::Gems] = 0;
        city.verify_stocks();

        common.treasury += i32::from(major.need_target_by_type[ResourceKind::Gold]) * 200;
        city.stock_by_type[ResourceKind::Gold] = 0;
        city.verify_stocks();

        for resource in all_resources() {
            city.add_to_stock_and_verify(resource, major.need_target_by_type[resource]);
        }
        Ok(())
    }

    /// Queues or cancels the city's power-plant upgrade and applies its
    /// corresponding treasury charge or refund.
    pub fn set_power_plant_upgrade(
        &mut self,
        nation: MajorNationId,
        enabled: bool,
    ) -> Result<(), RuleError> {
        let (common, _, city) = self.major_nation_city_parts_mut(nation)?;
        city.set_power_plant_upgrade(&mut common.treasury, enabled);
        Ok(())
    }

    /// Moves one resource into city stock, limited by both the resource need
    /// and unused transport capacity.
    pub fn direct_transport(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
    ) -> Result<i16, RuleError> {
        let (_, major, city) = self.major_nation_city_parts_mut(nation)?;
        Ok(city.direct_transport(major, resource, requested))
    }

    /// Spends one lumber and one steel to add one transport-capacity unit.
    ///
    /// A major nation without a city has no stockpile, so retail leaves it
    /// unchanged and reports that no rolling stock was built.
    pub fn increase_rolling_stock(&mut self, nation: MajorNationId) -> Result<bool, RuleError> {
        if self.cities[nation].is_none() {
            self.major_nation_parts_mut(nation)?;
            return Ok(false);
        }
        let (_, major, city) = self.major_nation_city_parts_mut(nation)?;
        Ok(city.increase_rolling_stock(major))
    }

    /// Spends three lumber and one fabric to add one merchant-capacity unit.
    ///
    /// A major nation without a city has no stockpile, so retail leaves it
    /// unchanged and reports that no merchant marine was built.
    pub fn increase_merchant_marine(&mut self, nation: MajorNationId) -> Result<bool, RuleError> {
        if self.cities[nation].is_none() {
            self.major_nation_parts_mut(nation)?;
            return Ok(false);
        }
        let (_, major, city) = self.major_nation_city_parts_mut(nation)?;
        Ok(city.increase_merchant_marine(major))
    }

    /// Allocates the next transport capacity across the retail city-policy
    /// priority list.
    pub fn allocate_transport_needs(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        self.major_nation_parts_mut(nation)?
            .1
            .allocate_transport_needs();
        Ok(())
    }

    /// Replaces a major nation's merchant capacity with its city's current
    /// industry allocation score.
    pub fn refresh_merchant_capacity(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let capacity = self.cities[nation]
            .as_ref()
            .ok_or(RuleError::MissingCity {
                nation: nation.nation(),
            })?
            .merchant_capacity();
        let (_, major) = self.major_nation_parts_mut(nation)?;
        major.capacities[NationCapacity::MerchantCapacity] = capacity;
        major.capacities[NationCapacity::AvailableMerchant] = capacity;
        Ok(())
    }

    /// Restores the remembered trade bids, constrained by current city stock,
    /// and clears the preceding aid allocations.
    pub fn recall_trade_bids(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let stock_by_type = self.cities[nation]
            .as_ref()
            .map(|city| city.stock_by_type)
            .unwrap_or_default();
        let (_, major) = self.major_nation_parts_mut(nation)?;

        for resource in all_resources() {
            let bid = major.remembered_trade_offers_by_resource[resource];
            if bid == -1 {
                major.unfilled_trade_offer_count += 1;
            }
            major.item_potentials[resource] = bid.min(stock_by_type[resource]);
        }
        major.aid_allocation_by_minor_nation = Default::default();
        Ok(())
    }

    /// Credits a minor nation's resource-specific aid allocation.
    pub fn add_aid_allocation(
        &mut self,
        nation: MajorNationId,
        minor_nation: MinorNationId,
        resource: ResourceKind,
        amount: i32,
    ) -> Result<(), RuleError> {
        let (common, major) = self.major_nation_parts_mut(nation)?;
        common.treasury += amount;
        major.aid_allocation_by_minor_nation[minor_nation][resource] += amount;
        major.aid_allocation_total += amount;
        Ok(())
    }

    /// Sets one current diplomatic grant, refunding the replaced amount before
    /// charging the replacement.
    pub fn set_diplomacy_grant(
        &mut self,
        nation: MajorNationId,
        target: NationId,
        grant: Option<DiplomacyGrant>,
    ) -> Result<bool, RuleError> {
        let (common, major) = self.major_nation_parts_mut(nation)?;
        let current = major.diplomacy_grants_by_nation[target];
        if current == grant {
            return Ok(true);
        }
        let current_amount = current.map_or(0, |grant| grant.amount);
        let proposed_amount = grant.map_or(0, |grant| grant.amount);
        if grant.is_some()
            && current_amount - proposed_amount + major.available_diplomacy_budget(common.treasury)
                < 0
        {
            return Ok(false);
        }

        major.grant_total_cost += proposed_amount - current_amount;
        common.treasury += current_amount - proposed_amount;
        major.diplomacy_grants_by_nation[target] = grant;
        Ok(true)
    }

    /// Clears current diplomacy policies and one-time grants, then posts each
    /// recurring grant through the ordinary treasury path.
    pub fn reset_diplomacy_commitments(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        for target in NationId::all() {
            let recurring_grant = {
                let (_, major) = self.major_nation_parts_mut(nation)?;
                major.diplomacy_policy_by_nation[target] = None;
                let grant = major.diplomacy_grants_by_nation[target];
                major.diplomacy_grants_by_nation[target] = None;
                grant.filter(|grant| grant.flags.contains(DiplomacyGrantFlags::RECURRING))
            };

            if let Some(grant) = recurring_grant {
                let _ = self.set_diplomacy_grant(nation, target, Some(grant))?;
            }
        }
        Ok(())
    }

    /// Applies one recovered decrement to a bilateral trade-policy score.
    pub fn decrement_trade_policy_score(
        &mut self,
        nation: MajorNationId,
        target: NationId,
    ) -> Result<(), RuleError> {
        let (common, _) = self.major_nation_parts_mut(nation)?;
        let next = common.trade_policy_by_nation[target].decrement_step(common.treasury);
        common.trade_policy_by_nation[target] = next;
        Ok(())
    }

    fn major_nation_parts_mut(
        &mut self,
        nation: MajorNationId,
    ) -> Result<(&mut NationCommonState, &mut MajorNationState), RuleError> {
        let state = self.nations[nation.nation()]
            .as_mut()
            .ok_or(RuleError::MissingNation {
                nation: nation.nation(),
            })?;
        state.major_parts_mut().ok_or(RuleError::NotMajorNation {
            nation: nation.nation(),
        })
    }

    fn major_nation_city_parts_mut(
        &mut self,
        nation: MajorNationId,
    ) -> Result<
        (
            &mut NationCommonState,
            &mut MajorNationState,
            &mut CityState,
        ),
        RuleError,
    > {
        let (nations, cities) = (&mut self.nations, &mut self.cities);
        let state = nations[nation.nation()]
            .as_mut()
            .ok_or(RuleError::MissingNation {
                nation: nation.nation(),
            })?;
        let (common, major) = state.major_parts_mut().ok_or(RuleError::NotMajorNation {
            nation: nation.nation(),
        })?;
        let city = cities[nation].as_mut().ok_or(RuleError::MissingCity {
            nation: nation.nation(),
        })?;
        Ok((common, major, city))
    }
}

fn settle_purchase(
    common: &mut NationCommonState,
    major: &mut MajorNationState,
    resource: ResourceKind,
    amount: i16,
    price: i16,
) {
    major.purchased_items_by_resource[resource] += amount;
    let cost = i32::from(price) * i32::from(amount);
    common.treasury -= cost;

    if amount > 0 {
        major.capacities[NationCapacity::AvailableMerchant] -= amount;
        major.budget_pool_delta -= cost;
    } else {
        major.budget_pool_base -= cost;
        if is_special_nation_interaction_resource(resource) {
            major.special_resource_trade_balance -= i32::from(amount);
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
        CityState, Difficulty, DiplomacyGrantFlags, DiplomacyPolicy, IndustryActionSlot, LaborPool,
        MinorNationId, MinorNationTable, NationData, NationState, PendingWorkState,
        PopulationState, RngState, TradePolicyScore, TurnState, WorldState,
    };

    fn major() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: crate::NationCapacityTable::from_array([10, 4, 0, 0]),
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: crate::NationTable::default(),
            diplomacy_grants_by_nation: crate::NationTable::default(),
            need_current_by_type: crate::ResourceTable::default(),
            need_target_by_type: crate::ResourceTable::default(),
            relation_delta_current: crate::ResourceTable::default(),
            purchased_items_by_resource: crate::ResourceTable::default(),
            item_potentials: crate::ResourceTable::default(),
            unfilled_trade_turns_by_resource: crate::ResourceTable::default(),
            transported_items_by_resource: crate::ResourceTable::default(),
            remembered_trade_offers_by_resource: crate::ResourceTable::default(),
            aid_allocation_by_minor_nation: crate::MinorNationTable::default(),
            budget_pool_base: 200,
            budget_pool_delta: 100,
            special_resource_trade_balance: 30,
            candidate_nation_flags: crate::NationTable::default(),
            scenario_initialized: false,
            turn_finished: false,
            pending_action_status: crate::PendingActionTable::default(),
            pending_action_payload_by_action: crate::PendingActionTable::default(),
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: crate::NationTable::default(),
            military_expenses: 0,
        }
    }

    fn state(is_major: bool) -> GameState {
        let nation = NationId::new(6);
        let mut nations = crate::NationTable::default();
        nations[nation] = Some(NationState {
            common: NationCommonState {
                owner_nation: 6,
                treasury: 1_000,
                home_tile: Some(crate::TileId::new(0)),
                trade_policy_by_nation: crate::NationTable::default(),
            },
            data: if is_major {
                NationData::Major(major())
            } else {
                NationData::Minor
            },
        });
        let major_nation = MajorNationId::new(6);
        let mut cities = crate::MajorNationTable::default();
        cities[major_nation] = Some(city());
        GameState {
            turn: TurnState {
                scenario_map_index_plus_one: 0,
                economic_turn: 1,
                phase_code: 5,
                difficulty: Difficulty::Easy,
                active_nation: NationId::new(6),
                selected_nation: NationId::new(6),
            },
            persistent_unit_id_counter: 0,
            world: WorldState {
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
                nations: crate::MajorNationTable::from_fn(|_nation| crate::NationPendingWork {
                    turn_events: vec![],
                    proposals: vec![],
                    turn_summary: vec![],
                    turn_start_events: vec![],
                }),
                war_transitions: vec![],
            },
        }
    }

    fn city() -> CityState {
        CityState {
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            military_recruit_count_by_kind: crate::MilitaryUnitTable::default(),
            civilian_recruit_count_by_kind: crate::CivilianUnitTable::default(),
            order_count_by_type: crate::IndustryActionTable::default(),
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: crate::ResourceTable::default(),
            home_town_tile: Some(crate::TileId::new(0)),
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

    #[test]
    fn buyer_uses_merchant_capacity_and_delta_budget() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        let outcome = game
            .purchase_item(nation, ResourceKind::Fabric, 3, 7)
            .unwrap();
        let state = game.nations[NationId::new(6)].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(state.common.treasury, 979);
        assert_eq!(major.purchased_items_by_resource[ResourceKind::Fabric], 3);
        assert_eq!(major.capacities[NationCapacity::AvailableMerchant], 7);
        assert_eq!(major.budget_pool_delta, 79);
        assert_eq!(major.budget_pool_base, 200);
        assert_eq!(major.special_resource_trade_balance, 30);
        assert_eq!(
            outcome.events,
            vec![GameEvent::TradeSettled {
                nation: nation.nation(),
                resource: ResourceKind::Fabric,
                amount: 3,
                price: 7,
            }]
        );
    }

    #[test]
    fn trade_bid_clamps_to_merchant_capacity_and_reports_the_applied_amount() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        let outcome = game
            .place_trade_bid(nation, ResourceKind::Fabric, 9)
            .unwrap();
        assert_eq!(
            game.nations[NationId::new(6)]
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
                nation: nation.nation(),
                resource: ResourceKind::Fabric,
                amount: 4,
            }]
        );
    }

    #[test]
    fn remembered_bids_and_purchased_items_commit_as_one_trade_phase() {
        let major_nation = MajorNationId::new(6);
        let nation = major_nation.nation();
        let mut game = state(true);
        game.place_trade_bid(major_nation, ResourceKind::Fabric, -1)
            .unwrap();
        game.place_trade_bid(major_nation, ResourceKind::Clothing, -1)
            .unwrap();
        assert_eq!(
            game.remember_trade_bids(major_nation).unwrap().events,
            vec![GameEvent::TradeBidsRemembered { nation }]
        );
        game.purchase_item(major_nation, ResourceKind::Fabric, 3, 7)
            .unwrap();
        game.purchase_item(major_nation, ResourceKind::Food, -30, 1)
            .unwrap();
        game.cities[MajorNationId::new(6)]
            .as_mut()
            .unwrap()
            .stock_by_type[ResourceKind::Food] = 20;

        assert_eq!(
            game.commit_purchased_items(major_nation).unwrap().events,
            vec![GameEvent::PurchasedItemsCommitted { nation }]
        );
        let major = game.nations[NationId::new(6)]
            .as_ref()
            .unwrap()
            .major()
            .unwrap();
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
        let city = game.cities[MajorNationId::new(6)].as_ref().unwrap();
        assert_eq!(city.stock_by_type[ResourceKind::Fabric], 3);
        assert_eq!(city.stock_by_type[ResourceKind::Food], 0);
    }

    #[test]
    fn created_items_credit_precious_metals_and_settle_targets_into_city_stock() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        let major = game.nations[nation.nation()]
            .as_mut()
            .unwrap()
            .major_mut()
            .unwrap();
        major.need_target_by_type[ResourceKind::Cotton] = 2;
        major.need_target_by_type[ResourceKind::Food] = 7;
        major.need_target_by_type[ResourceKind::Fabric] = 1;
        major.need_target_by_type[ResourceKind::Gems] = 3;
        major.need_target_by_type[ResourceKind::Gold] = 4;

        let city = game.cities[MajorNationId::new(6)].as_mut().unwrap();
        city.stock_by_type[ResourceKind::Cotton] = -5;
        city.stock_by_type[ResourceKind::Food] = 3;
        city.stock_by_type[ResourceKind::Fabric] = 5;
        city.stock_by_type[ResourceKind::Steel] = -1;
        city.stock_by_type[ResourceKind::Gems] = 99;
        city.stock_by_type[ResourceKind::Gold] = 99;

        game.add_created_items(nation).unwrap();

        let state = game.nations[nation.nation()].as_ref().unwrap();
        let major = state.major().unwrap();
        let city = game.cities[MajorNationId::new(6)].as_ref().unwrap();
        assert_eq!(state.common.treasury, 3_300);
        assert_eq!(city.stock_by_type[ResourceKind::Cotton], 2);
        assert_eq!(city.stock_by_type[ResourceKind::Food], 10);
        assert_eq!(city.stock_by_type[ResourceKind::Fabric], 6);
        assert_eq!(city.stock_by_type[ResourceKind::Steel], 0);
        assert_eq!(city.stock_by_type[ResourceKind::Gems], 3);
        assert_eq!(city.stock_by_type[ResourceKind::Gold], 4);
        assert_eq!(major.need_target_by_type[ResourceKind::Gems], 3);
        assert_eq!(major.need_target_by_type[ResourceKind::Gold], 4);
    }

    #[test]
    fn diplomacy_grant_settlement_replaces_or_rejects_grants() {
        let nation = MajorNationId::new(6);
        let target = NationId::new(8);
        let mut game = state(true);
        let state = game.nations[nation.nation()].as_mut().unwrap();
        state.common.treasury = 10_000;
        let major = state.major_mut().unwrap();
        major.diplomacy_budget_base = 50_000;
        let recurring_ten_thousand = DiplomacyGrant {
            amount: 10_000,
            flags: DiplomacyGrantFlags::RECURRING,
        };
        assert_eq!(
            game.set_diplomacy_grant(nation, target, Some(recurring_ten_thousand)),
            Ok(true)
        );

        let state = game.nations[nation.nation()].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(state.common.treasury, 0);
        assert_eq!(major.grant_total_cost, 10_000);
        assert_eq!(
            major.diplomacy_grants_by_nation[target],
            Some(recurring_ten_thousand)
        );

        let before_rejected = game.clone();
        assert_eq!(
            game.set_diplomacy_grant(
                nation,
                NationId::new(9),
                Some(DiplomacyGrant {
                    amount: 1_000,
                    flags: DiplomacyGrantFlags::empty(),
                }),
            ),
            Ok(false)
        );
        assert_eq!(game, before_rejected);

        assert_eq!(
            game.set_diplomacy_grant(
                nation,
                target,
                Some(DiplomacyGrant {
                    amount: 3_000,
                    flags: DiplomacyGrantFlags::RECURRING,
                }),
            ),
            Ok(true)
        );
        assert_eq!(game.set_diplomacy_grant(nation, target, None), Ok(true));
        let state = game.nations[nation.nation()].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(state.common.treasury, 10_000);
        assert_eq!(major.grant_total_cost, 0);
        assert_eq!(major.diplomacy_grants_by_nation[target], None);
    }

    #[test]
    fn reset_diplomacy_commitments_reposts_only_recurring_grants() {
        let nation = MajorNationId::new(6);
        let policy_target = NationId::new(0);
        let one_time_target = NationId::new(1);
        let recurring_target = NationId::new(2);
        let recurring_grant = DiplomacyGrant {
            amount: 3_000,
            flags: DiplomacyGrantFlags::RECURRING,
        };
        let mut game = state(true);
        let state = game.nations[nation.nation()].as_mut().unwrap();
        state.common.treasury = 10_000;
        state.major_mut().unwrap().diplomacy_policy_by_nation[policy_target] =
            Some(DiplomacyPolicy::BuildConsulate);
        game.set_diplomacy_grant(
            nation,
            one_time_target,
            Some(DiplomacyGrant {
                amount: 1_000,
                flags: DiplomacyGrantFlags::empty(),
            }),
        )
        .unwrap();
        game.set_diplomacy_grant(nation, recurring_target, Some(recurring_grant))
            .unwrap();

        game.reset_diplomacy_commitments(nation).unwrap();

        let state = game.nations[nation.nation()].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(major.diplomacy_policy_by_nation[policy_target], None);
        assert_eq!(major.diplomacy_grants_by_nation[one_time_target], None);
        assert_eq!(
            major.diplomacy_grants_by_nation[recurring_target],
            Some(recurring_grant)
        );
        assert_eq!(state.common.treasury, 3_000);
        assert_eq!(major.grant_total_cost, 7_000);
    }

    #[test]
    fn decrements_trade_policy_score_through_the_retail_steps() {
        let nation = MajorNationId::new(6);
        let target = NationId::new(0);
        let mut game = state(true);

        for (score, treasury, expected) in [
            (100, 0, 95),
            (95, 0, 90),
            (90, 0, 75),
            (75, 10_000, 75),
            (75, 10_001, 50),
            (300, 50_000, 300),
        ] {
            let common = &mut game.nations[nation.nation()].as_mut().unwrap().common;
            common.trade_policy_by_nation[target] = TradePolicyScore::new(score);
            common.treasury = treasury;

            game.decrement_trade_policy_score(nation, target).unwrap();

            assert_eq!(
                game.nations[nation.nation()]
                    .as_ref()
                    .unwrap()
                    .common
                    .trade_policy_by_nation[target],
                TradePolicyScore::new(expected)
            );
        }
    }

    #[test]
    fn refreshes_merchant_capacity_from_city_industry_weights() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        let city = game.cities[nation].as_mut().unwrap();
        city.order_count_by_type[IndustryActionSlot::Slot1] = 2;
        city.order_count_by_type[IndustryActionSlot::Slot5] = 1;
        city.order_count_by_type[IndustryActionSlot::Slot10] = 1;

        game.refresh_merchant_capacity(nation).unwrap();

        let major = game.nations[nation.nation()]
            .as_ref()
            .unwrap()
            .major()
            .unwrap();
        assert_eq!(major.capacities[NationCapacity::MerchantCapacity], 28);
        assert_eq!(major.capacities[NationCapacity::AvailableMerchant], 28);
    }

    #[test]
    fn recalls_bids_clamps_them_to_stock_and_clears_aid() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        let city = game.cities[nation].as_mut().unwrap();
        city.stock_by_type[ResourceKind::Cotton] = 3;
        city.stock_by_type[ResourceKind::Timber] = 5;

        let major = game.nations[nation.nation()]
            .as_mut()
            .unwrap()
            .major_mut()
            .unwrap();
        major.unfilled_trade_offer_count = 4;
        major.item_potentials[ResourceKind::Cotton] = 99;
        major.remembered_trade_offers_by_resource[ResourceKind::Cotton] = 7;
        major.remembered_trade_offers_by_resource[ResourceKind::Wool] = -1;
        major.remembered_trade_offers_by_resource[ResourceKind::Timber] = 2;
        major.aid_allocation_by_minor_nation[MinorNationId::new(7)][ResourceKind::Cotton] = 8;
        major.aid_allocation_by_minor_nation[MinorNationId::new(14)][ResourceKind::Steel] = 8;
        major.aid_allocation_by_minor_nation[MinorNationId::new(22)][ResourceKind::Gold] = 8;

        game.recall_trade_bids(nation).unwrap();

        let major = game.nations[nation.nation()]
            .as_ref()
            .unwrap()
            .major()
            .unwrap();
        assert_eq!(major.unfilled_trade_offer_count, 5);
        assert_eq!(major.item_potentials[ResourceKind::Cotton], 3);
        assert_eq!(major.item_potentials[ResourceKind::Wool], -1);
        assert_eq!(major.item_potentials[ResourceKind::Timber], 2);
        assert_eq!(
            major.aid_allocation_by_minor_nation,
            MinorNationTable::default()
        );
    }

    #[test]
    fn special_resource_seller_uses_base_budget_and_balance() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        game.purchase_item(nation, ResourceKind::Clothing, -2, 5)
            .unwrap();
        let state = game.nations[NationId::new(6)].as_ref().unwrap();
        let major = state.major().unwrap();
        assert_eq!(state.common.treasury, 1_010);
        assert_eq!(
            major.purchased_items_by_resource[ResourceKind::Clothing],
            -2
        );
        assert_eq!(major.capacities[NationCapacity::AvailableMerchant], 10);
        assert_eq!(major.budget_pool_base, 210);
        assert_eq!(major.budget_pool_delta, 100);
        assert_eq!(major.special_resource_trade_balance, 32);
    }

    #[test]
    fn ordinary_resource_seller_does_not_change_special_balance() {
        let nation = MajorNationId::new(6);
        let mut game = state(true);
        game.purchase_item(nation, ResourceKind::Fabric, -2, 5)
            .unwrap();
        assert_eq!(
            game.nations[NationId::new(6)]
                .as_ref()
                .unwrap()
                .major()
                .unwrap()
                .special_resource_trade_balance,
            30
        );
    }

    #[test]
    fn trade_operations_reject_missing_or_inconsistent_major_state_without_mutation() {
        let nation = MajorNationId::new(6);
        let mut game = state(false);
        let before = game.clone();
        assert_eq!(
            game.purchase_item(nation, ResourceKind::Food, 1, 1),
            Err(RuleError::NotMajorNation {
                nation: nation.nation()
            })
        );
        assert_eq!(game, before);
        assert_eq!(
            game.purchase_item(MajorNationId::new(5), ResourceKind::Food, 1, 1),
            Err(RuleError::MissingNation {
                nation: NationId::new(5)
            })
        );
        assert_eq!(game, before);
    }
}
