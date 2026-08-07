use crate::{
    GameCommand, GameEvent, GameState, MajorNationState, NationId, NationKind, NationState,
    ResourceKind, StepOutcome,
};
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleError {
    MissingNation { nation: NationId },
    NotMajorNation { nation: NationId },
    InvalidResourceCount { nation: NationId, actual: usize },
}

impl fmt::Display for RuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingNation { nation } => {
                write!(formatter, "nation {} is not present", nation.get())
            }
            Self::NotMajorNation { nation } => {
                write!(formatter, "nation {} is not a major nation", nation.get())
            }
            Self::InvalidResourceCount { nation, actual } => write!(
                formatter,
                "nation {} has {actual} purchased-item entries, expected {}",
                nation.get(),
                ResourceKind::COUNT
            ),
        }
    }
}

impl Error for RuleError {}

impl GameState {
    pub fn apply_command(&mut self, command: GameCommand) -> Result<StepOutcome, RuleError> {
        match command {
            GameCommand::PurchaseItem {
                nation,
                resource,
                amount,
                price,
            } => {
                let state = self.major_nation_mut(nation)?;
                settle_purchase(state, nation, resource, amount, price)?;
                Ok(StepOutcome {
                    events: vec![GameEvent::TradeSettled {
                        nation,
                        resource,
                        amount,
                        price,
                    }],
                })
            }
        }
    }

    fn major_nation_mut(&mut self, nation: NationId) -> Result<&mut NationState, RuleError> {
        let state = self
            .nations
            .get_mut(usize::from(nation.get()))
            .and_then(Option::as_mut)
            .ok_or(RuleError::MissingNation { nation })?;
        if state.kind != NationKind::Major || state.major.is_none() {
            return Err(RuleError::NotMajorNation { nation });
        }
        Ok(state)
    }
}

fn settle_purchase(
    nation: &mut NationState,
    nation_id: NationId,
    resource: ResourceKind,
    amount: i16,
    price: i16,
) -> Result<(), RuleError> {
    let major = nation
        .major
        .as_mut()
        .expect("major-nation presence was checked before settlement");
    validate_purchased_items(major, nation_id)?;

    let index = resource.index();
    major.purchased_items_by_resource[index] =
        major.purchased_items_by_resource[index].wrapping_add(amount);
    let cost = i32::from(price).wrapping_mul(i32::from(amount));
    nation.treasury = nation.treasury.wrapping_sub(cost);

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
    Ok(())
}

fn validate_purchased_items(major: &MajorNationState, nation: NationId) -> Result<(), RuleError> {
    let actual = major.purchased_items_by_resource.len();
    if actual == ResourceKind::COUNT {
        Ok(())
    } else {
        Err(RuleError::InvalidResourceCount { nation, actual })
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
    use crate::{PendingWorkState, RngState, TurnState, WorldState};

    fn major() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: [10, 0, 0, 0],
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: vec![0; ResourceKind::COUNT],
            diplomacy_grant_by_nation: vec![0; ResourceKind::COUNT],
            need_current_by_type: vec![0; ResourceKind::COUNT],
            need_target_by_type: vec![0; ResourceKind::COUNT],
            relation_delta_current: vec![0; ResourceKind::COUNT],
            purchased_items_by_resource: vec![0; ResourceKind::COUNT],
            item_potentials: vec![0; ResourceKind::COUNT],
            unfilled_trade_turns_by_resource: vec![0; ResourceKind::COUNT],
            transported_items_by_resource: vec![0; ResourceKind::COUNT],
            remembered_trade_offers_by_resource: vec![0; ResourceKind::COUNT],
            aid_allocation_matrix: vec![0; 23 * 23],
            budget_pool_base: 200,
            budget_pool_delta: 100,
            special_resource_trade_balance: 30,
            candidate_nation_flags: vec![0; 23],
            scenario_initialized: false,
            turn_finished: false,
            pending_action_status: vec![0; 13],
            pending_action_payload_by_action: vec![0; 13],
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: vec![0; 23],
            military_expenses: 0,
        }
    }

    fn state(kind: NationKind) -> GameState {
        let nation = NationId::new(6);
        let mut nations = vec![None; 23];
        nations[6] = Some(NationState {
            id: nation,
            kind,
            encoded_nation_slot: 6,
            owner_nation: 6,
            treasury: 1_000,
            home_tile: 0,
            need_level_by_nation: vec![0; 23],
            major: (kind == NationKind::Major).then(major),
        });
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
            cities: vec![],
            military_units: vec![],
            civilian_units: vec![],
            ships: vec![],
            task_forces: vec![],
            missions: vec![],
            pending: PendingWorkState {
                turn_flow_status_flags: 0,
                nations: vec![],
                war_transitions: vec![],
            },
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
        let mut game = state(NationKind::Major);
        let outcome = game
            .apply_command(purchase(nation, ResourceKind::Fabric, 3, 7))
            .unwrap();
        let state = game.nations[6].as_ref().unwrap();
        let major = state.major.as_ref().unwrap();
        assert_eq!(state.treasury, 979);
        assert_eq!(
            major.purchased_items_by_resource[ResourceKind::Fabric.index()],
            3
        );
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
    fn special_resource_seller_uses_base_budget_and_balance() {
        let nation = NationId::new(6);
        let mut game = state(NationKind::Major);
        game.apply_command(purchase(nation, ResourceKind::Clothing, -2, 5))
            .unwrap();
        let state = game.nations[6].as_ref().unwrap();
        let major = state.major.as_ref().unwrap();
        assert_eq!(state.treasury, 1_010);
        assert_eq!(
            major.purchased_items_by_resource[ResourceKind::Clothing.index()],
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
        let mut game = state(NationKind::Major);
        game.apply_command(purchase(nation, ResourceKind::Fabric, -2, 5))
            .unwrap();
        assert_eq!(
            game.nations[6]
                .as_ref()
                .unwrap()
                .major
                .as_ref()
                .unwrap()
                .special_resource_trade_balance,
            30
        );
    }

    #[test]
    fn command_rejects_missing_minor_and_malformed_nation_state() {
        let nation = NationId::new(6);
        let mut game = state(NationKind::Minor);
        assert_eq!(
            game.apply_command(purchase(nation, ResourceKind::Food, 1, 1)),
            Err(RuleError::NotMajorNation { nation })
        );
        assert_eq!(
            game.apply_command(purchase(NationId::new(5), ResourceKind::Food, 1, 1)),
            Err(RuleError::MissingNation {
                nation: NationId::new(5)
            })
        );

        let mut malformed = state(NationKind::Major);
        malformed.nations[6]
            .as_mut()
            .unwrap()
            .major
            .as_mut()
            .unwrap()
            .purchased_items_by_resource
            .pop();
        assert_eq!(
            malformed.apply_command(purchase(nation, ResourceKind::Food, 1, 1)),
            Err(RuleError::InvalidResourceCount { nation, actual: 22 })
        );
        assert_eq!(malformed.nations[6].as_ref().unwrap().treasury, 1_000);
    }
}
