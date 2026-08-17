use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorTradeThresholds {
    pub primary_manufactured_price: i16,
    pub secondary_manufactured_price: i16,
    pub general_offer_price: i16,
    pub random_offer_price: i16,
    pub coal_offer_price: i16,
    pub iron_offer_price: i16,
    pub oil_offer_price: i16,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorTradeState {
    pub current_supply: ResourceTable<i16>,
    pub offers: ResourceTable<i16>,
    pub grant_deltas: ResourceTable<i16>,
    pub thresholds: MinorTradeThresholds,
    pub primary_manufactured_request: Option<TradeCommodity>,
    pub secondary_manufactured_request: Option<TradeCommodity>,
    pub primary_request_fulfilled: i16,
    pub secondary_request_fulfilled: i16,
    pub independent_resource_counts: ResourceTable<i16>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForeignTradeBid {
    pub commodity: TradeCommodity,
    pub amount: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForeignTradeState {
    pub interior_bid: Option<ForeignTradeBid>,
    pub phase_counter: i16,
    pub refresh_interval: i16,
    pub requested_ship: ShipType,
    pub purchase_priority: TradeCommodityTable<i16>,
    pub preferred_resources: [Option<TradeCommodity>; 4],
    pub capability_flag_14: i16,
    pub capability_flag_16: i16,
    pub trade_partner_enabled: [bool; 7],
}

impl ForeignTradeState {
    pub(crate) fn for_random_start(personality: ForeignMinisterPersonality) -> Self {
        let refresh_interval = match personality {
            ForeignMinisterPersonality::Arms
            | ForeignMinisterPersonality::Bill
            | ForeignMinisterPersonality::Ted => 4,
            _ => 5,
        };
        let requested_ship = match personality {
            ForeignMinisterPersonality::Arms | ForeignMinisterPersonality::Bill => ShipType::Trader,
            _ => ShipType::Indiaman,
        };
        Self {
            interior_bid: None,
            phase_counter: 0,
            refresh_interval,
            requested_ship,
            purchase_priority: TradeCommodityTable::default(),
            preferred_resources: [None; 4],
            capability_flag_14: 0,
            capability_flag_16: 0,
            trade_partner_enabled: [true; 7],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GreatPowerState {
    /// Retail `TGreatPower::diplomacyEligibilityA0`. Independent of auto-vs-human subclass.
    pub diplomacy_eligible: bool,
    pub foreign_minister_personality: ForeignMinisterPersonality,
    pub foreign_minister_skill_index: i16,
    pub foreign_trade: ForeignTradeState,
    pub development_grant_by_nation: NationTable<i16>,
    pub defense_minister_skill_index: i16,
    pub capacities: NationCapacities,
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: NationTable<Option<DiplomacyPolicy>>,
    pub diplomacy_grants_by_nation: NationTable<Option<DiplomacyGrant>>,
    pub need_current_by_type: ResourceTable<i16>,
    pub need_target_by_type: ResourceTable<i16>,
    pub relation_delta_current: ResourceTable<i16>,
    pub purchased_items_by_resource: ResourceTable<i16>,
    pub item_potentials: ResourceTable<i16>,
    pub unfilled_trade_turns_by_resource: ResourceTable<i16>,
    pub transported_items_by_resource: ResourceTable<i16>,
    pub remembered_trade_offers_by_resource: ResourceTable<i16>,
    pub deal_book: TradeCommodityTable<Vec<TradeDealBookEntry>>,
    pub pending_ship: Option<ShipType>,
    pub interior_civilian: Box<InteriorCivilianState>,
    pub aid_allocation_by_minor_nation: MinorNationTable<ResourceTable<i32>>,
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub special_resource_trade_balance: i32,
    pub scenario_initialized: bool,
    pub turn_finished: bool,
    pub pending_actions: PendingActionTable<PendingActionState>,
    pub candidate_nation_flags: NationTable<u8>,
    pub colony_boycott_flags: NationTable<u8>,
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i16,
    pub army_movement_budget: i32,
    pub aid_allocation_total: i32,
    pub military_expenses: i32,
}

impl GreatPowerState {
    /// The post-`IGreatPower`/`IAutoGreatPower` construction state a major nation
    /// carries at the random-game start boundary. Only the human is diplomacy
    /// eligible before capital selection.
    pub(crate) fn for_random_start(
        human: bool,
        difficulty: Difficulty,
        foreign_minister_personality: ForeignMinisterPersonality,
    ) -> Self {
        let (diplomacy_budget_base, escalation_counter) = match difficulty {
            Difficulty::Introductory => (100_000, 8),
            Difficulty::Easy => (50_000, 10),
            Difficulty::Normal => (20_000, 12),
            Difficulty::Hard => (10_000, 15),
            Difficulty::NighOnImpossible => (1_000, 19),
        };
        Self {
            diplomacy_eligible: human,
            foreign_minister_personality,
            foreign_minister_skill_index: foreign_minister_personality.initial_skill_index(),
            foreign_trade: ForeignTradeState::for_random_start(foreign_minister_personality),
            development_grant_by_nation: NationTable::default(),
            defense_minister_skill_index: 0,
            capacities: NationCapacities::from_array([0, 0, 0x0f, 0]),
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: NationTable::default(),
            diplomacy_grants_by_nation: NationTable::default(),
            need_current_by_type: ResourceTable::default(),
            need_target_by_type: ResourceTable::default(),
            relation_delta_current: ResourceTable::default(),
            purchased_items_by_resource: ResourceTable::default(),
            item_potentials: ResourceTable::default(),
            unfilled_trade_turns_by_resource: ResourceTable::default(),
            transported_items_by_resource: ResourceTable::default(),
            remembered_trade_offers_by_resource: ResourceTable::default(),
            deal_book: TradeCommodityTable::default(),
            pending_ship: None,
            interior_civilian: Box::new(InteriorCivilianState::for_random_start(human)),
            aid_allocation_by_minor_nation: MinorNationTable::default(),
            budget_pool_base: 0,
            budget_pool_delta: 0,
            special_resource_trade_balance: 0,
            scenario_initialized: false,
            turn_finished: true,
            pending_actions: PendingActionTable::default(),
            candidate_nation_flags: NationTable::default(),
            colony_boycott_flags: NationTable::default(),
            diplomacy_budget_base,
            escalation_counter,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            army_movement_budget: 0x0f,
            aid_allocation_total: 0,
            military_expenses: 0,
        }
    }
}

const TRANSPORT_NEED_PRIORITY: [ResourceKind; 10] = [
    ResourceKind::Grain,
    ResourceKind::Fruit,
    ResourceKind::Livestock,
    ResourceKind::Fish,
    ResourceKind::Timber,
    ResourceKind::Coal,
    ResourceKind::Iron,
    ResourceKind::Cotton,
    ResourceKind::Wool,
    ResourceKind::Horses,
];

impl GreatPowerState {
    /// Mirrors the inline `TGreatPower::ComputeAvailableDiplomacyBudget` clamp.
    pub fn available_diplomacy_budget(&self, treasury: i32) -> i32 {
        (treasury + self.diplomacy_budget_base / 100).max(0)
    }

    pub(crate) fn update_need_target(&mut self, resource: ResourceKind, value: i16) {
        let target = &mut self.need_target_by_type[resource];
        self.capacities.reserved_transport += value - *target;
        *target = value;
    }

    pub(crate) fn allocate_transport_needs(&mut self) {
        for resource in TRANSPORT_NEED_PRIORITY {
            let headroom = self.capacities.transport - self.capacities.reserved_transport;
            if headroom == 0 {
                break;
            }
            self.update_need_target(resource, self.need_current_by_type[resource].min(headroom));
        }
    }

    pub fn deliver_item(&mut self, amount: i16) {
        self.capacities.available_merchant -= amount;
    }

    pub fn amount_unsold(&self, resource: ResourceKind) -> i16 {
        self.item_potentials[resource] + self.purchased_items_by_resource[resource]
    }

    pub fn advanced_manufactured_offers_exhausted(&self) -> bool {
        for resource in [
            ResourceKind::Clothing,
            ResourceKind::Furniture,
            ResourceKind::Hardware,
            ResourceKind::Arms,
        ] {
            let potential = self.item_potentials[resource];
            if potential > 0
                && i32::from(self.purchased_items_by_resource[resource]) + i32::from(potential) > 0
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn set_item_potential(&mut self, resource: ResourceKind, value: i16) {
        self.item_potentials[resource] = value.min(self.capacities.trade_offer);
    }

    pub(crate) fn remember_trade_bids(&mut self) {
        self.remembered_trade_offers_by_resource
            .clone_from(&self.item_potentials);
    }

    pub fn clear_trade_offer(&mut self, resource: ResourceKind) {
        self.item_potentials[resource] = 0;
    }

    pub fn is_still_buying(&self, resource: ResourceKind) -> bool {
        self.capacities.available_merchant > 0 && self.item_potentials[resource] < 0
    }

    pub(crate) fn settle_transported_items(&mut self, city: &mut CityState) {
        for resource in all_resources() {
            let amount = self.transported_items_by_resource[resource];
            city.adjust_stock(resource, amount);
            self.transported_items_by_resource[resource] = 0;
        }
    }

    pub(crate) fn settle_purchased_items(&mut self, city: &mut CityState) {
        for resource in all_resources() {
            let purchased = self.purchased_items_by_resource[resource];
            city.adjust_stock(resource, purchased);
            if self.remembered_trade_offers_by_resource[resource] == -1 && purchased == 0 {
                self.unfilled_trade_turns_by_resource[resource] += 1;
            } else {
                self.unfilled_trade_turns_by_resource[resource] = 0;
            }
            self.purchased_items_by_resource[resource] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn city() -> CityState {
        crate::test_support::city()
    }

    fn nation() -> GreatPowerState {
        let mut nation = crate::test_support::great_power_state();
        nation.capacities = crate::NationCapacities::from_array([0, 0, 15, 11]);
        nation
    }

    #[test]
    fn clamps_the_available_diplomacy_budget() {
        let mut state = nation();
        state.diplomacy_budget_base = 250;
        assert_eq!(state.available_diplomacy_budget(10), 12);
        assert_eq!(state.available_diplomacy_budget(-2), 0);
        assert_eq!(state.available_diplomacy_budget(-20), 0);
    }

    #[test]
    fn updates_current_target_and_reserved_capacity() {
        let mut state = nation();
        let resource = ResourceKind::Steel;
        state.need_current_by_type[resource] = 10;
        state.update_need_target(resource, 7);
        assert_eq!(state.need_target_by_type[resource], 7);
        assert_eq!(state.capacities.reserved_transport, 18);
        state.update_need_target(resource, 3);
        assert_eq!(state.capacities.reserved_transport, 14);
    }

    #[test]
    fn trade_offer_leaves_preserve_capacity() {
        let mut state = nation();
        state.capacities.available_merchant = 5;
        state.capacities.trade_offer = 3;
        state.deliver_item(2);
        assert_eq!(state.capacities.available_merchant, 3);

        let resource = ResourceKind::Coal;
        state.set_item_potential(resource, 7);
        assert_eq!(state.item_potentials[resource], 3);
        state.set_item_potential(resource, -1);
        assert!(state.is_still_buying(resource));
        state.purchased_items_by_resource[resource] = 4;
        assert_eq!(state.amount_unsold(resource), 3);
        state.clear_trade_offer(resource);
        assert!(!state.is_still_buying(resource));
    }

    #[test]
    fn advanced_manufactured_exhaustion_uses_only_resources_thirteen_through_sixteen() {
        let mut state = nation();
        state.item_potentials[ResourceKind::Steel] = 10;
        state.item_potentials[ResourceKind::Clothing] = 2;
        state.purchased_items_by_resource[ResourceKind::Clothing] = -2;
        assert!(state.advanced_manufactured_offers_exhausted());

        state.purchased_items_by_resource[ResourceKind::Clothing] = -1;
        assert!(!state.advanced_manufactured_offers_exhausted());
    }

    #[test]
    fn purchased_settlement_tracks_only_unfilled_requested_offers() {
        let mut state = nation();
        let mut owner_city = city();
        let cotton = ResourceKind::Cotton;
        let wool = ResourceKind::Wool;
        let timber = ResourceKind::Timber;
        state.remembered_trade_offers_by_resource[cotton] = -1;
        state.unfilled_trade_turns_by_resource[cotton] = 3;
        state.remembered_trade_offers_by_resource[wool] = -1;
        state.purchased_items_by_resource[wool] = 2;
        state.unfilled_trade_turns_by_resource[wool] = 9;
        state.unfilled_trade_turns_by_resource[timber] = 9;

        state.settle_purchased_items(&mut owner_city);
        assert_eq!(state.unfilled_trade_turns_by_resource[cotton], 4);
        assert_eq!(state.unfilled_trade_turns_by_resource[wool], 0);
        assert_eq!(state.unfilled_trade_turns_by_resource[timber], 0);
        assert_eq!(owner_city.stockpile[wool], 2);
        assert!(
            state
                .purchased_items_by_resource
                .iter()
                .all(|(_, amount)| *amount == 0)
        );
    }

    #[test]
    fn allocates_transport_needs_in_retail_priority_order() {
        let mut state = nation();
        state.capacities.transport = 8;
        state.capacities.reserved_transport = 2;
        state.need_current_by_type[ResourceKind::Grain] = 4;
        state.need_current_by_type[ResourceKind::Fruit] = 3;
        state.need_current_by_type[ResourceKind::Livestock] = 6;

        state.allocate_transport_needs();

        assert_eq!(state.need_target_by_type[ResourceKind::Grain], 4);
        assert_eq!(state.need_target_by_type[ResourceKind::Fruit], 2);
        assert_eq!(state.need_target_by_type[ResourceKind::Livestock], 0);
        assert_eq!(state.capacities.reserved_transport, 8);
    }
}
