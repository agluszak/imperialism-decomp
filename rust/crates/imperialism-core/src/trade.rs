use crate::{
    GameState, MajorNationId, MajorNationState, NationCommonState, ResourceKind, StateError,
    all_resources,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuleError {
    #[error("major nation {} is not present", .nation.get())]
    MissingMajorNation { nation: MajorNationId },
    #[error("major nation {} has no city state", .nation.get())]
    MissingCity { nation: MajorNationId },
    #[error("nation {} cannot run the player trade phase", .nation.get())]
    PlayerTradePhaseUnavailable { nation: MajorNationId },
}

impl From<StateError> for RuleError {
    fn from(value: StateError) -> Self {
        match value {
            StateError::MissingMajorNation { nation } => Self::MissingMajorNation { nation },
            StateError::MissingCity { nation } => Self::MissingCity { nation },
            StateError::MissingMinorNation { nation } => {
                panic!(
                    "trade path received missing minor nation {}",
                    nation.nation().get()
                )
            }
        }
    }
}

impl GameState {
    pub fn place_trade_bid(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        amount: i16,
    ) -> Result<i16, RuleError> {
        let major = &mut self.major_mut(nation)?.state;
        major.set_item_potential(resource, amount);
        Ok(major.item_potentials[resource])
    }

    pub fn purchase_item(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        amount: i16,
        price: i16,
    ) -> Result<(), RuleError> {
        let major = self.major_mut(nation)?;
        settle_purchase(&mut major.common, &mut major.state, resource, amount, price);
        Ok(())
    }

    pub fn remember_trade_bids(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        self.major_mut(nation)?.state.remember_trade_bids();
        Ok(())
    }

    pub fn commit_purchased_items(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (_, major, city) = self.major_city_parts_mut(nation)?;
        major.settle_purchased_items(city);
        Ok(())
    }

    /// Replaces a major nation's merchant capacity with its city's current
    /// industry allocation score.
    pub fn refresh_merchant_capacity(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (_, major, city) = self.major_city_parts_mut(nation)?;
        let capacity = city.merchant_capacity();
        major.capacities.trade_offer = capacity;
        major.capacities.available_merchant = capacity;
        Ok(())
    }

    /// Restores the remembered trade bids, constrained by current city stock,
    /// and clears the preceding aid allocations.
    pub fn recall_trade_bids(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (_, major, city) = self.major_city_parts_mut(nation)?;
        let stock_by_type = city.stock_by_type;

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

    /// Resets the retail player trade phase.
    ///
    /// Nations outside this mode use a different retail virtual implementation
    /// and remain unsupported until that behavior has a semantic state model.
    pub fn reset_player_trade_phase(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        if !self.major_mut(nation)?.state.diplomacy_eligible {
            return Err(RuleError::PlayerTradePhaseUnavailable { nation });
        }

        self.refresh_merchant_capacity(nation)?;
        let major = &mut self.major_mut(nation)?.state;
        major.unfilled_trade_offer_count = 0;
        major.budget_pool_base = 0;
        major.budget_pool_delta = 0;
        self.recall_trade_bids(nation)
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
        major.capacities.available_merchant -= amount;
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
    use crate::{MinorNationId, MinorNationTable, ResourceKind, test_support};

    fn trade_game() -> GameState {
        let mut game = test_support::game_state();
        let major = game.major_mut(MajorNationId::new(6)).unwrap();
        major.state.budget_pool_base = 200;
        major.state.budget_pool_delta = 100;
        major.state.special_resource_trade_balance = 30;
        game
    }

    #[test]
    fn buyer_uses_merchant_capacity_and_delta_budget() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        game.purchase_item(nation, ResourceKind::Fabric, 3, 7)
            .unwrap();
        let major = game.major(nation).unwrap();
        assert_eq!(major.common.treasury, 979);
        assert_eq!(
            major.state.purchased_items_by_resource[ResourceKind::Fabric],
            3
        );
        assert_eq!(major.state.capacities.available_merchant, 7);
        assert_eq!(major.state.budget_pool_delta, 79);
        assert_eq!(major.state.budget_pool_base, 200);
        assert_eq!(major.state.special_resource_trade_balance, 30);
    }

    #[test]
    fn trade_bid_clamps_to_merchant_capacity_and_reports_the_applied_amount() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        let applied = game
            .place_trade_bid(nation, ResourceKind::Fabric, 9)
            .unwrap();
        assert_eq!(applied, 4);
        assert_eq!(
            game.major(nation).unwrap().state.item_potentials[ResourceKind::Fabric],
            4
        );
    }

    #[test]
    fn remembered_bids_and_purchased_items_commit_as_one_trade_phase() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        game.place_trade_bid(nation, ResourceKind::Fabric, -1)
            .unwrap();
        game.place_trade_bid(nation, ResourceKind::Clothing, -1)
            .unwrap();
        game.remember_trade_bids(nation).unwrap();
        game.purchase_item(nation, ResourceKind::Fabric, 3, 7)
            .unwrap();
        game.purchase_item(nation, ResourceKind::Food, -30, 1)
            .unwrap();
        game.major_mut(nation)
            .unwrap()
            .city
            .as_mut()
            .unwrap()
            .stock_by_type[ResourceKind::Food] = 20;

        game.commit_purchased_items(nation).unwrap();
        let major = game.major(nation).unwrap();
        assert!(
            major
                .state
                .purchased_items_by_resource
                .iter()
                .all(|(_, amount)| *amount == 0)
        );
        assert_eq!(
            major.state.unfilled_trade_turns_by_resource[ResourceKind::Fabric],
            0
        );
        assert_eq!(
            major.state.unfilled_trade_turns_by_resource[ResourceKind::Clothing],
            1
        );
        let city = major.city.as_ref().unwrap();
        assert_eq!(city.stock_by_type[ResourceKind::Fabric], 3);
        assert_eq!(city.stock_by_type[ResourceKind::Food], 0);
    }

    #[test]
    fn refreshes_merchant_capacity_from_city_industry_weights() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        let city = game.major_mut(nation).unwrap().city.as_mut().unwrap();
        city.order_count_by_type[1] = 2;
        city.order_count_by_type[5] = 1;
        city.order_count_by_type[10] = 1;

        game.refresh_merchant_capacity(nation).unwrap();

        let major = &game.major(nation).unwrap().state;
        assert_eq!(major.capacities.trade_offer, 28);
        assert_eq!(major.capacities.available_merchant, 28);
    }

    #[test]
    fn recalls_bids_clamps_them_to_stock_and_clears_aid() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        {
            let major = game.major_mut(nation).unwrap();
            let city = major.city.as_mut().unwrap();
            city.stock_by_type[ResourceKind::Cotton] = 3;
            city.stock_by_type[ResourceKind::Timber] = 5;
            major.state.unfilled_trade_offer_count = 4;
            major.state.item_potentials[ResourceKind::Cotton] = 99;
            major.state.remembered_trade_offers_by_resource[ResourceKind::Cotton] = 7;
            major.state.remembered_trade_offers_by_resource[ResourceKind::Wool] = -1;
            major.state.remembered_trade_offers_by_resource[ResourceKind::Timber] = 2;
            major.state.aid_allocation_by_minor_nation[MinorNationId::new(7)]
                [ResourceKind::Cotton] = 8;
            major.state.aid_allocation_by_minor_nation[MinorNationId::new(14)]
                [ResourceKind::Steel] = 8;
            major.state.aid_allocation_by_minor_nation[MinorNationId::new(22)]
                [ResourceKind::Gold] = 8;
        }

        game.recall_trade_bids(nation).unwrap();

        let major = &game.major(nation).unwrap().state;
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
    fn recall_trade_bids_requires_a_city() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        game.major_mut(nation).unwrap().city = None;
        assert_eq!(
            game.recall_trade_bids(nation),
            Err(RuleError::MissingCity { nation })
        );
    }

    #[test]
    fn special_resource_seller_uses_base_budget_and_balance() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        game.purchase_item(nation, ResourceKind::Clothing, -2, 5)
            .unwrap();
        let major = game.major(nation).unwrap();
        assert_eq!(major.common.treasury, 1_010);
        assert_eq!(
            major.state.purchased_items_by_resource[ResourceKind::Clothing],
            -2
        );
        assert_eq!(major.state.capacities.available_merchant, 10);
        assert_eq!(major.state.budget_pool_base, 210);
        assert_eq!(major.state.budget_pool_delta, 100);
        assert_eq!(major.state.special_resource_trade_balance, 32);
    }

    #[test]
    fn ordinary_resource_seller_does_not_change_special_balance() {
        let nation = MajorNationId::new(6);
        let mut game = trade_game();
        game.purchase_item(nation, ResourceKind::Fabric, -2, 5)
            .unwrap();
        assert_eq!(
            game.major(nation)
                .unwrap()
                .state
                .special_resource_trade_balance,
            30
        );
    }

    #[test]
    fn trade_operations_reject_missing_major_state_without_mutation() {
        let mut game = trade_game();
        let before = game.clone();
        assert_eq!(
            game.purchase_item(MajorNationId::new(5), ResourceKind::Food, 1, 1),
            Err(RuleError::MissingMajorNation {
                nation: MajorNationId::new(5)
            })
        );
        assert_eq!(game, before);
    }
}
