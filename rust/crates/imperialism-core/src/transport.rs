use crate::{GameState, MajorNationId, ResourceKind, RuleError, all_resources};

impl GameState {
    /// Settles the nation's transported-item ledger into city stock.
    pub fn settle_transported_items(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (_, major, city) = self.major_city_parts_mut(nation)?;
        major.settle_transported_items(city);
        Ok(())
    }

    /// Mirrors `TGreatPower::AddCreatedItems` at the city-and-transport phase
    /// boundary. Commodity targets remain available for the rest of the phase;
    /// only the city's settled stock changes here.
    pub fn add_created_items(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let (common, major, city) = self.major_city_parts_mut(nation)?;

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

    /// Moves one resource into city stock, limited by both the resource need
    /// and unused transport capacity.
    pub fn direct_transport(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
    ) -> Result<i16, RuleError> {
        let (_, major, city) = self.major_city_parts_mut(nation)?;
        Ok(city.direct_transport(major, resource, requested))
    }

    /// Spends one lumber and one steel to add one transport-capacity unit.
    ///
    /// A major nation without a city has no stockpile, so retail leaves it
    /// unchanged and reports that no rolling stock was built.
    pub fn increase_rolling_stock(&mut self, nation: MajorNationId) -> Result<bool, RuleError> {
        let major = self.major_mut(nation)?;
        let Some(city) = major.city.as_mut() else {
            return Ok(false);
        };
        Ok(city.increase_rolling_stock(&mut major.state))
    }

    /// Spends three lumber and one fabric to add one merchant-capacity unit.
    ///
    /// A major nation without a city has no stockpile, so retail leaves it
    /// unchanged and reports that no merchant marine was built.
    pub fn increase_merchant_marine(&mut self, nation: MajorNationId) -> Result<bool, RuleError> {
        let major = self.major_mut(nation)?;
        let Some(city) = major.city.as_mut() else {
            return Ok(false);
        };
        Ok(city.increase_merchant_marine(&mut major.state))
    }

    /// Allocates the next transport capacity across the retail city-policy
    /// priority list.
    pub fn allocate_transport_needs(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        self.major_mut(nation)?.state.allocate_transport_needs();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn created_items_credit_precious_metals_and_settle_targets_into_city_stock() {
        let nation = MajorNationId::new(6);
        let mut game = test_support::game_state();
        {
            let major = game.major_mut(nation).unwrap();
            major.state.need_target_by_type[ResourceKind::Cotton] = 2;
            major.state.need_target_by_type[ResourceKind::Food] = 7;
            major.state.need_target_by_type[ResourceKind::Fabric] = 1;
            major.state.need_target_by_type[ResourceKind::Gems] = 3;
            major.state.need_target_by_type[ResourceKind::Gold] = 4;

            let city = major.city.as_mut().unwrap();
            city.stock_by_type[ResourceKind::Cotton] = -5;
            city.stock_by_type[ResourceKind::Food] = 3;
            city.stock_by_type[ResourceKind::Fabric] = 5;
            city.stock_by_type[ResourceKind::Steel] = -1;
            city.stock_by_type[ResourceKind::Gems] = 99;
            city.stock_by_type[ResourceKind::Gold] = 99;
        }

        game.add_created_items(nation).unwrap();

        let major = game.major(nation).unwrap();
        let city = major.city.as_ref().unwrap();
        assert_eq!(major.common.treasury, 3_300);
        assert_eq!(city.stock_by_type[ResourceKind::Cotton], 2);
        assert_eq!(city.stock_by_type[ResourceKind::Food], 10);
        assert_eq!(city.stock_by_type[ResourceKind::Fabric], 6);
        assert_eq!(city.stock_by_type[ResourceKind::Steel], 0);
        assert_eq!(city.stock_by_type[ResourceKind::Gems], 3);
        assert_eq!(city.stock_by_type[ResourceKind::Gold], 4);
        assert_eq!(major.state.need_target_by_type[ResourceKind::Gems], 3);
        assert_eq!(major.state.need_target_by_type[ResourceKind::Gold], 4);
    }

    #[test]
    fn rolling_stock_without_city_is_a_no_op() {
        let nation = MajorNationId::new(6);
        let mut game = test_support::game_state();
        game.major_mut(nation).unwrap().city = None;
        assert_eq!(game.increase_rolling_stock(nation), Ok(false));
    }

    #[test]
    fn merchant_marine_without_city_is_a_no_op() {
        let nation = MajorNationId::new(6);
        let mut game = test_support::game_state();
        game.major_mut(nation).unwrap().city = None;
        assert_eq!(game.increase_merchant_marine(nation), Ok(false));
    }

    #[test]
    fn missing_major_rejects_transport_ops() {
        let mut game = test_support::game_state();
        let missing = MajorNationId::new(5);
        assert_eq!(
            game.increase_rolling_stock(missing),
            Err(RuleError::MissingMajorNation { nation: missing })
        );
    }
}
