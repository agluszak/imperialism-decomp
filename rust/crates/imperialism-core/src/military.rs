use crate::{GameState, IndustryActionTable, MajorNationId, RuleError};

const MILITARY_MAINTENANCE_MULTIPLIER: i32 = 25;

const NAVY_ARMS_BY_SHIP_TYPE: IndustryActionTable<i32> =
    IndustryActionTable::from_array([0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18]);

impl GameState {
    /// Charges one major nation for its current army and navy.
    pub fn pay_for_military(&mut self, nation: MajorNationId) -> Result<(), RuleError> {
        let nation_id = nation.nation();
        let arms = self
            .military_units
            .iter()
            .filter(|unit| unit.nation == nation_id)
            .map(|unit| unit.unit_type.arms_required())
            .sum::<i32>()
            + self
                .ships
                .iter()
                .filter(|ship| ship.nation == nation_id)
                .map(|ship| NAVY_ARMS_BY_SHIP_TYPE[ship.ship_type])
                .sum::<i32>();
        let charge = arms * MILITARY_MAINTENANCE_MULTIPLIER;

        let (common, major) = self.major_nation_parts_mut(nation)?;
        major.military_expenses = charge;
        common.treasury -= charge;
        Ok(())
    }
}
