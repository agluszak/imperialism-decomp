use crate::{GameState, MajorNation, MajorNationId};

const MILITARY_MAINTENANCE_MULTIPLIER: i32 = 25;

impl GameState {
    /// Charges one major nation for its current army.
    pub fn pay_for_military(&mut self, nation: MajorNationId) {
        let nation_id = nation.nation();
        let arms = self
            .military_units
            .iter()
            .filter(|unit| unit.nation == nation_id)
            .map(|unit| unit.unit_type.arms_required())
            .sum::<i32>();
        let charge = arms * MILITARY_MAINTENANCE_MULTIPLIER;

        let MajorNation {
            common,
            economy: major,
            ..
        } = &mut self.nations.majors[nation];
        major.military_expenses = charge;
        common.treasury -= charge;
    }
}
