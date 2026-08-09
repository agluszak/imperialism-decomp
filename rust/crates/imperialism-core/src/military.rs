use crate::{GameState, MajorNation, MajorNationId, ShipTypeTable};

const MILITARY_MAINTENANCE_MULTIPLIER: i32 = 25;

const NAVY_ARMS_BY_SHIP_TYPE: ShipTypeTable<i32> =
    ShipTypeTable::from_array([0, 0, 0, 2, 5, 0, 0, 3, 6, 15, 0, 8, 24, 18]);

impl GameState {
    /// Charges one major nation for its current army and navy.
    pub fn pay_for_military(&mut self, nation: MajorNationId) {
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

        let MajorNation {
            common,
            economy: major,
            ..
        } = &mut self.nations.majors[nation];
        major.military_expenses = charge;
        common.treasury -= charge;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NationId, OceanZoneId, ShipState, ShipType, test_support};

    fn ship(ship_type: ShipType, nation: NationId) -> ShipState {
        ShipState {
            ship_type,
            location: OceanZoneId::new(0),
            task_force: None,
            aggression: 1,
            nation,
            name: String::new(),
            strength: 1,
            experience: 0,
            selection: 0,
        }
    }

    #[test]
    fn charges_owned_navy_and_ignores_foreign_ships() {
        let mut state = test_support::game_state();
        let nation = MajorNationId::new(6);
        state.nations.majors[nation].common.treasury = 10_000;
        state.ships = vec![
            ship(ShipType::Frigate, nation.nation()),
            ship(ShipType::AdvancedIronclad, nation.nation()),
            ship(ShipType::Dreadnought, nation.nation()),
            ship(ShipType::Dreadnought, NationId::new(0)),
        ];

        state.pay_for_military(nation);

        assert_eq!(
            state.nations.majors[nation].economy.military_expenses,
            1_025
        );
        assert_eq!(state.nations.majors[nation].common.treasury, 8_975);
    }
}
