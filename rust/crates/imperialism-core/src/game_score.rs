//! `TGreatPower::GenerateGameScore` (0x004e32a0).

use crate::*;

const DIFFICULTY_PERCENT: [i32; 5] = [10, 15, 20, 25, 30];

/// Twelve rows written to `gameScoreRows930` and shown by `TGameScorePicture`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GameScore {
    pub labor: i32,
    pub transport: i32,
    pub industry: i32,
    pub provinces: i32,
    pub military: i32,
    pub navy: i32,
    pub diplomacy: i32,
    pub merchant_marine: i32,
    pub year: i32,
    pub subtotal: i32,
    pub difficulty_percent: i32,
    pub total: i32,
}

impl GameScore {
    pub fn rows(self) -> [i32; 12] {
        [
            self.labor,
            self.transport,
            self.industry,
            self.provinces,
            self.military,
            self.navy,
            self.diplomacy,
            self.merchant_marine,
            self.year,
            self.subtotal,
            self.difficulty_percent,
            self.total,
        ]
    }
}

impl GameState {
    /// `TGreatPower::GenerateGameScore`. Row 11 is `subtotal * difficulty percent / 10`.
    pub fn generate_game_score(&self, nation: MajorNationId) -> GameScore {
        let major = &self.nations.majors[&nation];
        let labor = i32::from(major.city.population.baseline_labor.strength());
        let transport = i32::from(major.economy.capacities.transport);
        let industry = [
            CityFacilitySlot::TextileMill,
            CityFacilitySlot::ClothingFactory,
            CityFacilitySlot::SteelMill,
            CityFacilitySlot::Metalworks,
            CityFacilitySlot::LumberMill,
            CityFacilitySlot::FurnitureFactory,
        ]
        .iter()
        .map(|&slot| i32::from(major.city.production_orders[slot]))
        .sum();
        let mut provinces = major.common.owned_regions().len() as i32;
        for minor in MinorNationId::all() {
            let Some(common) = self.nations.minors.get(&minor) else {
                continue;
            };
            if common.common.status().is_colony_of(nation.nation()) {
                provinces += common.common.owned_regions().len() as i32;
            }
        }
        provinces *= 10;
        let military = self
            .military_units
            .values()
            .filter(|unit| unit.nation == nation.nation())
            .map(|unit| unit.unit_type.arms_required())
            .sum();
        let navy = self.navy_arms(nation.nation());
        let mut relation_sum = 0;
        let mut relation_count = 0;
        for other in NationId::all() {
            if other == nation.nation() || self.nations.common(other).is_none() {
                continue;
            }
            relation_sum += i32::from(self.diplomacy.standings[nation.nation()][other]);
            relation_count += 1;
        }
        let diplomacy = if relation_count == 0 {
            0
        } else {
            relation_sum / relation_count
        };
        let merchant_marine = i32::from(major.city.merchant_capacity());
        let year = (100 - self.turn.economic_turn / 4) * 10;
        let subtotal = labor
            + transport
            + industry
            + provinces
            + military
            + navy
            + diplomacy
            + merchant_marine
            + year;
        let difficulty_percent = DIFFICULTY_PERCENT[self.turn.difficulty as usize];
        GameScore {
            labor,
            transport,
            industry,
            provinces,
            military,
            navy,
            diplomacy,
            merchant_marine,
            year,
            subtotal,
            difficulty_percent,
            total: subtotal * difficulty_percent / 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn score_total_scales_subtotal_by_difficulty_percent() {
        let state = game_state();
        let score = state.generate_game_score(MajorNationId::new(0));
        assert_eq!(score.difficulty_percent, 15);
        assert_eq!(score.total, score.subtotal * 15 / 10);
        assert_eq!(score.year, 1000);
    }
}
