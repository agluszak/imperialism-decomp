use crate::*;

const ARMY_POWER_WEIGHT: MilitaryUnitTable<i32> = MilitaryUnitTable::from_array([
    70, 137, 135, 164, 165, 211, 193, 300, 95, 243, 230, 265, 230, 275, 323, 549, 170, 450, 471,
    495, 493, 1010, 715, 913, 193, 260, 360, 200, 200, 200,
]);
const NAVY_POWER_WEIGHT: ShipTypeTable<i32> =
    ShipTypeTable::from_array([0, 0, 0, 150, 300, 0, 0, 200, 400, 650, 0, 450, 1500, 1200]);

#[derive(Clone, Copy, Default)]
struct CouncilPower {
    military: i32,
    relations: i32,
    territory_and_population: i32,
    commodity: i32,
}

struct CouncilMaxima {
    military: i32,
    relations: i32,
    territory: i32,
    population: i32,
    commodity: i32,
}

impl Default for CouncilMaxima {
    fn default() -> Self {
        Self {
            military: 1,
            relations: 1,
            territory: 1,
            population: 1,
            commodity: 1,
        }
    }
}

impl CouncilPower {
    const fn total(self) -> i32 {
        self.military + self.relations + self.territory_and_population + self.commodity
    }
}

impl GameState {
    /// Retail's normalized military-power figure shown in the newspaper.
    pub fn newspaper_military_power(&self, nation: MajorNationId) -> i32 {
        self.council_comparative_power()[nation].military
    }

    /// Retail's normalized commodity-power figure shown in the newspaper.
    pub fn newspaper_commodity_power(&self, nation: MajorNationId) -> i32 {
        self.council_comparative_power()[nation].commodity
    }

    /// Retail's decade-boundary Council of Governors ballot rebuild.
    pub(crate) fn rebuild_council_ballot(&mut self, force_full_clear: bool) {
        if self.diplomacy.influence_thresholds.as_array()[0] == 0 {
            for province in ProvinceId::all() {
                let Some(former) = self.map.provinces[province].former_owner() else {
                    continue;
                };
                let mut threshold = if MajorNationId::from_nation(former).is_some() {
                    14
                } else {
                    8
                };
                let die = if threshold == 14 { 6 } else { 4 };
                for _ in 0..3 {
                    threshold += (self.rng.next_crt_rand() % die) as i16;
                }
                self.diplomacy.influence_thresholds[province] = threshold;
            }
        }
        if force_full_clear {
            self.diplomacy.influence_thresholds = ProvinceTable::default();
        }

        let power = self.council_comparative_power();
        let mut ranking: Vec<_> = MajorNationId::all()
            .map(|nation| (nation, power[nation].total()))
            .collect();
        for left in 0..ranking.len() - 1 {
            for right in left + 1..ranking.len() {
                if ranking[right].1 > ranking[left].1
                    || (ranking[right].1 == ranking[left].1 && self.rng.next_crt_rand() & 1 != 0)
                {
                    ranking.swap(left, right);
                }
            }
        }
        let chairman = ranking[0].0;
        let counterpart = ranking[1].0;
        self.diplomacy.congress.chairman = Some(chairman);
        self.diplomacy.congress.counterpart = Some(counterpart);

        let mut chairman_side = NationTable::default();
        let mut counterpart_side = NationTable::default();
        for nation in NationId::all() {
            if self.nations.common(nation).is_none() {
                chairman_side[nation] = self.rng.next_crt_rand() % 50 + 50;
                counterpart_side[nation] = self.rng.next_crt_rand() % 50 + 50;
            } else if matches!(
                self.nations.country_status(nation),
                Some(CountryStatus::ProtectorateOf(_))
            ) {
                let home_owner = self
                    .nations
                    .home_tile(nation)
                    .and_then(|tile| self.map[tile].owner_nation)
                    .and_then(TileOwnerTag::nation);
                chairman_side[nation] = if home_owner == Some(chairman.nation()) {
                    1
                } else {
                    self.rng.next_crt_rand() % 50 + 50
                };
                counterpart_side[nation] = if home_owner == Some(counterpart.nation()) {
                    1
                } else {
                    self.rng.next_crt_rand() % 50 + 50
                };
            } else {
                chairman_side[nation] =
                    (i32::from(self.diplomacy.standings[chairman.nation()][nation]) * 100 / 255
                        + power[chairman].relations)
                        / 2;
                counterpart_side[nation] =
                    (i32::from(self.diplomacy.standings[counterpart.nation()][nation]) * 100 / 255
                        + power[counterpart].relations)
                        / 2;
            }
        }
        chairman_side[chairman.nation()] = 100;
        counterpart_side[counterpart.nation()] = 100;
        let mut chairman_support = 0;
        let mut counterpart_support = 0;
        let mut owned = 0;
        let mut vote_residual: ProvinceTable<Option<i16>> = ProvinceTable::default();
        let mut max_residual = 0;
        for province in ProvinceId::all() {
            let Some(owner) = self.map.provinces[province].owner() else {
                self.diplomacy.influence_sides[province] = None;
                continue;
            };
            owned += 1;
            let chairman_wins =
                owner == chairman.nation() || self.status_of(owner).is_colony_of(chairman.nation());
            let counterpart_wins = owner == counterpart.nation()
                || self.status_of(owner).is_colony_of(counterpart.nation());
            let side = if chairman_wins {
                vote_residual[province] = Some(0);
                Some(chairman)
            } else if counterpart_wins {
                vote_residual[province] = Some(0);
                Some(counterpart)
            } else {
                let former_major = self.map.provinces[province]
                    .former_owner()
                    .and_then(MajorNationId::from_nation)
                    .is_some();
                let (mut chairman_score, mut counterpart_score) = if former_major {
                    (
                        (power[chairman].military + power[chairman].commodity) / 2,
                        (power[counterpart].military + power[counterpart].commodity) / 2,
                    )
                } else {
                    (chairman_side[owner], counterpart_side[owner])
                };
                if owner.get() >= MinorNationId::FIRST {
                    for &tile in &self.map.provinces[province].linked_tiles {
                        if self.map[tile].secondary_owner_nation == Some(chairman) {
                            chairman_score += 2;
                        } else if self.map[tile].secondary_owner_nation == Some(counterpart) {
                            counterpart_score += 2;
                        }
                    }
                }
                let threshold = i32::from(self.diplomacy.influence_thresholds[province]);
                if chairman_score - counterpart_score >= threshold {
                    let residual = (chairman_score - counterpart_score - threshold) as i16;
                    vote_residual[province] = Some(residual);
                    max_residual = max_residual.max(residual);
                    Some(chairman)
                } else if counterpart_score - chairman_score >= threshold {
                    let residual = (counterpart_score - chairman_score - threshold) as i16;
                    vote_residual[province] = Some(residual);
                    max_residual = max_residual.max(residual);
                    Some(counterpart)
                } else {
                    None
                }
            };
            self.diplomacy.influence_sides[province] = side;
            chairman_support += i16::from(side == Some(chairman));
            counterpart_support += i16::from(side == Some(counterpart));
        }
        // Retail derives animation tiers after every vote. The tiers are transient,
        // but the direct-winner dice are authoritative CRT RNG consumption.
        for province in ProvinceId::all() {
            match vote_residual[province] {
                Some(0) => {
                    let _tier = self.rng.next_crt_rand() % 15 + 1;
                }
                Some(residual) => {
                    let _tier = i32::from(max_residual - residual + 15);
                }
                None => {}
            }
        }
        self.diplomacy.congress.chairman_support = chairman_support;
        self.diplomacy.congress.counterpart_support = counterpart_support;
        self.diplomacy.congress.neutral_support = owned - chairman_support - counterpart_support;
        self.diplomacy.last_processed_nation = None;

        let leader = if chairman_support > counterpart_support {
            Some((chairman, chairman_support))
        } else if counterpart_support > chairman_support {
            Some((counterpart, counterpart_support))
        } else {
            None
        };
        if let Some((leader, support)) = leader {
            if force_full_clear || support >= owned * 2 / 3 {
                self.diplomacy.last_processed_nation = Some(leader);
            } else if self.event_eligible(leader.nation())
                && self.nations.majors[&leader].economy.pending_actions
                    [PendingActionKind::CouncilLeadMonument]
                    .progress()
                    < PendingActionProgress::Handled
            {
                self.nations.majors[&leader].economy.pending_actions
                    [PendingActionKind::CouncilLeadMonument]
                    .queue();
            }
        } else if force_full_clear {
            self.diplomacy.last_processed_nation = Some(chairman);
        }
    }

    fn council_comparative_power(&self) -> MajorNationTable<CouncilPower> {
        let mut rows: MajorNationTable<CouncilPower> = MajorNationTable::default();
        let mut territory: MajorNationTable<i32> = MajorNationTable::default();
        let mut technology: MajorNationTable<i32> = MajorNationTable::default();
        let mut maxima = CouncilMaxima::default();
        for nation in MajorNationId::all() {
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            rows[nation].military = self
                .military_units
                .values()
                .filter(|unit| {
                    unit.nation == nation.nation() && !unit.unit_type.is_militia_category()
                })
                .map(|unit| {
                    ARMY_POWER_WEIGHT[unit.unit_type] * (i32::from(unit.experience) / 100 + 10) / 10
                })
                .sum::<i32>()
                + self
                    .ships
                    .values()
                    .filter(|ship| ship.nation == nation.nation())
                    .map(|ship| {
                        NAVY_POWER_WEIGHT[ship.ship_type] * (i32::from(ship.experience) / 100 + 10)
                            / 10
                    })
                    .sum::<i32>()
                + 500;
            let mut relation_sum = 0;
            let mut relation_count = 0;
            for other in NationId::all() {
                if other != nation.nation() && self.nations.common(other).is_some() {
                    relation_sum += i32::from(self.diplomacy.standings[nation.nation()][other]);
                    relation_count += 1;
                }
            }
            rows[nation].relations = relation_sum / relation_count;
            rows[nation].commodity = ManufacturedItem::ALL[4..]
                .iter()
                .map(|&item| self.nations.majors[&nation].city.orders.items[item].accumulated_value)
                .sum();
            territory[nation] = self.nations.majors[&nation].common.owned_regions().len() as i32;
            technology[nation] = i32::from(self.nations.majors[&nation].city.population.count);
            maxima.military = maxima.military.max(rows[nation].military);
            maxima.relations = maxima.relations.max(rows[nation].relations);
            maxima.territory = maxima.territory.max(territory[nation]);
            maxima.population = maxima.population.max(technology[nation]);
            maxima.commodity = maxima.commodity.max(rows[nation].commodity);
        }
        for nation in MajorNationId::all() {
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            rows[nation].military = rows[nation].military * 100 / maxima.military;
            rows[nation].relations = rows[nation].relations * 100 / maxima.relations;
            rows[nation].territory_and_population = territory[nation] * 50 / maxima.territory
                + technology[nation] * 50 / maxima.population;
            rows[nation].commodity = rows[nation].commodity * 100 / maxima.commodity;
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_rebuild_clears_thresholds_and_resolves_a_tie_for_the_chairman() {
        let mut state = crate::test_support::game_state();
        state.diplomacy.influence_thresholds = ProvinceTable::from_array([12; PROVINCE_COUNT]);

        state.rebuild_council_ballot(true);

        assert!(
            state
                .diplomacy
                .influence_thresholds
                .as_array()
                .iter()
                .all(|&threshold| threshold == 0)
        );
        assert_eq!(
            state.diplomacy.last_processed_nation,
            state.diplomacy.congress.chairman
        );
    }
}
