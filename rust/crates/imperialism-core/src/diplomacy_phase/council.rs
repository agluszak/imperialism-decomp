use crate::*;

const ARMY_POWER_WEIGHT: [i32; 30] = [
    70, 137, 135, 164, 165, 211, 193, 300, 95, 243, 230, 265, 230, 275, 323, 549, 170, 450, 471,
    495, 493, 1010, 715, 913, 193, 260, 360, 200, 200, 200,
];
const NAVY_POWER_WEIGHT: [i32; 14] = [0, 0, 0, 150, 300, 0, 0, 200, 400, 650, 0, 450, 1500, 1200];

impl GameState {
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
            .map(|nation| (nation, power[nation].iter().sum::<i32>()))
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
                        + power[chairman][1])
                        / 2;
                counterpart_side[nation] =
                    (i32::from(self.diplomacy.standings[counterpart.nation()][nation]) * 100 / 255
                        + power[counterpart][1])
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
                        (power[chairman][0] + power[chairman][3]) / 2,
                        (power[counterpart][0] + power[counterpart][3]) / 2,
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
                && self.nations.majors[leader].economy.pending_actions
                    [PendingActionKind::CouncilLeadMonument]
                    .status()
                    < PendingActionStatus::HANDLED
            {
                self.nations.majors[leader].economy.pending_actions
                    [PendingActionKind::CouncilLeadMonument]
                    .queue();
            }
        } else if force_full_clear {
            self.diplomacy.last_processed_nation = Some(chairman);
        }
    }

    fn council_comparative_power(&self) -> MajorNationTable<[i32; 4]> {
        let mut rows: MajorNationTable<[i32; 4]> = MajorNationTable::default();
        let mut territory: MajorNationTable<i32> = MajorNationTable::default();
        let mut technology: MajorNationTable<i32> = MajorNationTable::default();
        let mut maxima = [1; 5];
        for nation in MajorNationId::all() {
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            rows[nation][0] = self
                .military_units
                .iter()
                .filter(|unit| {
                    unit.nation == nation.nation() && !unit.unit_type.is_militia_category()
                })
                .map(|unit| {
                    ARMY_POWER_WEIGHT[unit.unit_type as usize]
                        * (i32::from(unit.experience) / 100 + 10)
                        / 10
                })
                .sum::<i32>()
                + self
                    .ships
                    .iter()
                    .filter(|ship| ship.nation == nation.nation())
                    .map(|ship| {
                        NAVY_POWER_WEIGHT[ship.ship_type as usize]
                            * (i32::from(ship.experience) / 100 + 10)
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
            rows[nation][1] = relation_sum / relation_count;
            rows[nation][3] = ManufacturedItem::ALL[4..]
                .iter()
                .map(|&item| self.nations.majors[nation].city.orders.items[item].accumulated_value)
                .sum();
            territory[nation] = self.nations.majors[nation].common.owned_regions().len() as i32;
            technology[nation] = i32::from(self.nations.majors[nation].city.population.count);
            maxima[0] = maxima[0].max(rows[nation][0]);
            maxima[1] = maxima[1].max(rows[nation][1]);
            maxima[2] = maxima[2].max(territory[nation]);
            maxima[3] = maxima[3].max(technology[nation]);
            maxima[4] = maxima[4].max(rows[nation][3]);
        }
        for nation in MajorNationId::all() {
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            rows[nation][0] = rows[nation][0] * 100 / maxima[0];
            rows[nation][1] = rows[nation][1] * 100 / maxima[1];
            rows[nation][2] =
                territory[nation] * 50 / maxima[2] + technology[nation] * 50 / maxima[3];
            rows[nation][3] = rows[nation][3] * 100 / maxima[4];
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
