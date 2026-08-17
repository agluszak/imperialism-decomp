use super::*;

impl GameState {
    pub(super) fn passes_alliance_strength(&self, nation: MajorNationId, target: NationId) -> bool {
        if self.has_alliance_guard(target, nation.nation()) {
            return false;
        }
        let (ally_army, ally_navy) = self.allied_forces(nation);
        let army = self.military_power(nation);
        let navy = self.naval_force(nation);
        let own = army.max(navy);
        let ally = (ally_army.trunc().max(ally_navy.trunc()) as i32) / 4;
        let mut strongest: f32 = 0.0;
        for peer in majors() {
            if !self.event_eligible(peer.nation()) {
                continue;
            }
            strongest = strongest
                .max(self.military_power(peer))
                .max(self.naval_force(peer));
        }
        let tick = self.clamped_quarter() as f32;
        let standing = f32::from(self.diplomacy.standings[nation.nation()][target]);
        let combined = own + ally as f32;
        let score =
            (strongest / combined + (standing + own) / (tick + combined - STRENGTH_OFFSET)) * 0.5;
        self.accept_alliance_number(nation) <= score
    }

    pub(super) fn peace_threat(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        let self_army = at_least_one(self.military_power(nation));
        let self_navy = at_least_one(self.naval_force(nation));
        let mut allied_self_army = 0.0;
        let mut allied_self_navy = 0.0;
        let mut allied_target_army = 0.0;
        let mut allied_target_navy = 0.0;
        for other in majors() {
            if !self.event_eligible(other.nation()) {
                continue;
            }
            if self.at_war(other.nation(), nation.nation()) && other != target {
                allied_self_army += self.military_power(other);
                allied_self_navy += self.naval_force(other);
            }
            if self.at_war(other.nation(), target.nation()) && other != nation {
                allied_target_army += self.military_power(other);
                allied_target_navy += self.naval_force(other);
            }
        }
        let peer = -PEER_WEIGHT;
        if self.are_nations_border_linked(target.nation(), nation.nation()) {
            (self_army + allied_self_army * peer)
                / (self.military_power(target) + allied_target_army * peer)
        } else {
            (self_navy + allied_self_navy * peer)
                / (self.naval_force(target) + allied_target_navy * peer)
        }
    }

    pub(super) fn deserves_to_be_enemy(
        &self,
        nation: MajorNationId,
        target: MajorNationId,
    ) -> bool {
        if !self.are_nations_border_linked(nation.nation(), target.nation()) {
            if enemy_navy_threshold(self.turn.difficulty) >= self.navy_arms(nation.nation()) {
                return false;
            }
            let average = truncated_average(
                self.navy_ratio(nation, target),
                self.navy_standing_ratio(nation, target),
            );
            return self.war_number(nation) <= average;
        }
        if enemy_army_threshold(self.turn.difficulty) >= self.army_unit_power(nation.nation()) {
            return false;
        }
        let year = i32::from(self.turn.diplomacy_year_term_raw);
        let progress =
            (self.turn.year_quarters() + year) / (year_divisor(self.turn.difficulty, year) + year);
        let average = truncated_average(
            self.army_ratio(nation, target),
            self.army_standing_ratio(nation, target),
        );
        self.war_number(nation) <= progress as f32 * average
    }

    pub(super) fn allied_forces(&self, nation: MajorNationId) -> (f32, f32) {
        let mut army = 0.0;
        let mut navy = 0.0;
        for ally in majors() {
            if self.diplomacy.relationships[nation.nation()][ally.nation()]
                == DiplomaticRelationship::Alliance
            {
                army += self.military_power(ally);
                navy += self.naval_force(ally);
            }
        }
        (army, navy)
    }

    pub(super) fn allied_army(&self, nation: MajorNationId) -> f32 {
        self.allied_forces(nation).0
    }

    pub(super) fn allied_navy(&self, nation: MajorNationId) -> f32 {
        self.allied_forces(nation).1
    }

    pub(super) fn ratio(self_score: f32, target: f32, ally: f32) -> f32 {
        let denom = target - ally * ALLY_WEIGHT;
        #[allow(clippy::float_cmp)]
        if denom == 0.0 {
            self_score
        } else {
            self_score / denom
        }
    }

    pub(super) fn army_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        Self::ratio(
            self.military_power(nation),
            self.military_power(target),
            self.allied_army(target),
        )
    }

    pub(super) fn navy_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        Self::ratio(
            self.naval_force(nation),
            self.naval_force(target),
            self.allied_navy(target),
        )
    }

    pub(super) fn standing_ratio(
        &self,
        nation: MajorNationId,
        target: MajorNationId,
        self_score: f32,
        target_score: f32,
        ally: f32,
    ) -> f32 {
        let year = self.clamped_quarter() as f32;
        let standing = f32::from(self.diplomacy.standings[nation.nation()][target.nation()]);
        let denom = standing - ally * ALLY_WEIGHT + target_score;
        let numer = year + self_score - YEAR_BIAS;
        #[allow(clippy::float_cmp)]
        if denom == 0.0 { numer } else { numer / denom }
    }

    pub(super) fn army_standing_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        self.standing_ratio(
            nation,
            target,
            self.military_power(nation),
            self.military_power(target),
            self.allied_army(target),
        )
    }

    pub(super) fn navy_standing_ratio(&self, nation: MajorNationId, target: MajorNationId) -> f32 {
        self.standing_ratio(
            nation,
            target,
            self.naval_force(nation),
            self.naval_force(target),
            self.allied_navy(target),
        )
    }

    pub(super) fn target_force(&self, target: MajorNationId, linked: NationId) -> f32 {
        if self.are_nations_border_linked(target.nation(), linked) {
            self.military_power(target)
        } else {
            self.naval_force(target)
        }
    }

    pub(super) fn army_ratio_with_secondary(
        &self,
        nation: MajorNationId,
        target: NationId,
        secondary: NationId,
    ) -> f32 {
        let Some(target) = MajorNationId::from_nation(target) else {
            return self.military_power(nation);
        };
        Self::ratio(
            self.military_power(nation),
            self.target_force(target, secondary),
            self.allied_army(target),
        )
    }

    pub(super) fn navy_ratio_with_secondary(
        &self,
        nation: MajorNationId,
        target: NationId,
        secondary: NationId,
    ) -> f32 {
        let Some(target) = MajorNationId::from_nation(target) else {
            return self.naval_force(nation);
        };
        Self::ratio(
            self.naval_force(nation),
            self.target_force(target, secondary),
            self.allied_navy(target),
        )
    }

    pub(super) fn standing_pair(
        &self,
        nation: MajorNationId,
        target: NationId,
        partner: NationId,
        self_score: f32,
        ally: f32,
    ) -> f32 {
        let Some(target_major) = MajorNationId::from_nation(target) else {
            return self_score;
        };
        let standing_target = f32::from(self.diplomacy.standings[nation.nation()][target]);
        let standing_partner = f32::from(self.diplomacy.standings[nation.nation()][partner]);
        let denom = standing_target - ally * ALLY_WEIGHT + self.target_force(target_major, partner);
        #[allow(clippy::float_cmp)]
        if denom == 0.0 {
            standing_partner + self_score
        } else {
            (standing_partner + self_score) / denom
        }
    }

    pub(super) fn army_standing_pair(
        &self,
        nation: MajorNationId,
        target: NationId,
        partner: NationId,
    ) -> f32 {
        self.standing_pair(
            nation,
            target,
            partner,
            self.military_power(nation),
            self.allied_army_of(target),
        )
    }

    pub(super) fn navy_standing_pair(
        &self,
        nation: MajorNationId,
        target: NationId,
        partner: NationId,
    ) -> f32 {
        self.standing_pair(
            nation,
            target,
            partner,
            self.naval_force(nation),
            self.allied_navy_of(target),
        )
    }

    pub(super) fn allied_army_of(&self, nation: NationId) -> f32 {
        MajorNationId::from_nation(nation).map_or(0.0, |major| self.allied_army(major))
    }

    pub(super) fn allied_navy_of(&self, nation: NationId) -> f32 {
        MajorNationId::from_nation(nation).map_or(0.0, |major| self.allied_navy(major))
    }

    pub(super) fn pair_ratio(
        self_score: f32,
        opponent: f32,
        partner: f32,
        ally: f32,
        swap: bool,
    ) -> f32 {
        let denom = opponent - ally * ALLY_WEIGHT;
        let mut numer = if swap {
            self_score - partner * ALLY_WEIGHT
        } else {
            self_score - partner * PEER_WEIGHT
        };
        #[allow(clippy::float_cmp)]
        if denom != 0.0 {
            numer /= denom;
        }
        numer
    }

    pub(super) fn pair_nations(
        &self,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> (MajorNationId, MajorNationId) {
        if swap { (b, a) } else { (a, b) }
    }

    pub(super) fn army_pair_ratio(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        let (opponent, partner) = self.pair_nations(a, b, swap);
        Self::pair_ratio(
            self.military_power(nation),
            self.military_power(opponent),
            self.military_power(partner),
            self.allied_army(opponent),
            swap,
        )
    }

    pub(super) fn navy_pair_ratio(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        let (opponent, partner) = self.pair_nations(a, b, swap);
        Self::pair_ratio(
            self.naval_force(nation),
            self.naval_force(opponent),
            self.naval_force(partner),
            self.allied_navy(opponent),
            swap,
        )
    }

    pub(super) fn army_pair_standing(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        self.pair_standing(nation, a, b, swap, false)
    }

    pub(super) fn navy_pair_standing(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
    ) -> f32 {
        self.pair_standing(nation, a, b, swap, true)
    }

    pub(super) fn pair_standing(
        &self,
        nation: MajorNationId,
        a: MajorNationId,
        b: MajorNationId,
        swap: bool,
        navy: bool,
    ) -> f32 {
        let (opponent, partner) = self.pair_nations(a, b, swap);
        let self_score = if navy {
            self.naval_force(nation)
        } else {
            self.military_power(nation)
        };
        let opponent_score = if navy {
            self.naval_force(opponent)
        } else {
            self.military_power(opponent)
        };
        let partner_score = if navy {
            self.naval_force(partner)
        } else {
            self.military_power(partner)
        };
        let ally = if navy {
            self.allied_navy(opponent)
        } else {
            self.allied_army(opponent)
        };
        let standing_opp = f32::from(self.diplomacy.standings[nation.nation()][opponent.nation()]);
        let standing_partner =
            f32::from(self.diplomacy.standings[nation.nation()][partner.nation()]);
        let denom = standing_opp - ally * ALLY_WEIGHT + opponent_score;
        let mut numer = if swap {
            standing_partner - partner_score * ALLY_WEIGHT + self_score
        } else {
            standing_partner - partner_score * PEER_WEIGHT + self_score
        };
        #[allow(clippy::float_cmp)]
        if denom != 0.0 {
            numer /= denom;
        }
        numer
    }

    pub(super) fn war_number(&self, nation: MajorNationId) -> f32 {
        let Some(major) = self.nations.major(nation) else {
            return 0.0;
        };
        coeff(&WAR_FOREIGN, major.economy.foreign_minister_skill_index)
            + coeff(&WAR_DEFENSE, major.economy.defense_minister_skill_index)
    }

    pub(super) fn seek_alliance_number(&self, nation: MajorNationId) -> f32 {
        let Some(major) = self.nations.major(nation) else {
            return 0.0;
        };
        coeff(
            &SEEK_ALLIANCE_DEFENSE,
            major.economy.defense_minister_skill_index,
        ) + coeff(
            &SEEK_ALLIANCE_FOREIGN,
            major.economy.foreign_minister_skill_index,
        )
    }

    pub(super) fn accept_alliance_number(&self, nation: MajorNationId) -> f32 {
        let Some(major) = self.nations.major(nation) else {
            return 0.0;
        };
        coeff(
            &ACCEPT_ALLIANCE_DEFENSE,
            major.economy.defense_minister_skill_index,
        ) + coeff(
            &ACCEPT_ALLIANCE_FOREIGN,
            major.economy.foreign_minister_skill_index,
        )
    }

    pub(super) fn seek_peace_number(&self, nation: MajorNationId) -> f32 {
        let Some(major) = self.nations.major(nation) else {
            return 0.0;
        };
        coeff(
            &SEEK_PEACE_FOREIGN,
            major.economy.foreign_minister_skill_index,
        ) + coeff(
            &SEEK_PEACE_DEFENSE,
            major.economy.defense_minister_skill_index,
        )
    }

    pub(super) fn accept_peace_number(&self, nation: MajorNationId) -> f32 {
        let Some(major) = self.nations.major(nation) else {
            return 0.0;
        };
        coeff(
            &ACCEPT_PEACE_FOREIGN,
            major.economy.foreign_minister_skill_index,
        ) + coeff(
            &ACCEPT_PEACE_DEFENSE,
            major.economy.defense_minister_skill_index,
        )
    }

    pub(super) fn clamped_quarter(&self) -> i32 {
        self.turn.year_quarters().min(0x3c)
    }
}
