use crate::{GameState, MajorNationId, PendingActionKind, TechnologyResearchStatus};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingActionState {
    status: PendingActionStatus,
    payload: Option<i16>,
}

impl PendingActionState {
    pub const fn new(status: PendingActionStatus, payload: Option<i16>) -> Self {
        Self { status, payload }
    }
    pub const fn status(self) -> PendingActionStatus {
        self.status
    }
    pub const fn payload(self) -> Option<i16> {
        self.payload
    }
    pub const fn is_queued(self) -> bool {
        self.status.is_queued()
    }
    pub const fn completed_level(self) -> Option<i16> {
        self.status.completed_level()
    }
    /// Army-growth threshold level: queued work is ignored; raw 0 and `0x33`
    /// both count as level 0, matching `TUnitOrder` recruit production.
    pub(crate) const fn level(self) -> Option<i16> {
        if self.status.is_queued() {
            None
        } else if let Some(level) = self.status.completed_level() {
            Some(level)
        } else {
            Some(0)
        }
    }
    pub(crate) fn queue(&mut self, payload: i16) {
        self.status = PendingActionStatus::QUEUED;
        self.payload = (payload != -1).then_some(payload);
    }
    pub(crate) fn set_status(&mut self, status: PendingActionStatus) {
        self.status = status;
    }
    pub(crate) fn set_payload(&mut self, payload: Option<i16>) {
        self.payload = payload;
    }
}

/// Retail `TGreatPower::pendingActionStatus.byAction[]` raw status byte.
///
/// Queued work is `0x32`. Completed reward levels use the `0x33 + n` convention,
/// so `0x33` through `0x39` are valid persistent values.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PendingActionStatus(i8);

impl PendingActionStatus {
    pub const NONE: Self = Self(0);
    pub const QUEUED: Self = Self(0x32);

    pub const fn from_retail(value: i8) -> Self {
        Self(value)
    }

    pub const fn retail(self) -> i8 {
        self.0
    }

    pub const fn is_queued(self) -> bool {
        self.0 == Self::QUEUED.0
    }

    /// Completed reward level `n` stored as `0x33 + n`.
    pub const fn completed(level: i16) -> Self {
        Self((0x33 + level) as i8)
    }

    pub const fn completed_level(self) -> Option<i16> {
        if self.0 >= 0x33 {
            Some((self.0 as i16) - 0x33)
        } else {
            None
        }
    }

    pub(crate) fn has_reached(self, other: Self) -> bool {
        self >= other
    }
}

impl GameState {
    /// `TGreatPower::MarkAllPendingStatusFlagsHandled` for every event-eligible great power.
    pub fn mark_all_pending_status_flags_handled(&mut self) {
        for index in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(index);
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            self.mark_nation_pending_status_flags_handled(nation);
        }
    }

    fn mark_nation_pending_status_flags_handled(&mut self, nation: MajorNationId) {
        let ironworking_researched = self.technology.research_status_by_nation[nation][0x0f]
            == TechnologyResearchStatus::Researched;
        let actions = &mut self.nations.majors[nation].economy.pending_actions;

        if actions[PendingActionKind::ShipyardIronworkingUpgrade]
            .status()
            .retail()
            < 0x33
            && ironworking_researched
        {
            actions[PendingActionKind::ShipyardIronworkingUpgrade]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::ConqueredCapitalArmoryUpgrade].is_queued() {
            actions[PendingActionKind::ConqueredCapitalArmoryUpgrade]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::UniversityExpansion].is_queued() {
            match actions[PendingActionKind::UniversityExpansion].payload() {
                Some(2) => actions[PendingActionKind::UniversityExpansion]
                    .set_status(PendingActionStatus::completed(0)),
                Some(3) => {
                    actions[PendingActionKind::UniversityExpansion]
                        .set_status(PendingActionStatus::completed(1));
                    actions[PendingActionKind::UniversityExpansion].set_payload(None);
                }
                _ => {}
            }
        }
        if actions[PendingActionKind::RailyardExpansion].is_queued() {
            actions[PendingActionKind::RailyardExpansion]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion].is_queued() {
            actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::ColonyMonumentMerchantCapacity].is_queued() {
            actions[PendingActionKind::ColonyMonumentMerchantCapacity]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::CouncilLeadMonument].is_queued() {
            actions[PendingActionKind::CouncilLeadMonument]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::ConquestMonumentArmory].is_queued() {
            actions[PendingActionKind::ConquestMonumentArmory]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::NavyGrowthReward].is_queued() {
            let level = actions[PendingActionKind::NavyGrowthReward]
                .payload()
                .unwrap_or(-1);
            actions[PendingActionKind::NavyGrowthReward]
                .set_status(PendingActionStatus::completed(level));
        }
        if actions[PendingActionKind::ArmyGrowthReward].is_queued() {
            let level = actions[PendingActionKind::ArmyGrowthReward]
                .payload()
                .unwrap_or(-1);
            actions[PendingActionKind::ArmyGrowthReward]
                .set_status(PendingActionStatus::completed(level));
        }
        if actions[PendingActionKind::OverseasDeveloperReward].is_queued() {
            actions[PendingActionKind::OverseasDeveloperReward]
                .set_status(PendingActionStatus::completed(0));
        }
        if actions[PendingActionKind::VillageDevelopment].is_queued() {
            actions[PendingActionKind::VillageDevelopment].set_status(PendingActionStatus::NONE);
        }
        if actions[PendingActionKind::TownDevelopment].is_queued() {
            actions[PendingActionKind::TownDevelopment].set_status(PendingActionStatus::NONE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn pending_action_level_is_derived_from_status_not_payload() {
        assert_eq!(
            PendingActionState::new(PendingActionStatus::NONE, None).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::QUEUED, Some(6)).level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::completed(0), Some(6)).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::completed(1), Some(6)).level(),
            Some(1)
        );
    }

    #[test]
    fn pending_action_completed_level_follows_the_0x33_plus_n_convention() {
        assert_eq!(
            PendingActionState::new(PendingActionStatus::NONE, None).completed_level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::QUEUED, Some(6)).completed_level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::completed(0), Some(6)).completed_level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::completed(1), Some(6)).completed_level(),
            Some(1)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::from_retail(0x39), Some(6))
                .completed_level(),
            Some(6)
        );
    }

    #[test]
    fn newspaper_boundary_promotes_queued_army_and_navy_payloads() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].economy.pending_actions[PendingActionKind::ArmyGrowthReward]
            .queue(6);
        state.nations.majors[nation].economy.pending_actions[PendingActionKind::NavyGrowthReward]
            .queue(3);
        state.nations.majors[nation].economy.pending_actions[PendingActionKind::VillageDevelopment]
            .queue(-1);

        state.mark_all_pending_status_flags_handled();

        let army = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::ArmyGrowthReward];
        assert_eq!(army.status(), PendingActionStatus::from_retail(0x39));
        assert_eq!(army.completed_level(), Some(6));
        let navy = state.nations.majors[nation].economy.pending_actions
            [PendingActionKind::NavyGrowthReward];
        assert_eq!(navy.status(), PendingActionStatus::completed(3));
        assert_eq!(
            state.nations.majors[nation].economy.pending_actions
                [PendingActionKind::VillageDevelopment]
                .status(),
            PendingActionStatus::NONE
        );
    }
}
