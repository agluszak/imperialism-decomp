use crate::{
    GameState, MajorNationId, PendingActionKind, PendingActionTable, Technology,
    TechnologyResearchStatus,
};
use serde::{Deserialize, Serialize};

/// Semantic lifecycle for one retail pending-action slot.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PendingActionProgress {
    #[default]
    None,
    Queued,
    Handled,
    RewardLevel(i16),
}

impl PendingActionProgress {
    pub fn is_queued(self) -> bool {
        matches!(self, Self::Queued)
    }

    pub fn is_none(self) -> bool {
        matches!(self, Self::None)
    }

    pub fn has_reached(self, threshold: Self) -> bool {
        self >= threshold
    }

    pub const fn growth_reward_level(self) -> Option<i16> {
        match self {
            Self::None => Some(0),
            Self::Queued => None,
            Self::Handled => Some(0),
            Self::RewardLevel(level) => Some(level),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingActionState {
    progress: PendingActionProgress,
    payload: Option<i16>,
}

impl PendingActionState {
    pub const fn new(progress: PendingActionProgress, payload: Option<i16>) -> Self {
        Self { progress, payload }
    }

    pub const fn progress(self) -> PendingActionProgress {
        self.progress
    }

    pub const fn payload(self) -> Option<i16> {
        self.payload
    }

    pub(crate) fn queue(&mut self) {
        self.progress = PendingActionProgress::Queued;
        self.payload = None;
    }

    pub(crate) fn queue_with_payload(&mut self, payload: i16) {
        self.progress = PendingActionProgress::Queued;
        self.payload = Some(payload);
    }

    pub(crate) fn set_progress(&mut self, progress: PendingActionProgress) {
        self.progress = progress;
    }

    pub(crate) fn set_payload(&mut self, payload: Option<i16>) {
        self.payload = payload;
    }

    /// Army/navy growth reward level for this slot.
    pub const fn growth_reward_level(self) -> Option<i16> {
        self.progress.growth_reward_level()
    }
}

impl GameState {
    /// Retail `TGreatPower::MarkAllPendingStatusFlagsHandled` for every event-eligible major.
    pub fn mark_all_pending_status_flags_handled(&mut self) {
        for nation in MajorNationId::all() {
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            let ironworking_researched = self.technology.research_status_by_nation[nation]
                [Technology::AdvancedIronWorking]
                == TechnologyResearchStatus::Researched;
            let actions = &mut self.nations.majors[&nation].economy.pending_actions;
            mark_pending_status_flags_handled(actions, ironworking_researched);
        }
    }
}

fn mark_pending_status_flags_handled(
    actions: &mut PendingActionTable<PendingActionState>,
    ironworking_researched: bool,
) {
    let shipyard = &mut actions[PendingActionKind::ShipyardIronworkingUpgrade];
    if !shipyard
        .progress()
        .has_reached(PendingActionProgress::Handled)
        && ironworking_researched
    {
        shipyard.set_progress(PendingActionProgress::Handled);
    }

    mark_queued_handled(
        &mut actions[PendingActionKind::ConqueredCapitalArmoryUpgrade],
        PendingActionProgress::Handled,
    );

    let university = &mut actions[PendingActionKind::UniversityExpansion];
    if university.progress().is_queued() {
        match university.payload() {
            Some(2) => university.set_progress(PendingActionProgress::Handled),
            Some(3) => {
                university.set_progress(PendingActionProgress::RewardLevel(1));
                university.set_payload(None);
            }
            _ => {}
        }
    }

    for kind in [
        PendingActionKind::RailyardExpansion,
        PendingActionKind::AnnexedGreatPowerCapitalExpansion,
        PendingActionKind::ColonyMonumentMerchantCapacity,
        PendingActionKind::CouncilLeadMonument,
        PendingActionKind::ConquestMonumentArmory,
    ] {
        mark_queued_handled(&mut actions[kind], PendingActionProgress::Handled);
    }

    mark_queued_as_reward_level(&mut actions[PendingActionKind::NavyGrowthReward]);
    mark_queued_as_reward_level(&mut actions[PendingActionKind::ArmyGrowthReward]);
    mark_queued_handled(
        &mut actions[PendingActionKind::OverseasDeveloperReward],
        PendingActionProgress::Handled,
    );
    mark_queued_handled(
        &mut actions[PendingActionKind::VillageDevelopment],
        PendingActionProgress::None,
    );
    mark_queued_handled(
        &mut actions[PendingActionKind::TownDevelopment],
        PendingActionProgress::None,
    );
}

fn mark_queued_handled(action: &mut PendingActionState, progress: PendingActionProgress) {
    if action.progress().is_queued() {
        action.set_progress(progress);
    }
}

fn mark_queued_as_reward_level(action: &mut PendingActionState) {
    if action.progress().is_queued() {
        let progress = match action.payload() {
            Some(payload) => PendingActionProgress::RewardLevel(payload),
            None => PendingActionProgress::Queued,
        };
        action.set_progress(progress);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_action_growth_reward_level_is_semantic() {
        assert_eq!(
            PendingActionState::new(PendingActionProgress::None, None).growth_reward_level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionProgress::Queued, Some(6)).growth_reward_level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionProgress::Handled, Some(6)).growth_reward_level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionProgress::RewardLevel(1), Some(6))
                .growth_reward_level(),
            Some(1)
        );
        assert_eq!(
            PendingActionState::new(PendingActionProgress::RewardLevel(6), Some(6))
                .growth_reward_level(),
            Some(6)
        );

        let mut actions = PendingActionTable::default();
        actions[PendingActionKind::NavyGrowthReward] =
            PendingActionState::new(PendingActionProgress::Queued, Some(1));
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(
            actions[PendingActionKind::NavyGrowthReward].progress(),
            PendingActionProgress::RewardLevel(1)
        );

        actions[PendingActionKind::NavyGrowthReward] =
            PendingActionState::new(PendingActionProgress::Queued, Some(3));
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(
            actions[PendingActionKind::NavyGrowthReward].progress(),
            PendingActionProgress::RewardLevel(3)
        );
    }
}
