use crate::{
    GameState, MajorNationId, PendingActionKind, PendingActionTable, Technology,
    TechnologyResearchStatus,
};
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
    pub(crate) fn queue(&mut self) {
        self.status = PendingActionStatus::QUEUED;
        self.payload = None;
    }
    pub(crate) fn queue_with_payload(&mut self, payload: i16) {
        self.status = PendingActionStatus::QUEUED;
        self.payload = Some(payload);
    }
    pub(crate) fn set_status(&mut self, status: PendingActionStatus) {
        self.status = status;
    }
    pub(crate) fn set_payload(&mut self, payload: Option<i16>) {
        self.payload = payload;
    }
    /// Army/navy growth reward level recovered from the status byte.
    ///
    /// Queued has no completed level, `0` is level zero, and handled growth
    /// statuses `0x33..=0x39` are `status - 0x33`. Other action kinds assign
    /// different meaning to the same values.
    pub const fn growth_reward_level(self) -> Option<i16> {
        self.status.growth_reward_level()
    }
}

/// Raw retail pending-action status byte.
///
/// Different action kinds assign different meaning to the same values. Common
/// sentinels are [`NONE`](Self::NONE) (`0`), [`QUEUED`](Self::QUEUED) (`0x32`),
/// and [`HANDLED`](Self::HANDLED) (`0x33`). Army/navy growth then store
/// `0x33 + payload` through `0x39`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PendingActionStatus(i8);

impl PendingActionStatus {
    pub const NONE: Self = Self(0);
    pub const QUEUED: Self = Self(0x32);
    pub const HANDLED: Self = Self(0x33);

    pub const fn from_retail(value: i8) -> Self {
        Self(value)
    }

    pub const fn retail(self) -> i8 {
        self.0
    }

    pub const fn is_queued(self) -> bool {
        self.0 == 0x32
    }

    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    pub const fn growth_reward_level(self) -> Option<i16> {
        match self.0 {
            0 => Some(0),
            0x32 => None,
            0x33..=0x39 => Some(self.0 as i16 - 0x33),
            _ => None,
        }
    }

    pub fn has_reached(self, other: Self) -> bool {
        self >= other
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
    if !shipyard.status().has_reached(PendingActionStatus::HANDLED) && ironworking_researched {
        shipyard.set_status(PendingActionStatus::HANDLED);
    }

    mark_queued_handled(
        &mut actions[PendingActionKind::ConqueredCapitalArmoryUpgrade],
        PendingActionStatus::HANDLED,
    );

    let university = &mut actions[PendingActionKind::UniversityExpansion];
    if university.status().is_queued() {
        match university.payload() {
            Some(2) => university.set_status(PendingActionStatus::HANDLED),
            Some(3) => {
                university.set_status(PendingActionStatus::from_retail(0x34));
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
        mark_queued_handled(&mut actions[kind], PendingActionStatus::HANDLED);
    }

    mark_queued_as_payload_plus_handled(&mut actions[PendingActionKind::NavyGrowthReward]);
    mark_queued_as_payload_plus_handled(&mut actions[PendingActionKind::ArmyGrowthReward]);
    mark_queued_handled(
        &mut actions[PendingActionKind::OverseasDeveloperReward],
        PendingActionStatus::HANDLED,
    );
    mark_queued_handled(
        &mut actions[PendingActionKind::VillageDevelopment],
        PendingActionStatus::NONE,
    );
    mark_queued_handled(
        &mut actions[PendingActionKind::TownDevelopment],
        PendingActionStatus::NONE,
    );
}

fn mark_queued_handled(action: &mut PendingActionState, status: PendingActionStatus) {
    if action.status().is_queued() {
        action.set_status(status);
    }
}

fn mark_queued_as_payload_plus_handled(action: &mut PendingActionState) {
    if action.status().is_queued() {
        let status = match action.payload() {
            Some(payload) => PendingActionStatus::from_retail((payload + 0x33) as i8),
            None => PendingActionStatus::QUEUED,
        };
        action.set_status(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_action_growth_reward_level_is_derived_from_the_raw_status_byte() {
        assert_eq!(
            PendingActionState::new(PendingActionStatus::NONE, None).growth_reward_level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::QUEUED, Some(6)).growth_reward_level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::HANDLED, Some(6)).growth_reward_level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::from_retail(0x34), Some(6))
                .growth_reward_level(),
            Some(1)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::from_retail(0x39), Some(6))
                .growth_reward_level(),
            Some(6)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::from_retail(0x3a), None)
                .growth_reward_level(),
            None
        );
    }

    #[test]
    fn newspaper_mark_handled_promotes_navy_growth_through_reward_levels() {
        let mut actions = PendingActionTable::default();
        actions[PendingActionKind::NavyGrowthReward] =
            PendingActionState::new(PendingActionStatus::QUEUED, Some(1));
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(
            actions[PendingActionKind::NavyGrowthReward].status(),
            PendingActionStatus::from_retail(0x34)
        );

        actions[PendingActionKind::NavyGrowthReward] =
            PendingActionState::new(PendingActionStatus::QUEUED, Some(2));
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(
            actions[PendingActionKind::NavyGrowthReward].status(),
            PendingActionStatus::from_retail(0x35)
        );

        actions[PendingActionKind::NavyGrowthReward] =
            PendingActionState::new(PendingActionStatus::QUEUED, Some(3));
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(
            actions[PendingActionKind::NavyGrowthReward].status(),
            PendingActionStatus::from_retail(0x36)
        );
    }
}
