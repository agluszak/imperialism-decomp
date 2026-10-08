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

/// One queued pending action surfaced to the player after the newspaper.
///
/// Retail `TViewMgr::QueueTurnStatusPromptSlot3C(kind, payload)`; `payload` is the
/// raw retail word (`-1` when the action carries no payload).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingStatusPrompt {
    pub kind: PendingActionKind,
    pub payload: i16,
}

impl GameState {
    /// Retail `TGreatPower::DispatchPendingStatusPrompts`.
    ///
    /// Returns the prompts in retail dispatch order and applies the university
    /// expansion paper grant that retail performs while dispatching. Statuses are
    /// left untouched; [`mark_all_pending_status_flags_handled`](Self::mark_all_pending_status_flags_handled)
    /// consumes them afterwards.
    pub fn dispatch_pending_status_prompts(
        &mut self,
        nation: MajorNationId,
    ) -> Vec<PendingStatusPrompt> {
        let mut prompts = Vec::new();
        let ironworking_researched = self.technology.research_status_by_nation[nation]
            [Technology::AdvancedIronWorking]
            == TechnologyResearchStatus::Researched;
        let actions = self.nations.major(nation).economy.pending_actions;
        let mut push = |kind: PendingActionKind, payload: i16| {
            prompts.push(PendingStatusPrompt { kind, payload });
        };

        let shipyard = actions[PendingActionKind::ShipyardIronworkingUpgrade];
        if !shipyard.status().has_reached(PendingActionStatus::HANDLED) && ironworking_researched {
            push(
                PendingActionKind::ShipyardIronworkingUpgrade,
                retail_payload(shipyard),
            );
        }
        let armory = actions[PendingActionKind::ConqueredCapitalArmoryUpgrade];
        if armory.status().is_queued() {
            push(
                PendingActionKind::ConqueredCapitalArmoryUpgrade,
                retail_payload(armory),
            );
        }
        let university = actions[PendingActionKind::UniversityExpansion];
        if university.status().is_queued() {
            match university.payload() {
                Some(payload @ 2) => {
                    self.grant_university_expansion_paper(nation);
                    push(PendingActionKind::UniversityExpansion, payload);
                }
                Some(3) => {
                    self.grant_university_expansion_paper(nation);
                    push(PendingActionKind::UniversityExpansion, -1);
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
            if actions[kind].status().is_queued() {
                push(kind, retail_payload(actions[kind]));
            }
        }
        if actions[PendingActionKind::NavyGrowthReward]
            .status()
            .is_queued()
        {
            push(
                PendingActionKind::NavyGrowthReward,
                i16::from(self.technology.navy_growth_ship_type.retail()),
            );
        }
        for kind in [
            PendingActionKind::ArmyGrowthReward,
            PendingActionKind::OverseasDeveloperReward,
            PendingActionKind::VillageDevelopment,
            PendingActionKind::TownDevelopment,
        ] {
            if actions[kind].status().is_queued() {
                push(kind, retail_payload(actions[kind]));
            }
        }
        prompts
    }

    fn grant_university_expansion_paper(&mut self, nation: MajorNationId) {
        self.nations
            .city_mut(nation)
            .stockpile
            .wrapping_add_and_verify(crate::ResourceKind::Paper, 10);
    }

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

fn retail_payload(action: PendingActionState) -> i16 {
    action.payload().unwrap_or(-1)
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
    use crate::test_support::game_state;
    use crate::{MajorNationId, ResourceKind, Technology, TechnologyResearchStatus};

    fn queue(state: &mut crate::GameState, nation: MajorNationId, kind: PendingActionKind) {
        state.nations.majors[&nation].economy.pending_actions[kind].queue_with_payload(kind as i16);
    }

    #[test]
    fn pending_status_prompts_follow_retail_dispatch_order() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        for index in 0..PendingActionKind::LENGTH {
            queue(&mut state, nation, enum_map::Enum::from_usize(index));
        }
        state.nations.majors[&nation].economy.pending_actions
            [PendingActionKind::UniversityExpansion]
            .queue_with_payload(2);
        state.technology.research_status_by_nation[nation][Technology::AdvancedIronWorking] =
            TechnologyResearchStatus::Researched;

        let prompts = state.dispatch_pending_status_prompts(nation);
        let kinds: Vec<u8> = prompts.iter().map(|prompt| prompt.kind as u8).collect();
        assert_eq!(kinds, [5, 6, 7, 8, 9, 10, 11, 12, 0, 1, 2, 3, 4]);
        assert_eq!(
            prompts[8].payload,
            i16::from(state.technology.navy_growth_ship_type.retail())
        );
        assert_eq!(prompts[12].payload, 4);
    }

    #[test]
    fn shipyard_prompt_requires_advanced_ironworking_and_skips_handled_actions() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        assert!(state.dispatch_pending_status_prompts(nation).is_empty());

        state.technology.research_status_by_nation[nation][Technology::AdvancedIronWorking] =
            TechnologyResearchStatus::Researched;
        assert_eq!(
            state.dispatch_pending_status_prompts(nation),
            [PendingStatusPrompt {
                kind: PendingActionKind::ShipyardIronworkingUpgrade,
                payload: -1,
            }]
        );

        state.nations.majors[&nation].economy.pending_actions
            [PendingActionKind::ShipyardIronworkingUpgrade]
            .set_status(PendingActionStatus::HANDLED);
        assert!(state.dispatch_pending_status_prompts(nation).is_empty());
    }

    #[test]
    fn university_expansion_prompt_grants_paper_and_maps_payload_three_to_minus_one() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        let paper_before = state.nations.city(nation).stockpile[ResourceKind::Paper];

        state.nations.majors[&nation].economy.pending_actions
            [PendingActionKind::UniversityExpansion]
            .queue_with_payload(1);
        assert!(state.dispatch_pending_status_prompts(nation).is_empty());
        assert_eq!(
            state.nations.city(nation).stockpile[ResourceKind::Paper],
            paper_before
        );

        state.nations.majors[&nation].economy.pending_actions
            [PendingActionKind::UniversityExpansion]
            .queue_with_payload(2);
        assert_eq!(
            state.dispatch_pending_status_prompts(nation),
            [PendingStatusPrompt {
                kind: PendingActionKind::UniversityExpansion,
                payload: 2,
            }]
        );
        assert_eq!(
            state.nations.city(nation).stockpile[ResourceKind::Paper],
            paper_before + 10
        );

        state.nations.majors[&nation].economy.pending_actions
            [PendingActionKind::UniversityExpansion]
            .queue_with_payload(3);
        assert_eq!(
            state.dispatch_pending_status_prompts(nation),
            [PendingStatusPrompt {
                kind: PendingActionKind::UniversityExpansion,
                payload: -1,
            }]
        );
        assert_eq!(
            state.nations.city(nation).stockpile[ResourceKind::Paper],
            paper_before + 20
        );
    }

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

        let mut actions = PendingActionTable::default();
        actions[PendingActionKind::NavyGrowthReward] =
            PendingActionState::new(PendingActionStatus::QUEUED, Some(1));
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(
            actions[PendingActionKind::NavyGrowthReward].status(),
            PendingActionStatus::from_retail(0x34)
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
