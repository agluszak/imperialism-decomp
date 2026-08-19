use crate::{GameState, MajorNationId, NationId, ProvinceId, Technology, TechnologyResearchStatus};
use serde::{Deserialize, Serialize};

/// Per-kind pending-action state for one great power.
///
/// Retail stores these as a 13-entry status/payload pair. Gameplay uses named
/// fields; the 0x32 / 0x33+level / nation-slot encoding lives in legacy save I/O.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingActions {
    pub navy_growth: GrowthReward,
    pub army_growth: GrowthReward,
    pub overseas_developer: FlagPending,
    pub village_development: SettlementPending,
    pub town_development: SettlementPending,
    pub shipyard_ironworking: FlagPending,
    pub conquered_capital_armory: FlagPending,
    pub university_expansion: UniversityExpansion,
    pub railyard_expansion: FlagPending,
    pub annexed_capital: NationPending,
    pub colony_monument: NationPending,
    pub council_lead_monument: FlagPending,
    pub conquest_monument_armory: FlagPending,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum GrowthReward {
    #[default]
    Idle,
    Queued {
        level: Option<i32>,
    },
    Granted {
        level: i32,
    },
}

impl GrowthReward {
    pub const fn is_queued(self) -> bool {
        matches!(self, Self::Queued { .. })
    }

    /// Completed newspaper reward level. Queued has none; idle is level zero.
    pub const fn granted_level(self) -> Option<i32> {
        match self {
            Self::Idle => Some(0),
            Self::Queued { .. } => None,
            Self::Granted { level } => Some(level),
        }
    }

    /// Queues a growth reward without a completed level (retail payload none).
    #[allow(dead_code)]
    pub(crate) fn queue(&mut self) {
        *self = Self::Queued { level: None };
    }

    pub(crate) fn queue_level(&mut self, level: i32) {
        *self = Self::Queued { level: Some(level) };
    }

    fn mark_handled(&mut self) {
        if let Self::Queued { level: Some(level) } = *self {
            *self = Self::Granted { level };
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum FlagPending {
    #[default]
    Idle,
    Queued,
    Handled,
}

impl FlagPending {
    pub const fn is_queued(self) -> bool {
        matches!(self, Self::Queued)
    }

    pub const fn is_handled(self) -> bool {
        matches!(self, Self::Handled)
    }

    pub(crate) fn queue(&mut self) {
        if !self.is_handled() {
            *self = Self::Queued;
        }
    }

    fn mark_handled_if_queued(&mut self) {
        if self.is_queued() {
            *self = Self::Handled;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum NationPending {
    #[default]
    Idle,
    Queued {
        nation: NationId,
    },
    Handled,
}

impl NationPending {
    pub const fn is_queued(self) -> bool {
        matches!(self, Self::Queued { .. })
    }

    pub const fn is_handled(self) -> bool {
        matches!(self, Self::Handled)
    }

    pub(crate) fn queue(&mut self, nation: NationId) {
        if !self.is_handled() {
            *self = Self::Queued { nation };
        }
    }

    fn mark_handled_if_queued(&mut self) {
        if self.is_queued() {
            *self = Self::Handled;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum SettlementPending {
    #[default]
    Idle,
    Queued {
        province: ProvinceId,
    },
}

impl SettlementPending {
    pub const fn is_queued(self) -> bool {
        matches!(self, Self::Queued { .. })
    }

    pub(crate) fn queue(&mut self, province: ProvinceId) {
        *self = Self::Queued { province };
    }

    fn clear_if_queued(&mut self) {
        if self.is_queued() {
            *self = Self::Idle;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum UniversityExpansion {
    #[default]
    Idle,
    Queued {
        stage: i32,
    },
    Level2,
    Level3,
}

impl UniversityExpansion {
    pub const fn is_idle(self) -> bool {
        matches!(self, Self::Idle)
    }

    pub const fn building_level(self) -> i32 {
        match self {
            Self::Idle | Self::Queued { .. } => 1,
            Self::Level2 => 2,
            Self::Level3 => 3,
        }
    }

    pub(crate) fn queue_stage(&mut self, stage: i32) {
        *self = Self::Queued { stage };
    }

    fn mark_handled_if_queued(&mut self) {
        match *self {
            Self::Queued { stage: 2 } => *self = Self::Level2,
            Self::Queued { stage: 3 } => *self = Self::Level3,
            _ => {}
        }
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

fn mark_pending_status_flags_handled(actions: &mut PendingActions, ironworking_researched: bool) {
    if !actions.shipyard_ironworking.is_handled() && ironworking_researched {
        actions.shipyard_ironworking = FlagPending::Handled;
    }
    actions.conquered_capital_armory.mark_handled_if_queued();
    actions.university_expansion.mark_handled_if_queued();
    actions.railyard_expansion.mark_handled_if_queued();
    actions.annexed_capital.mark_handled_if_queued();
    actions.colony_monument.mark_handled_if_queued();
    actions.council_lead_monument.mark_handled_if_queued();
    actions.conquest_monument_armory.mark_handled_if_queued();
    actions.navy_growth.mark_handled();
    actions.army_growth.mark_handled();
    actions.overseas_developer.mark_handled_if_queued();
    actions.village_development.clear_if_queued();
    actions.town_development.clear_if_queued();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_reward_level_uses_granted_state_not_a_status_byte() {
        assert_eq!(GrowthReward::Idle.granted_level(), Some(0));
        assert_eq!(
            GrowthReward::Queued { level: Some(6) }.granted_level(),
            None
        );
        assert_eq!(GrowthReward::Granted { level: 0 }.granted_level(), Some(0));
        assert_eq!(GrowthReward::Granted { level: 1 }.granted_level(), Some(1));
        assert_eq!(GrowthReward::Granted { level: 6 }.granted_level(), Some(6));
    }

    #[test]
    fn newspaper_mark_handled_promotes_navy_growth_through_reward_levels() {
        let mut actions = PendingActions {
            navy_growth: GrowthReward::Queued { level: Some(1) },
            ..PendingActions::default()
        };
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(actions.navy_growth, GrowthReward::Granted { level: 1 });

        actions.navy_growth = GrowthReward::Queued { level: Some(2) };
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(actions.navy_growth, GrowthReward::Granted { level: 2 });

        actions.navy_growth = GrowthReward::Queued { level: Some(3) };
        mark_pending_status_flags_handled(&mut actions, false);
        assert_eq!(actions.navy_growth, GrowthReward::Granted { level: 3 });
    }
}
