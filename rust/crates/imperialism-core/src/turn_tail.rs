//! Non-military turn-machine tail: pressure, elimination, the post-combat
//! diplomacy-offer gate, the quarter gate, season advance, return-to-map, and
//! turn alerts.
//!
//! Diplomacy-phase offer replies live in [`crate::GameState::do_diplomacy`].
//! Technology and newspaper are in their own modules.

use crate::*;
use serde::{Deserialize, Serialize};

const BASE_PRESSURE: [i32; 5] = [1000, 500, 200, 100, 10];
const PRESSURE_MIN_FLOOR: [i32; 5] = [2, 3, 4, 6, 10];
const PRESSURE_RISE_CAP: [i32; 5] = [20, 35, 50, 75, 100];
const PRESSURE_DECAY_STEP: [i32; 5] = [2, 2, 1, 1, 1];
const PRESSURE_RISE_STEP: [i32; 5] = [1, 1, 1, 2, 3];
const PRESSURE_HARD_ALERT: [i32; 5] = [6, 6, 6, 6, 6];
const PRESSURE_COMPILE_THRESHOLD: [i32; 5] = [5, 5, 5, 5, 5];
const COMMODITY_ALERT_ITEMS: [ManufacturedItem; 5] = [
    ManufacturedItem::Fabric,
    ManufacturedItem::Lumber,
    ManufacturedItem::Paper,
    ManufacturedItem::Steel,
    ManufacturedItem::Fuel,
];

/// Outcome of turn-machine case `0x19`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EliminationOutcome {
    Continue,
    PlayerEliminated,
    Victory,
}

/// Outcome of the quarter-gate check in turn-machine case `0x0e`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarterGateResult {
    Continue,
    DecadeCinematic,
}

impl GameState {
    /// Retail `TGreatPower::UpdateGreatPowerPressureStateAndDispatchEscalationMessage`.
    ///
    /// AI great powers override this to a no-op that returns false.
    pub fn update_great_power_pressure(&mut self, nation: MajorNationId) -> bool {
        if self.is_auto(nation) {
            return false;
        }

        let locale = self.turn.difficulty as usize;
        let treasury = self.nations.majors[nation].common.treasury;
        let mut base_pressure = sum_aid_allocation(&self.nations.majors[nation].economy);
        let need = &self.nations.majors[nation].economy.need_target_by_type;
        base_pressure += i32::from(need[ResourceKind::Gold]) * 200;
        base_pressure += i32::from(need[ResourceKind::Gems]) * 500;
        base_pressure += self.nations.majors[nation].economy.budget_pool_base;
        let floor = BASE_PRESSURE[locale];
        if base_pressure < floor {
            base_pressure = floor;
        }

        let smoothed = (self.nations.majors[nation].economy.diplomacy_budget_base * 90
            + base_pressure * 1000)
            / 100;
        self.nations.majors[nation].economy.diplomacy_budget_base = smoothed;
        let pressure_band = smoothed / 100;
        let mut hard_alert = false;

        if treasury < 0 {
            let half_band = pressure_band / 2;
            if -half_band == treasury || -treasury < half_band {
                self.nations.majors[nation].economy.pressure_counter = 1;
            } else if -pressure_band == treasury || -treasury < pressure_band {
                if self.nations.majors[nation].economy.pressure_counter > 1 {
                    raise_escalation(&mut self.nations.majors[nation].economy, locale);
                }
                self.nations.majors[nation].economy.pressure_counter = 2;
            } else {
                raise_escalation(&mut self.nations.majors[nation].economy, locale);
                let pressure = &mut self.nations.majors[nation].economy.pressure_counter;
                if *pressure < 3 {
                    *pressure = 3;
                } else {
                    *pressure += 1;
                }
                let pressure_tier = i32::from(self.nations.majors[nation].economy.pressure_counter);
                if PRESSURE_HARD_ALERT[locale] <= pressure_tier {
                    hard_alert = true;
                } else if pressure_tier >= PRESSURE_COMPILE_THRESHOLD[locale] {
                    self.compile_great_power_relationship_delta_lines(nation);
                }
            }
        } else if self.nations.majors[nation].economy.pressure_counter != 0 {
            let next = i32::from(self.nations.majors[nation].economy.escalation_counter)
                - PRESSURE_DECAY_STEP[locale];
            self.nations.majors[nation].economy.escalation_counter =
                next.max(PRESSURE_MIN_FLOOR[locale]) as i16;
            self.nations.majors[nation].economy.pressure_counter = 0;
        }

        if hard_alert {
            return true;
        }

        let treasury = self.nations.majors[nation].common.treasury;
        if treasury >= 0 {
            self.nations.majors[nation].economy.army_movement_budget = 0;
            return false;
        }

        let drain = (199
            - i32::from(self.nations.majors[nation].economy.escalation_counter) * treasury)
            / 200;
        self.nations.majors[nation].economy.army_movement_budget = drain;
        self.nations.majors[nation].common.treasury = treasury - drain;
        false
    }

    /// Turn-machine case `0x0b`: update every live great power from slot 6 down to 0.
    pub fn do_great_power_pressure_phase(&mut self) -> bool {
        let mut lost = false;
        for nation in MajorNationId::all().rev() {
            if self.update_great_power_pressure(nation) {
                lost = true;
            }
        }
        lost
    }

    /// Turn-machine case `0x0d`: post-combat diplomacy-offer screen, not the
    /// diplomacy-phase offer replies.
    pub fn diplomacy_offer_gate(&self) -> bool {
        self.pending.combat_reports_pending && self.event_eligible(self.turn.active_nation)
    }

    /// Turn-machine case `0x19`.
    pub fn do_elimination_phase(&mut self) -> EliminationOutcome {
        let mut outcome = EliminationOutcome::Continue;
        if matches!(
            self.status_of(self.turn.active_nation),
            CountryStatus::ProtectorateOf(_)
        ) {
            outcome = EliminationOutcome::PlayerEliminated;
        }

        let empty_majors: Vec<_> = MajorNationId::all()
            .filter(|&nation| {
                self.nations.majors[nation]
                    .common
                    .owned_regions()
                    .is_empty()
            })
            .collect();
        for nation in empty_majors {
            self.remove_nation_slot(nation.nation());
        }

        for minor in MinorNationId::all() {
            let empty = self.nations.minors[minor]
                .as_ref()
                .is_some_and(|nation| nation.common.owned_regions().is_empty());
            if !empty {
                continue;
            }
            for nation in MajorNationId::all() {
                if self.event_eligible(nation.nation()) {
                    self.new_status_for(nation, NationId::new(0), 100);
                }
            }
        }

        if outcome != EliminationOutcome::Continue {
            return outcome;
        }

        let eligible = MajorNationId::all()
            .filter(|&nation| self.event_eligible(nation.nation()))
            .count();
        if eligible == 1 && self.event_eligible(self.turn.active_nation) {
            EliminationOutcome::Victory
        } else {
            EliminationOutcome::Continue
        }
    }

    /// Turn-machine case `0x0e` decade check after any congress-result rewrite.
    pub fn quarter_gate(&mut self) -> QuarterGateResult {
        if let Some(last) = self.diplomacy.last_processed_nation {
            self.turn.phase = if last.nation() == self.turn.active_nation {
                PhaseCode::TOP_TEN_SCORES
            } else {
                PhaseCode::OPENING_CINEMATIC
            };
        } else {
            self.turn.phase = PhaseCode::SEASON_ADVANCE;
        }

        let tick = self.turn.economic_turn;
        let decade = tick / 40;
        if tick % 40 != 0
            || decade < 0
            || decade >= self.turn.quarter_gate_by_decade.len() as i32
            || self.turn.quarter_gate_by_decade[decade as usize] == 0
        {
            QuarterGateResult::Continue
        } else {
            QuarterGateResult::DecadeCinematic
        }
    }

    /// Turn-machine case `0x10`: clear turn-flow flags, advance the season, and
    /// post the technology phase.
    pub fn advance_season_phase(&mut self) {
        self.turn.phase = PhaseCode::TECHNOLOGY_ADVANCES;
        self.turn.turn_flow_status_flags = 0;
        self.turn.advance_season();
    }

    /// Turn-machine case `0x12` reset work, then the strategic map.
    pub fn return_to_map(&mut self) {
        self.turn.phase = PhaseCode::STRATEGIC_MAP;
        for nation in MajorNationId::all() {
            if !self.event_eligible(nation.nation()) {
                continue;
            }
            self.pending.nations[nation].turn_events.clear();
            self.pending.nations[nation].turn_start_events.clear();
        }
    }

    /// Retail `ShowTurnAlertsForActiveNation`. Capitol-threat alerts wait on
    /// military scoring and stay off here.
    pub fn show_turn_alerts(&mut self) -> bool {
        let tick = self.turn.economic_turn;
        if tick == 1 || self.turn.last_turn_alert_tick == tick {
            return false;
        }
        let Some(nation) = MajorNationId::from_nation(self.turn.active_nation) else {
            self.turn.last_turn_alert_tick = tick;
            return false;
        };

        let mut shown = false;
        if self.turn.turn_flow_status_flags & 1 == 0
            && self.treasury_status_prompt_code(nation) != 0
        {
            shown = true;
        }
        if self.turn.turn_flow_status_flags & 0x10 == 0 && self.commodity_record_below_step(nation)
        {
            shown = true;
        }
        if self.turn.turn_flow_status_flags & 0x1000 == 0
            && self.need_current_exceeds_target(nation)
        {
            shown = true;
        }
        if self
            .nations
            .city(nation)
            .forecast_population_food(&self.nations.majors[nation].economy.need_target_by_type)
            .starvation_count
            != 0
        {
            shown = true;
        }

        self.turn.last_turn_alert_tick = tick;
        shown
    }

    fn treasury_status_prompt_code(&self, nation: MajorNationId) -> i16 {
        let last_effort = self.diplomacy.last_diplomatic_effort_turn;
        let tick = self.turn.economic_turn as i16;
        if last_effort == 0 && tick == 3 {
            return 0x25;
        }
        if i32::from(last_effort) - self.turn.economic_turn > 4
            && self.nations.majors[nation].common.treasury >= 10_000
        {
            return 0x27;
        }
        0
    }

    fn commodity_record_below_step(&self, nation: MajorNationId) -> bool {
        let city = self.nations.city(nation);
        if city.population.strength <= 1 {
            return false;
        }
        COMMODITY_ALERT_ITEMS.into_iter().any(|item| {
            self.city_order_limit(nation, CityOrderId::Item(item))
                .maximum
                > self.city_order_quantity(nation, CityOrderId::Item(item))
        })
    }

    fn need_current_exceeds_target(&self, nation: MajorNationId) -> bool {
        let economy = &self.nations.majors[nation].economy;
        if economy.capacities.transport == economy.capacities.reserved_transport {
            return false;
        }
        all_resources().any(|resource| {
            economy.need_current_by_type[resource] > economy.need_target_by_type[resource]
        })
    }

    fn new_status_for(&mut self, nation: MajorNationId, target: NationId, policy_code: i32) {
        self.nations.majors[nation].common.trade_policy_by_nation[target] =
            TradePolicyScore::NEUTRAL;
        self.nations.majors[nation]
            .economy
            .diplomacy_grants_by_nation[target] = None;
        if policy_code == 500 {
            self.nations.majors[nation]
                .economy
                .diplomacy_policy_by_nation[target] = None;
            return;
        }
        if policy_code != 200 && self.is_auto(nation) {
            self.set_enemy(nation, target);
        }
    }

    fn remove_nation_slot(&mut self, removed: NationId) {
        for peer in MajorNationId::all() {
            if peer.nation() == removed || !self.event_eligible(peer.nation()) {
                continue;
            }
            self.new_status_for(peer, removed, 500);
        }

        for other in NationId::all() {
            self.diplomacy.relationships[removed][other] = DiplomaticRelationship::Peace;
            self.diplomacy.relationships[other][removed] = DiplomaticRelationship::Peace;
            self.diplomacy.standings[removed][other] = 0x5a;
            self.diplomacy.standings[other][removed] = 0x5a;
        }
    }
}

fn sum_aid_allocation(economy: &GreatPowerState) -> i32 {
    let mut total = 0;
    for amounts in economy.aid_allocation_by_minor_nation.iter() {
        for resource in all_resources() {
            total += amounts[resource];
        }
    }
    total
}

fn raise_escalation(economy: &mut GreatPowerState, locale: usize) {
    let next = i32::from(economy.escalation_counter) + PRESSURE_RISE_STEP[locale];
    economy.escalation_counter = next.min(PRESSURE_RISE_CAP[locale]) as i16;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn modest_debt_sets_pressure_one_and_drains_treasury() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].kind = MajorNationKind::GreatPower;
        state.nations.majors[nation].common.treasury = -100;
        state.nations.majors[nation].economy.diplomacy_budget_base = 50_000;
        state.nations.majors[nation].economy.escalation_counter = 10;
        state.turn.difficulty = Difficulty::Easy;

        assert!(!state.update_great_power_pressure(nation));
        assert_eq!(state.nations.majors[nation].economy.pressure_counter, 1);
        assert_eq!(state.nations.majors[nation].common.treasury, -105);
        assert_eq!(state.nations.majors[nation].economy.army_movement_budget, 5);
    }

    #[test]
    fn auto_great_power_pressure_is_a_noop() {
        let mut state = game_state();
        let nation = MajorNationId::new(1);
        state.nations.majors[nation].kind = MajorNationKind::AutoGreatPower;
        state.nations.majors[nation].common.treasury = -10_000;
        state.nations.majors[nation].economy.pressure_counter = 4;
        assert!(!state.update_great_power_pressure(nation));
        assert_eq!(state.nations.majors[nation].economy.pressure_counter, 4);
        assert_eq!(state.nations.majors[nation].common.treasury, -10_000);
    }

    #[test]
    fn surplus_decays_existing_pressure() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].kind = MajorNationKind::GreatPower;
        state.nations.majors[nation].common.treasury = 500;
        state.nations.majors[nation].economy.pressure_counter = 2;
        state.nations.majors[nation].economy.escalation_counter = 10;
        state.nations.majors[nation].economy.army_movement_budget = 12;
        state.turn.difficulty = Difficulty::Easy;

        assert!(!state.update_great_power_pressure(nation));
        assert_eq!(state.nations.majors[nation].economy.pressure_counter, 0);
        assert_eq!(state.nations.majors[nation].economy.escalation_counter, 8);
        assert_eq!(state.nations.majors[nation].economy.army_movement_budget, 0);
    }

    #[test]
    fn first_tick_skips_turn_alerts() {
        let mut state = game_state();
        state.turn.economic_turn = 1;
        assert!(!state.show_turn_alerts());
        assert_eq!(state.turn.last_turn_alert_tick, 0);
    }

    #[test]
    fn turn_three_treasury_prompt_marks_alerts_shown() {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.diplomacy.last_diplomatic_effort_turn = 0;
        assert!(state.show_turn_alerts());
        assert_eq!(state.turn.last_turn_alert_tick, 3);
        assert!(!state.show_turn_alerts());
    }

    #[test]
    fn diplomacy_offer_gate_follows_combat_reports_and_eligibility() {
        let mut state = game_state();
        assert!(!state.diplomacy_offer_gate());
        state.pending.combat_reports_pending = true;
        assert!(state.diplomacy_offer_gate());
        state.nations.set_country_status(
            state.turn.active_nation,
            CountryStatus::ProtectorateOf(NationId::new(1)),
        );
        assert!(!state.diplomacy_offer_gate());
    }

    #[test]
    fn quarter_gate_skips_off_decade_and_opens_on_enabled_decade() {
        let mut state = game_state();
        state.turn.economic_turn = 39;
        assert_eq!(state.quarter_gate(), QuarterGateResult::Continue);
        assert_eq!(state.turn.phase, PhaseCode::SEASON_ADVANCE);

        state.diplomacy.last_processed_nation = Some(MajorNationId::new(0));
        state.turn.active_nation = NationId::new(0);
        assert_eq!(state.quarter_gate(), QuarterGateResult::Continue);
        assert_eq!(state.turn.phase, PhaseCode::TOP_TEN_SCORES);

        state.turn.economic_turn = 40;
        state.turn.quarter_gate_by_decade[1] = 1;
        assert_eq!(state.quarter_gate(), QuarterGateResult::DecadeCinematic);

        state.turn.quarter_gate_by_decade[1] = 0;
        assert_eq!(state.quarter_gate(), QuarterGateResult::Continue);
    }

    #[test]
    fn season_advance_clears_flags_and_increments_the_tick() {
        let mut state = game_state();
        state.turn.economic_turn = 4;
        state.turn.turn_flow_status_flags = 0x51;
        state.advance_season_phase();
        assert_eq!(state.turn.economic_turn, 5);
        assert_eq!(state.turn.turn_flow_status_flags, 0);
        assert_eq!(state.turn.phase, PhaseCode::TECHNOLOGY_ADVANCES);
    }

    #[test]
    fn return_to_map_clears_eligible_notice_queues() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.pending.nations[nation]
            .turn_events
            .push(DiplomacyNotice {
                source: NationId::new(1),
                code: 3,
            });
        state.pending.nations[nation]
            .turn_start_events
            .push(TurnStartEvent::Tagged {
                class: "TTurnStartEvent".into(),
                tag: 1,
            });
        state.return_to_map();
        assert_eq!(state.turn.phase, PhaseCode::STRATEGIC_MAP);
        assert!(state.pending.nations[nation].turn_events.is_empty());
        assert!(state.pending.nations[nation].turn_start_events.is_empty());
    }

    #[test]
    fn elimination_continues_when_every_great_power_still_holds_land() {
        let mut state = game_state();
        for nation in MajorNationId::all() {
            state.nations.append_owned_region_during_construction(
                nation.nation(),
                ProvinceId::new(u16::from(nation.get())),
            );
        }
        assert_eq!(state.do_elimination_phase(), EliminationOutcome::Continue);
    }

    #[test]
    fn empty_minor_resets_trade_policy_toward_nation_zero() {
        let mut state = game_state();
        let minor = MinorNationId::new(7);
        state.nations.minors[minor] = Some(MinorNation {
            common: NationCommonState::from_parts(
                "M".into(),
                CountryStatus::Independent,
                Vec::new(),
                0,
                None,
                NationTable::default(),
            ),
            consortium_members: [minor; 4],
            trade: MinorTradeState::default(),
        });
        state.nations.majors[MajorNationId::new(0)]
            .common
            .trade_policy_by_nation[NationId::new(0)] = TradePolicyScore::new(75);

        assert_eq!(state.do_elimination_phase(), EliminationOutcome::Continue);
        assert_eq!(
            state.nations.majors[MajorNationId::new(0)]
                .common
                .trade_policy_by_nation[NationId::new(0)],
            TradePolicyScore::NEUTRAL
        );
    }

    #[test]
    fn protectorate_active_nation_is_eliminated() {
        let mut state = game_state();
        state.nations.set_country_status(
            state.turn.active_nation,
            CountryStatus::ProtectorateOf(NationId::new(1)),
        );
        assert_eq!(
            state.do_elimination_phase(),
            EliminationOutcome::PlayerEliminated
        );
    }
}
