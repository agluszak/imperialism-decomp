"""Shared semantic checkpoint identifiers and normalized observation schemas.

The native scenarios and retail GDB tape intentionally do not share execution code.
They meet only here, after each side has produced observations at a named checkpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


ACTION_RANDOM_GAME_SETUP = "random_game.setup"
ACTION_COMBINED_MAP_ENTRY = "combined_map.enter"
ACTION_CITY_ACTIVATION = "city.activate"
ACTION_TURN_ADVANCEMENT = "turn.advance"
ACTION_DIPLOMACY_PHASE = "diplomacy_phase.run"
ACTION_TRADE_PHASE = "trade_phase.run"
ACTION_CITY_TRANSPORT_PHASE = "city_transport_phase.run"
ACTION_CIVILIANS_PHASE = "civilians_phase.run"
ACTION_MILITARY_PHASE = "military_phase.run"
ACTION_STRATEGIC_NAVAL_BATTLE_MATRIX = "strategic_naval_battle_matrix.run"
ACTION_MILITARY_CLEANUP = "second_turn_military_cleanup.run"
ACTION_RECOMPUTE_METRICS = "recompute_nation_order_priority_metrics.run"
ACTION_REASSESS_MISSIONS = "reassess_control_sea_missions.run"
ACTION_REASSESS_MISSIONS_DAMAGED = (
    "reassess_control_sea_missions_damaged_ship.run"
)
ACTION_AI_NAVAL_DEVELOPMENT = "ai_naval_industry_development.run"
ACTION_SECOND_TURN_SEQUENCE = "second_turn_sequence.run"
ACTION_CONSECUTIVE_TURN_SEQUENCE = "consecutive_turn_sequence.run"
ACTION_CHECK_TECH_ADVANCES = "check_technology_advances.run"
ACTION_CHECK_TECH_ADVANCES_AI = "check_technology_advances_ai_purchase.run"
ACTION_TECH_NAVAL_UPGRADE = "technology_naval_capability_upgrade.run"
ACTION_TECH_NAVAL_SEQUENCE = "technology_naval_capability_sequence.run"
ACTION_NAVY_BATTLE_DEPLOY = "navy_battle_accepted_deploy_tiles.run"
ACTION_NAVY_BATTLE_DEFENDER = "navy_battle_player_as_defender.run"
ACTION_TURN_STOP_TECHNOLOGY = "turn_stop_technology.run"
ACTION_SEASON_ADVANCE = "season_advance_clears_status_flags.run"
ACTION_ELIMINATION_PHASE = "elimination_phase_with_landed_great_powers.run"
ACTION_TURN_ALERTS_FIRST = "turn_alerts_skip_first_economic_turn.run"
ACTION_TURN_ALERTS_LATER = "turn_alerts_later_turn.run"
ACTION_PRESSURE_HUMAN_DEBT = "great_power_pressure_human_debt.run"
ACTION_PRESSURE_AI_NOOP = "great_power_pressure_ai_noop.run"
ACTION_TURN_STOP_DEAL_BOOK = "turn_stop_deal_book.run"
ACTION_TURN_STOP_CITY_TRANSPORT = "turn_stop_city_and_transport.run"
ACTION_TURN_STOP_TRADE = "turn_stop_trade.run"
ACTION_BATTLE_MELEE = "interactive_army_battle_melee.run"
ACTION_BATTLE_RANGED = "interactive_army_battle_ranged.run"
ACTION_COMBAT_UNCONTESTED = "combat_moves_uncontested.run"
ACTION_COMBAT_BATTLE = "combat_moves_creates_battle.run"
ACTION_COMBAT_RESUME = "combat_moves_resumes_after_battle.run"
ACTION_COMBAT_THEN_MOVES = "combat_moves_battle_then_later_movement.run"
ACTION_TURN_STATE_COMBAT_MOVES = "turn_state_combat_moves.run"
ACTION_TURN_STATE_MILITARY_CLEANUP = "turn_state_military_cleanup.run"

CHECKPOINT_RANDOM_SETUP_READY = "random_setup.ready"
CHECKPOINT_COMBINED_MAP_READY = "combined_map.ready"
CHECKPOINT_CITY_ACTIVE = "city.active"
CHECKPOINT_TURN_ADVANCED = "turn.advanced"
CHECKPOINT_DIPLOMACY_PHASE = "diplomacy_phase.resolved"
CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE = "second_turn_diplomacy_phase.resolved"
CHECKPOINT_TRADE_PHASE = "trade_phase.resolved"
CHECKPOINT_SECOND_TURN_TRADE_PHASE = "second_turn_trade_phase.resolved"
CHECKPOINT_CITY_TRANSPORT_PHASE = "city_transport_phase.resolved"
CHECKPOINT_CIVILIANS_PHASE = "civilians_phase.resolved"
CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE = "second_turn_civilians_phase.resolved"
CHECKPOINT_MILITARY_PHASE = "military_phase.resolved"
CHECKPOINT_NAVAL_ENCOUNTER_PHASE = "military_phase_naval_encounter.resolved"
CHECKPOINT_NAVAL_ESCALATION_PHASE = "military_phase_naval_escalation.resolved"
CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX = "strategic_naval_battle_matrix.resolved"
CHECKPOINT_LAND_COMBAT_PHASE = "military_phase_land_combat.resolved"
CHECKPOINT_LAND_INTERACTIVE_PHASE = "military_phase_land_interactive.resolved"
CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE = (
    "military_phase_ships_without_orders.resolved"
)
CHECKPOINT_LAND_RETREAT_PHASE = "military_phase_land_retreat.resolved"
CHECKPOINT_SECOND_TURN_MILITARY_PHASE = "second_turn_military_phase.resolved"
CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP = "second_turn_military_cleanup.resolved"
CHECKPOINT_RECOMPUTE_METRICS = "recompute_nation_order_priority_metrics.resolved"
CHECKPOINT_REASSESS_MISSIONS = "reassess_control_sea_missions.resolved"
CHECKPOINT_REASSESS_MISSIONS_DAMAGED = (
    "reassess_control_sea_missions_damaged_ship.resolved"
)
CHECKPOINT_AI_NAVAL_DEVELOPMENT = "ai_naval_industry_development.resolved"
CHECKPOINT_SECOND_TURN_SEQUENCE = "second_turn_sequence.resolved"
CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE = "consecutive_turn_sequence.resolved"
CHECKPOINT_CHECK_TECH_ADVANCES = "check_technology_advances.resolved"
CHECKPOINT_CHECK_TECH_ADVANCES_AI = (
    "check_technology_advances_ai_purchase.resolved"
)
CHECKPOINT_TECH_NAVAL_UPGRADE = (
    "technology_naval_capability_upgrade.resolved"
)
CHECKPOINT_TECH_NAVAL_SEQUENCE = (
    "technology_naval_capability_sequence.resolved"
)
CHECKPOINT_NAVY_BATTLE_DEPLOY = "navy_battle_accepted_deploy_tiles.resolved"
CHECKPOINT_NAVY_BATTLE_DEFENDER = "navy_battle_player_as_defender.resolved"
CHECKPOINT_TURN_STOP_TECHNOLOGY = "turn_stop_technology.resolved"
CHECKPOINT_SEASON_ADVANCE = "season_advance_clears_status_flags.resolved"
CHECKPOINT_ELIMINATION_PHASE = (
    "elimination_phase_with_landed_great_powers.resolved"
)
CHECKPOINT_TURN_ALERTS_FIRST = "turn_alerts_skip_first_economic_turn.resolved"
CHECKPOINT_TURN_ALERTS_LATER = "turn_alerts_later_turn.resolved"
CHECKPOINT_PRESSURE_HUMAN_DEBT = "great_power_pressure_human_debt.resolved"
CHECKPOINT_PRESSURE_AI_NOOP = "great_power_pressure_ai_noop.resolved"
CHECKPOINT_TURN_STOP_DEAL_BOOK = "turn_stop_deal_book.resolved"
CHECKPOINT_TURN_STOP_CITY_TRANSPORT = "turn_stop_city_and_transport.resolved"
CHECKPOINT_TURN_STOP_TRADE = "turn_stop_trade.resolved"
CHECKPOINT_BATTLE_MELEE = "interactive_army_battle_melee.resolved"
CHECKPOINT_BATTLE_RANGED = "interactive_army_battle_ranged.resolved"
CHECKPOINT_COMBAT_UNCONTESTED = "combat_moves_uncontested.resolved"
CHECKPOINT_COMBAT_BATTLE = "combat_moves_creates_battle.resolved"
CHECKPOINT_COMBAT_RESUME = "combat_moves_resumes_after_battle.resolved"
CHECKPOINT_COMBAT_THEN_MOVES = "combat_moves_battle_then_later_movement.resolved"
CHECKPOINT_TURN_STATE_COMBAT_MOVES = "turn_state_combat_moves.resolved"
CHECKPOINT_TURN_STATE_MILITARY_CLEANUP = "turn_state_military_cleanup.resolved"


@dataclass(frozen=True)
class CheckpointSchema:
    checkpoint_id: str
    action_id: str
    native_test: str
    required_paths: tuple[str, ...]


_COMBAT_MOVES_FIELDS = (
    "turn.phase",
    "turn.active",
    "turn.economic_turn",
    "turn.turn_flow_status_flags",
    "battles",
    "units",
)


_PLAYER_DIPLOMACY_POLICY_SCENARIOS = (
    "player_diplomacy_policy_posts_consulate",
    "player_diplomacy_policy_rejects_consulate_on_major",
    "player_diplomacy_policy_posts_join_empire",
    "player_diplomacy_policy_posts_alliance",
    "player_diplomacy_policy_needs_alliance_entanglement",
    "player_diplomacy_policy_confirms_alliance_entanglement",
    "player_diplomacy_policy_posts_non_aggression_pact",
    "player_diplomacy_policy_posts_peace_treaty",
    "player_diplomacy_policy_posts_declare_war",
    "player_diplomacy_policy_posts_embassy",
    "player_diplomacy_policy_retracts_embassy",
    "player_diplomacy_policy_cannot_afford_committed_consulate",
    "player_diplomacy_policy_rejects_colony",
    "player_diplomacy_policy_selects_self",
    "player_trade_policy_posts_subsidy",
    "player_trade_policy_retracts_subsidy",
    "player_trade_policy_boycott_clears_grant",
    "player_trade_policy_rejects_allied_boycott",
    "player_colony_boycott_posts_and_propagates",
    "player_colony_boycott_retracts_and_propagates",
    "player_colony_boycott_own_colony_no_op",
)


_NATION_ECONOMY_SCENARIOS = (
    "trade_market_price",
    "trade_phase_sell_only",
    "trade_policy_set",
    "trade_policy_step",
    "recall_trade_bids",
    "player_trade_phase_reset",
    "ai_capital_selection_trade_bids",
    "trade_capacity_refresh",
    "major_trade_settlement",
    "purchased_items_phase",
    "direct_transport",
    "transport_need_allocation",
    "transported_items_phase",
    "rolling_stock",
    "rolling_stock_insufficient_resources",
    "merchant_marine",
    "created_items_phase",
    "aid_allocation",
    "power_plant_upgrade",
    "military_maintenance",
    "diplomacy_offer_gate",
    "quarter_gate_off_decade",
    "turn_state_quarter_gate",
)

_DIPLOMACY_ECONOMY_SCENARIOS = (
    "diplomacy_grant_entry_updates_treasury",
    "diplomacy_reset_preserves_recurring_grants",
    "return_to_map_clears_notice_queues",
    "turn_state_diplomacy_phase",
    "turn_state_diplomacy_offer_gate",
    "turn_state_return_to_map",
)

_PROVINCE_SCENARIOS = (
    "province_loss_with_stationed_unit",
    "province_owner_ocean_context",
)

_DEVELOPMENT_SCENARIOS = (
    "completed_rail_section",
    "issued_rail_section",
    "completed_resource_development",
)

_YIELD_SCENARIOS = (
    "nation_resource_yield_rebuild",
    "ai_nation_resource_yield_rebuild_clamps_targets",
    "nation_resource_yield_rebuild_multiple_towns",
)

_GROWTH_SCENARIOS = (
    "navy_growth_pending",
    "army_growth_selected_general",
)

_TACTICAL_SNAPSHOT_SCENARIOS = (
    "interactive_army_battle_done",
    "interactive_army_battle_move",
    "interactive_army_battle_retreat",
)

_ARMY_MILITARY_SCENARIOS = (
    "auto_resolve_land_battle",
    "army_movement_give_orders",
)

_CITY_ITEM_ORDER_SCENARIOS = (
    "city_item_order_increase",
    "city_item_order_decrease",
)

_OPENING_SCENARIOS = (
    "opening_civilian_grant",
    "opening_home_city_setup",
)

_PENDING_STATUS_SCENARIOS = (
    "newspaper_pending_status",
    "newspaper_navy_growth_reward_levels",
)

_NEWS_SCENARIOS = (
    "construct_newspaper_page",
    "construct_newspaper_page_misc_event",
    "turn_stop_newspaper",
)

_ARMY_UI_SCENARIOS = (
    "army_toolbar_counts",
    "army_select_category",
    "army_set_order_mode",
    "army_select_province",
    "army_click_blocked",
    "army_click_friendly",
    "army_click_hostile",
    "army_selection_cycling",
)

_NAVY_UI_SCENARIOS = (
    "navy_create_force",
    "navy_toolbar_counts",
    "navy_select_ship",
    "navy_set_aggression",
    "navy_submit_order",
    "navy_cancel_order",
    "navy_zone_target",
    "navy_province_target",
    "navy_selection_cycling",
    "navy_empty_toolbar",
)


SCHEMAS = {
    CHECKPOINT_RANDOM_SETUP_READY: CheckpointSchema(
        CHECKPOINT_RANDOM_SETUP_READY,
        ACTION_RANDOM_GAME_SETUP,
        "random_game_easy_skips_capital",
        ("turn_event", "active_view", "nation.active"),
    ),
    CHECKPOINT_COMBINED_MAP_READY: CheckpointSchema(
        CHECKPOINT_COMBINED_MAP_READY,
        ACTION_COMBINED_MAP_ENTRY,
        "load_saved_game",
        (
            "turn_event",
            "active_view",
            "nation.active",
            "nation.economic_turn",
            "map.present",
            "map.wrap",
            "city_orders.city_present",
            "city_orders.production_orders",
            "city_orders.production_flags",
        ),
    ),
    CHECKPOINT_CITY_ACTIVE: CheckpointSchema(
        CHECKPOINT_CITY_ACTIVE,
        ACTION_CITY_ACTIVATION,
        "city_screen_opens",
        ("turn_event", "active_view", "nation.active", "city_orders.city_present"),
    ),
    CHECKPOINT_TURN_ADVANCED: CheckpointSchema(
        CHECKPOINT_TURN_ADVANCED,
        ACTION_TURN_ADVANCEMENT,
        "easy_turns_advance",
        ("turn_event", "nation.active", "nation.economic_turn"),
    ),
    CHECKPOINT_DIPLOMACY_PHASE: CheckpointSchema(
        CHECKPOINT_DIPLOMACY_PHASE,
        ACTION_DIPLOMACY_PHASE,
        "diplomacy_phase_applies_grant_and_consulate",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "last_processed_nation",
            "diplomacy.nations",
        ),
    ),
    CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_DIPLOMACY_PHASE,
        ACTION_DIPLOMACY_PHASE,
        "second_turn_diplomacy_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "last_processed_nation",
            "diplomacy.nations",
        ),
    ),
    CHECKPOINT_TRADE_PHASE: CheckpointSchema(
        CHECKPOINT_TRADE_PHASE,
        ACTION_TRADE_PHASE,
        "trade_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "trade.market",
            "trade.nations",
        ),
    ),
    CHECKPOINT_SECOND_TURN_TRADE_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_TRADE_PHASE,
        ACTION_TRADE_PHASE,
        "second_turn_trade_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "trade.market",
            "trade.nations",
        ),
    ),
    CHECKPOINT_CITY_TRANSPORT_PHASE: CheckpointSchema(
        CHECKPOINT_CITY_TRANSPORT_PHASE,
        ACTION_CITY_TRANSPORT_PHASE,
        "city_and_transport_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "city_transport.nations",
            "city_transport.regions",
        ),
    ),
    CHECKPOINT_CIVILIANS_PHASE: CheckpointSchema(
        CHECKPOINT_CIVILIANS_PHASE,
        ACTION_CIVILIANS_PHASE,
        "civilians_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "civilians.units",
            "civilians.nations",
        ),
    ),
    CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_CIVILIANS_PHASE,
        ACTION_CIVILIANS_PHASE,
        "second_turn_civilians_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "civilians.units",
            "civilians.nations",
        ),
    ),
    CHECKPOINT_MILITARY_PHASE: CheckpointSchema(
        CHECKPOINT_MILITARY_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_NAVAL_ENCOUNTER_PHASE: CheckpointSchema(
        CHECKPOINT_NAVAL_ENCOUNTER_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_naval_encounter",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_NAVAL_ESCALATION_PHASE: CheckpointSchema(
        CHECKPOINT_NAVAL_ESCALATION_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_naval_escalation",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX: CheckpointSchema(
        CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX,
        ACTION_STRATEGIC_NAVAL_BATTLE_MATRIX,
        "strategic_naval_battle_matrix",
        ("cases",),
    ),
    CHECKPOINT_LAND_COMBAT_PHASE: CheckpointSchema(
        CHECKPOINT_LAND_COMBAT_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_land_combat",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "military.land_battle",
            "military.province_owners",
        ),
    ),
    CHECKPOINT_LAND_INTERACTIVE_PHASE: CheckpointSchema(
        CHECKPOINT_LAND_INTERACTIVE_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_land_interactive",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "military.land_battle",
            "military.province_owners",
        ),
    ),
    CHECKPOINT_LAND_RETREAT_PHASE: CheckpointSchema(
        CHECKPOINT_LAND_RETREAT_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_land_retreat",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "military.land_battle",
            "military.province_owners",
        ),
    ),
    CHECKPOINT_SECOND_TURN_MILITARY_PHASE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_MILITARY_PHASE,
        ACTION_MILITARY_PHASE,
        "second_turn_military_phase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
    CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
        ACTION_MILITARY_CLEANUP,
        "second_turn_military_cleanup",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military_cleanup.region_scores",
            "military_cleanup.city_score_total",
            "military_cleanup.queue_divergence",
            "military_cleanup.mobile_score",
            "military_cleanup.mobile_divergence",
            "military_cleanup.combined_divergence",
            "military_cleanup.weighted_military",
            "military_cleanup.expansion_pressure",
            "military_cleanup.unit_divergence",
            "military_cleanup.mission_pressure",
        ),
    ),
    CHECKPOINT_TURN_STATE_COMBAT_MOVES: CheckpointSchema(
        CHECKPOINT_TURN_STATE_COMBAT_MOVES,
        ACTION_TURN_STATE_COMBAT_MOVES,
        "turn_state_combat_moves",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "dispatched_event",
            "military.nations",
            "military.ships",
            "military.task_forces",
            "rng.crt_rand",
            "rng.map_generation",
            "rng.zone_status",
        ),
    ),
    CHECKPOINT_TURN_STATE_MILITARY_CLEANUP: CheckpointSchema(
        CHECKPOINT_TURN_STATE_MILITARY_CLEANUP,
        ACTION_TURN_STATE_MILITARY_CLEANUP,
        "turn_state_military_cleanup",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "dispatched_event",
            "military_cleanup.region_scores",
            "military_cleanup.city_score_total",
            "military_cleanup.queue_divergence",
            "military_cleanup.mobile_score",
            "military_cleanup.mobile_divergence",
            "military_cleanup.combined_divergence",
            "military_cleanup.weighted_military",
            "military_cleanup.expansion_pressure",
            "military_cleanup.unit_divergence",
            "military_cleanup.mission_pressure",
            "trade.nations",
            "diplomacy.nations",
            "missions",
            "rng.crt_rand",
            "rng.map_generation",
            "rng.zone_status",
        ),
    ),
    CHECKPOINT_RECOMPUTE_METRICS: CheckpointSchema(
        CHECKPOINT_RECOMPUTE_METRICS,
        ACTION_RECOMPUTE_METRICS,
        "recompute_nation_order_priority_metrics",
        (
            "queue_divergence",
            "mobile_score",
            "mobile_divergence",
            "combined_divergence",
            "weighted_military",
            "expansion_pressure",
            "unit_divergence",
            "mission_pressure",
        ),
    ),
    CHECKPOINT_REASSESS_MISSIONS: CheckpointSchema(
        CHECKPOINT_REASSESS_MISSIONS,
        ACTION_REASSESS_MISSIONS,
        "reassess_control_sea_missions",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "missions",
        ),
    ),
    CHECKPOINT_REASSESS_MISSIONS_DAMAGED: CheckpointSchema(
        CHECKPOINT_REASSESS_MISSIONS_DAMAGED,
        ACTION_REASSESS_MISSIONS_DAMAGED,
        "reassess_control_sea_missions_damaged_ship",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "missions",
        ),
    ),
    CHECKPOINT_AI_NAVAL_DEVELOPMENT: CheckpointSchema(
        CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        ACTION_AI_NAVAL_DEVELOPMENT,
        "ai_naval_industry_development",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "missions",
            "development",
        ),
    ),
    CHECKPOINT_SECOND_TURN_SEQUENCE: CheckpointSchema(
        CHECKPOINT_SECOND_TURN_SEQUENCE,
        ACTION_SECOND_TURN_SEQUENCE,
        "second_turn_sequence",
        (
            "stops",
            "economic_turn",
        ),
    ),
    CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE: CheckpointSchema(
        CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        ACTION_CONSECUTIVE_TURN_SEQUENCE,
        "consecutive_turn_sequence",
        (
            "stops",
            "economic_turns",
        ),
    ),
    CHECKPOINT_CHECK_TECH_ADVANCES: CheckpointSchema(
        CHECKPOINT_CHECK_TECH_ADVANCES,
        ACTION_CHECK_TECH_ADVANCES,
        "check_technology_advances",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "technology",
        ),
    ),
    CHECKPOINT_CHECK_TECH_ADVANCES_AI: CheckpointSchema(
        CHECKPOINT_CHECK_TECH_ADVANCES_AI,
        ACTION_CHECK_TECH_ADVANCES_AI,
        "check_technology_advances_ai_purchase",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "technology",
        ),
    ),
    CHECKPOINT_TECH_NAVAL_UPGRADE: CheckpointSchema(
        CHECKPOINT_TECH_NAVAL_UPGRADE,
        ACTION_TECH_NAVAL_UPGRADE,
        "technology_naval_capability_upgrade",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "technology",
        ),
    ),
    CHECKPOINT_TECH_NAVAL_SEQUENCE: CheckpointSchema(
        CHECKPOINT_TECH_NAVAL_SEQUENCE,
        ACTION_TECH_NAVAL_SEQUENCE,
        "technology_naval_capability_sequence",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "technology",
        ),
    ),
    CHECKPOINT_TURN_STOP_TECHNOLOGY: CheckpointSchema(
        CHECKPOINT_TURN_STOP_TECHNOLOGY,
        ACTION_TURN_STOP_TECHNOLOGY,
        "turn_stop_technology",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "technology",
        ),
    ),
    CHECKPOINT_SEASON_ADVANCE: CheckpointSchema(
        CHECKPOINT_SEASON_ADVANCE,
        ACTION_SEASON_ADVANCE,
        "season_advance_clears_status_flags",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
        ),
    ),
    CHECKPOINT_ELIMINATION_PHASE: CheckpointSchema(
        CHECKPOINT_ELIMINATION_PHASE,
        ACTION_ELIMINATION_PHASE,
        "elimination_phase_with_landed_great_powers",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "eligibility",
            "nation_encoded",
            "nation_status",
            "dispatched_event",
            "rng.crt_rand",
            "rng.map_generation",
            "rng.zone_status",
        ),
    ),
    CHECKPOINT_TURN_ALERTS_FIRST: CheckpointSchema(
        CHECKPOINT_TURN_ALERTS_FIRST,
        ACTION_TURN_ALERTS_FIRST,
        "turn_alerts_skip_first_economic_turn",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "shown",
        ),
    ),
    CHECKPOINT_TURN_ALERTS_LATER: CheckpointSchema(
        CHECKPOINT_TURN_ALERTS_LATER,
        ACTION_TURN_ALERTS_LATER,
        "turn_alerts_later_turn",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "alerts",
        ),
    ),
    CHECKPOINT_PRESSURE_HUMAN_DEBT: CheckpointSchema(
        CHECKPOINT_PRESSURE_HUMAN_DEBT,
        ACTION_PRESSURE_HUMAN_DEBT,
        "great_power_pressure_human_debt",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "lost",
            "nations",
        ),
    ),
    CHECKPOINT_PRESSURE_AI_NOOP: CheckpointSchema(
        CHECKPOINT_PRESSURE_AI_NOOP,
        ACTION_PRESSURE_AI_NOOP,
        "great_power_pressure_ai_noop",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "lost",
            "nations",
        ),
    ),
    CHECKPOINT_TURN_STOP_DEAL_BOOK: CheckpointSchema(
        CHECKPOINT_TURN_STOP_DEAL_BOOK,
        ACTION_TURN_STOP_DEAL_BOOK,
        "turn_stop_deal_book",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
        ),
    ),
    CHECKPOINT_TURN_STOP_CITY_TRANSPORT: CheckpointSchema(
        CHECKPOINT_TURN_STOP_CITY_TRANSPORT,
        ACTION_TURN_STOP_CITY_TRANSPORT,
        "turn_stop_city_and_transport",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
        ),
    ),
    CHECKPOINT_TURN_STOP_TRADE: CheckpointSchema(
        CHECKPOINT_TURN_STOP_TRADE,
        ACTION_TURN_STOP_TRADE,
        "turn_stop_trade",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "stop",
            "phase",
            "category_index",
            "entry_ordinal",
            "buyer",
            "seller",
            "amount",
            "price",
            "commodity",
            "deals",
        ),
    ),
    CHECKPOINT_BATTLE_MELEE: CheckpointSchema(
        CHECKPOINT_BATTLE_MELEE,
        ACTION_BATTLE_MELEE,
        "interactive_army_battle_melee",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "kinds",
            "targets",
            "actuals",
            "snapshots",
        ),
    ),
    CHECKPOINT_BATTLE_RANGED: CheckpointSchema(
        CHECKPOINT_BATTLE_RANGED,
        ACTION_BATTLE_RANGED,
        "interactive_army_battle_ranged",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "kinds",
            "targets",
            "actuals",
            "snapshots",
        ),
    ),
    CHECKPOINT_COMBAT_UNCONTESTED: CheckpointSchema(
        CHECKPOINT_COMBAT_UNCONTESTED,
        ACTION_COMBAT_UNCONTESTED,
        "combat_moves_uncontested",
        _COMBAT_MOVES_FIELDS,
    ),
    CHECKPOINT_COMBAT_BATTLE: CheckpointSchema(
        CHECKPOINT_COMBAT_BATTLE,
        ACTION_COMBAT_BATTLE,
        "combat_moves_creates_battle",
        _COMBAT_MOVES_FIELDS,
    ),
    CHECKPOINT_COMBAT_RESUME: CheckpointSchema(
        CHECKPOINT_COMBAT_RESUME,
        ACTION_COMBAT_RESUME,
        "combat_moves_resumes_after_battle",
        _COMBAT_MOVES_FIELDS,
    ),
    CHECKPOINT_COMBAT_THEN_MOVES: CheckpointSchema(
        CHECKPOINT_COMBAT_THEN_MOVES,
        ACTION_COMBAT_THEN_MOVES,
        "combat_moves_battle_then_later_movement",
        _COMBAT_MOVES_FIELDS,
    ),
    CHECKPOINT_NAVY_BATTLE_DEPLOY: CheckpointSchema(
        CHECKPOINT_NAVY_BATTLE_DEPLOY,
        ACTION_NAVY_BATTLE_DEPLOY,
        "navy_battle_accepted_deploy_tiles",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "column_count",
            "current_side",
            "side0_nation",
            "side1_nation",
            "side0_selected",
            "side1_selected",
            "side0_tiles",
            "side1_tiles",
        ),
    ),
    CHECKPOINT_NAVY_BATTLE_DEFENDER: CheckpointSchema(
        CHECKPOINT_NAVY_BATTLE_DEFENDER,
        ACTION_NAVY_BATTLE_DEFENDER,
        "navy_battle_player_as_defender",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "column_count",
            "current_side",
            "side0_nation",
            "side1_nation",
            "side0_selected",
            "side1_selected",
            "side0_tiles",
            "side1_tiles",
        ),
    ),
    CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE: CheckpointSchema(
        CHECKPOINT_SHIPS_WITHOUT_ORDERS_PHASE,
        ACTION_MILITARY_PHASE,
        "military_phase_ships_without_orders",
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    ),
}


for _policy_scenario in _PLAYER_DIPLOMACY_POLICY_SCENARIOS:
    SCHEMAS[_policy_scenario + ".resolved"] = CheckpointSchema(
        _policy_scenario + ".resolved",
        _policy_scenario + ".run",
        _policy_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "toggle",
            "diplomacy.nations",
        ),
    )
del _policy_scenario

for _economy_scenario in _NATION_ECONOMY_SCENARIOS:
    SCHEMAS[_economy_scenario + ".resolved"] = CheckpointSchema(
        _economy_scenario + ".resolved",
        _economy_scenario + ".run",
        _economy_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "toggle",
            "trade.market",
            "trade.nations",
        )
        + (
            (
                "dispatched_event",
                "rng.crt_rand",
                "rng.map_generation",
                "rng.zone_status",
            )
            if _economy_scenario.startswith("turn_state_")
            else ()
        ),
    )
del _economy_scenario

for _diplo_economy_scenario in _DIPLOMACY_ECONOMY_SCENARIOS:
    SCHEMAS[_diplo_economy_scenario + ".resolved"] = CheckpointSchema(
        _diplo_economy_scenario + ".resolved",
        _diplo_economy_scenario + ".run",
        _diplo_economy_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "toggle",
            "diplomacy.nations",
        )
        + (
            (
                "missions",
                "dispatched_event",
                "rng.crt_rand",
                "rng.map_generation",
                "rng.zone_status",
            )
            if _diplo_economy_scenario.startswith("turn_state_")
            else ()
        ),
    )
del _diplo_economy_scenario

SCHEMAS["province_loss_with_stationed_unit.resolved"] = CheckpointSchema(
    "province_loss_with_stationed_unit.resolved",
    "province_loss_with_stationed_unit.run",
    "province_loss_with_stationed_unit",
    (
        "turn.phase",
        "turn.active",
        "turn.economic_turn",
        "turn.turn_flow_status_flags",
        "military.nations",
        "military.ships",
        "military.task_forces",
        "military.province_owners",
        "civilians.units",
        "civilians.nations",
    ),
)
for _dev_scenario in _DEVELOPMENT_SCENARIOS:
    SCHEMAS[_dev_scenario + ".resolved"] = CheckpointSchema(
        _dev_scenario + ".resolved",
        _dev_scenario + ".run",
        _dev_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "civilians.units",
            "civilians.nations",
            "tiles",
        ),
    )
del _dev_scenario

for _yield_scenario in _YIELD_SCENARIOS:
    SCHEMAS[_yield_scenario + ".resolved"] = CheckpointSchema(
        _yield_scenario + ".resolved",
        _yield_scenario + ".run",
        _yield_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "trade.nations",
            "civilians.units",
            "civilians.nations",
        ),
    )
del _yield_scenario

SCHEMAS["owned_region_development.resolved"] = CheckpointSchema(
    "owned_region_development.resolved",
    "owned_region_development.run",
    "owned_region_development",
    (
        "turn.phase",
        "turn.active",
        "turn.economic_turn",
        "turn.turn_flow_status_flags",
        "trade.nations",
        "civilians.units",
        "civilians.nations",
        "provinces",
    ),
)

SCHEMAS["specialist_recruitment.resolved"] = CheckpointSchema(
    "specialist_recruitment.resolved",
    "specialist_recruitment.run",
    "specialist_recruitment",
    (
        "turn.phase",
        "turn.active",
        "turn.economic_turn",
        "turn.turn_flow_status_flags",
        "civilians.units",
        "civilians.nations",
    ),
)

for _growth_scenario in _GROWTH_SCENARIOS:
    SCHEMAS[_growth_scenario + ".resolved"] = CheckpointSchema(
        _growth_scenario + ".resolved",
        _growth_scenario + ".run",
        _growth_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    )
del _growth_scenario

for _army_scenario in _ARMY_MILITARY_SCENARIOS:
    SCHEMAS[_army_scenario + ".resolved"] = CheckpointSchema(
        _army_scenario + ".resolved",
        _army_scenario + ".run",
        _army_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "military.nations",
            "military.ships",
            "military.task_forces",
        ),
    )
del _army_scenario

SCHEMAS["advisory_map_missions_case16.resolved"] = CheckpointSchema(
    "advisory_map_missions_case16.resolved",
    "advisory_map_missions_case16.run",
    "advisory_map_missions_case16",
    (
        "turn.phase",
        "turn.active",
        "turn.economic_turn",
        "missions",
    ),
)

for _tactical_scenario in _TACTICAL_SNAPSHOT_SCENARIOS:
    _fields = [
        "turn.phase",
        "turn.active",
        "turn.economic_turn",
        "snapshots",
    ]
    if _tactical_scenario == "interactive_army_battle_move":
        _fields += ["targets", "actuals"]
    SCHEMAS[_tactical_scenario + ".resolved"] = CheckpointSchema(
        _tactical_scenario + ".resolved",
        _tactical_scenario + ".run",
        _tactical_scenario,
        tuple(_fields),
    )
del _tactical_scenario, _fields

for _item_order_scenario in _CITY_ITEM_ORDER_SCENARIOS:
    SCHEMAS[_item_order_scenario + ".resolved"] = CheckpointSchema(
        _item_order_scenario + ".resolved",
        _item_order_scenario + ".run",
        _item_order_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "civilians.units",
            "civilians.nations",
            "applied",
            "quantity",
            "requested",
            "fabric_tracking",
        ),
    )
del _item_order_scenario

SCHEMAS["province_owner_ocean_context.resolved"] = CheckpointSchema(
    "province_owner_ocean_context.resolved",
    "province_owner_ocean_context.run",
    "province_owner_ocean_context",
    (
        "turn.phase",
        "turn.active",
        "turn.economic_turn",
        "turn.turn_flow_status_flags",
        "province_owners",
        "missions",
    ),
)

for _opening_scenario in _OPENING_SCENARIOS:
    SCHEMAS[_opening_scenario + ".resolved"] = CheckpointSchema(
        _opening_scenario + ".resolved",
        _opening_scenario + ".run",
        _opening_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "civilians.units",
            "civilians.nations",
        ),
    )
del _opening_scenario

for _pending_scenario in _PENDING_STATUS_SCENARIOS:
    SCHEMAS[_pending_scenario + ".resolved"] = CheckpointSchema(
        _pending_scenario + ".resolved",
        _pending_scenario + ".run",
        _pending_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "pending_nations",
        ),
    )
del _pending_scenario

for _news_scenario in _NEWS_SCENARIOS:
    SCHEMAS[_news_scenario + ".resolved"] = CheckpointSchema(
        _news_scenario + ".resolved",
        _news_scenario + ".run",
        _news_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "news",
            "newspaper_events",
        )
        + (
            (
                "dispatched_event",
                "pending_nations",
                "rng.crt_rand",
                "rng.map_generation",
                "rng.zone_status",
            )
            if _news_scenario == "turn_stop_newspaper"
            else ()
        ),
    )
del _news_scenario

for _army_ui_scenario in _ARMY_UI_SCENARIOS:
    SCHEMAS[_army_ui_scenario + ".resolved"] = CheckpointSchema(
        _army_ui_scenario + ".resolved",
        _army_ui_scenario + ".run",
        _army_ui_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "military.nations",
            "result",
        ),
    )
del _army_ui_scenario

for _navy_ui_scenario in _NAVY_UI_SCENARIOS:
    SCHEMAS[_navy_ui_scenario + ".resolved"] = CheckpointSchema(
        _navy_ui_scenario + ".resolved",
        _navy_ui_scenario + ".run",
        _navy_ui_scenario,
        (
            "turn.phase",
            "turn.active",
            "turn.economic_turn",
            "turn.turn_flow_status_flags",
            "military.nations",
            "result",
        ),
    )
del _navy_ui_scenario


_RESOURCE_NAMES = (
    "cotton", "wool", "timber", "coal", "iron", "horses", "oil", "food",
    "fabric", "lumber", "paper", "steel", "fuel", "clothing", "furniture",
    "hardware", "arms", "grain", "fruit", "fish", "livestock", "gems", "gold",
)


_DIPLOMACY_POLICY_NAMES = {
    0x12D: "join_empire",
    0x12E: "alliance",
    0x12F: "non_aggression_pact",
    0x130: "peace_treaty",
    0x131: "declare_war",
    0x132: "join_empire_with_war_entanglements",
    0x133: "build_consulate",
    0x134: "build_embassy",
}


def _native_captures(result: Mapping[str, Any]) -> Mapping[str, Any]:
    captures = result.get("captures")
    if not isinstance(captures, Mapping):
        captures_path = result.get("captures_path")
        if isinstance(captures_path, str) and captures_path:
            from pathlib import Path

            from tools.runtime.protocol import load_captures

            captures = load_captures(
                dict(result),
                Path(captures_path) if Path(captures_path).is_absolute() else Path("."),
            )
        else:
            captures = None
    return _require_mapping(captures, "native captures")


def _diplomacy_policy_name(code: Any, label: str) -> str | None:
    value = _require_int(code, label)
    if value == -1:
        return None
    name = _DIPLOMACY_POLICY_NAMES.get(value)
    if name is None:
        raise ValueError(f"{label} has no semantic representation: {value:#x}")
    return name


def _diplomacy_grant(entry: Any, label: str) -> dict[str, Any] | None:
    value = _require_int(entry, label)
    if value == -1:
        return None
    if value < -1:
        raise ValueError(f"{label} is below the -1 sentinel: {value}")
    return {"amount": value & 0x3FFF, "recurring": (value & 0x4000) != 0}


def _native_diplomacy_policy_nations(
    nations: Any, label: str
) -> list[Any]:
    if not isinstance(nations, list):
        raise ValueError(f"{label} nations must be an array")
    normalized = []
    for entry in nations:
        if entry is None:
            normalized.append(None)
            continue
        nation = _require_mapping(entry, f"{label} nation entry")
        normalized.append(
            {
                "treasury": _require_int(
                    nation.get("treasury"), f"{label} nation.treasury"
                ),
                "needs": _require_int_list(
                    nation.get("needs"), f"{label} nation.needs"
                ),
                "boycotts": _require_int_list(
                    nation.get("boycotts"), f"{label} nation.boycotts"
                ),
                "policies": nation.get("policies"),
                "grants": nation.get("grants"),
                "proposals": nation.get("proposals"),
                "turn_events": nation.get("turn_events"),
            }
        )
    return normalized


def _retail_diplomacy_policy_nations(
    nations_raw: Any,
) -> list[Any]:
    if not isinstance(nations_raw, list):
        raise ValueError("retail diplomacy_nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"retail diplomacy nation {slot}")
        policies_raw = _require_int_list(
            nation_map.get("policies"), f"retail policies[{slot}]"
        )
        grants_raw = _require_int_list(
            nation_map.get("grants"), f"retail grants[{slot}]"
        )
        nations.append(
            {
                "treasury": _require_int(
                    nation_map.get("treasury"), f"retail treasury[{slot}]"
                ),
                "needs": _require_int_list(
                    nation_map.get("needs"), f"retail needs[{slot}]"
                ),
                "boycotts": _require_int_list(
                    nation_map.get("boycotts"), f"retail boycotts[{slot}]"
                ),
                "policies": [
                    _diplomacy_policy_name(
                        code, f"retail policies[{slot}][{index}]"
                    )
                    for index, code in enumerate(policies_raw)
                ],
                "grants": [
                    _diplomacy_grant(
                        entry, f"retail grants[{slot}][{index}]"
                    )
                    for index, entry in enumerate(grants_raw)
                ],
                "proposals": _diplomacy_proposals(
                    nation_map.get("proposals"), f"retail proposals[{slot}]"
                ),
                "turn_events": _diplomacy_records(
                    nation_map.get("turn_events"),
                    f"retail turn_events[{slot}]",
                ),
            }
        )
    return nations


def normalize_native_player_diplomacy_policy(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a native player-diplomacy-policy case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    toggle = captures.get("result")
    if not isinstance(toggle, (bool, int)):
        if toggle is not None:
            raise ValueError("native result must be a number")
        toggle = 0
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    diplomacy = _require_mapping(
        ephemeral.get("diplomacy"), "native ephemeral diplomacy"
    )
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
        "toggle": int(toggle),
        "diplomacy": {
            "nations": _native_diplomacy_policy_nations(
                diplomacy.get("nations"), "native"
            )
        },
    }
    if checkpoint_id.startswith("turn_state_"):
        observation["missions"] = _mission_records(
            ephemeral.get("missions"), "native missions"
        )
        observation["dispatched_event"] = _require_int(
            turn.get("dispatched_event"), "native dispatched_event"
        )
        observation["rng"] = _rng_state(ephemeral.get("rng"), "native rng")
    return observation


def normalize_retail_player_diplomacy_policy(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail player-diplomacy-policy capture to the same schema."""
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "toggle": _require_int(raw.get("toggle"), "retail toggle"),
        "diplomacy": {
            "nations": _retail_diplomacy_policy_nations(
                raw.get("diplomacy_nations")
            )
        },
    }
    if checkpoint_id.startswith("turn_state_"):
        observation["missions"] = _mission_records(
            raw.get("missions"), "retail missions"
        )
        observation["dispatched_event"] = _require_int(
            raw.get("dispatched_event"), "retail dispatched_event"
        )
        observation["rng"] = _rng_state(raw.get("rng"), "retail rng")
    return observation


def normalize_native_diplomacy_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_DIPLOMACY_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable diplomacy-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    diplomacy = _require_mapping(ephemeral.get("diplomacy"), "native ephemeral diplomacy")
    nations = diplomacy.get("nations")
    if isinstance(nations, list):
        for nation in nations:
            if isinstance(nation, dict):
                nation.pop("encoded_slot", None)
                nation.pop("terrain_eligible", None)
                nation.pop("budget_base", None)
                nation.pop("escalation", None)
                nation.pop("pressure", None)
                nation.pop("needs", None)
                nation.pop("boycotts", None)
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_DIPLOMACY_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "last_processed_nation": ephemeral.get("last_processed_nation"),
        "diplomacy": diplomacy,
    }


def normalize_retail_diplomacy_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_DIPLOMACY_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB diplomacy capture to the same stable schema."""
    nations_raw = raw.get("diplomacy_nations")
    if not isinstance(nations_raw, list):
        raise ValueError("retail diplomacy_nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"retail diplomacy nation {slot}")
        policies_raw = _require_int_list(
            nation_map.get("policies"), f"retail policies[{slot}]"
        )
        grants_raw = _require_int_list(
            nation_map.get("grants"), f"retail grants[{slot}]"
        )
        nations.append(
            {
                "treasury": _require_int(
                    nation_map.get("treasury"), f"retail treasury[{slot}]"
                ),
                "policies": [
                    _diplomacy_policy_name(code, f"retail policies[{slot}][{index}]")
                    for index, code in enumerate(policies_raw)
                ],
                "grants": [
                    _diplomacy_grant(entry, f"retail grants[{slot}][{index}]")
                    for index, entry in enumerate(grants_raw)
                ],
                "proposals": _diplomacy_proposals(
                    nation_map.get("proposals"), f"retail proposals[{slot}]"
                ),
                "turn_events": _diplomacy_records(
                    nation_map.get("turn_events"), f"retail turn_events[{slot}]"
                ),
            }
        )
    last_processed = raw.get("last_processed_nation")
    if last_processed == -1:
        last_processed = None
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_DIPLOMACY_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "last_processed_nation": last_processed,
        "diplomacy": {"nations": nations},
    }


def _diplomacy_proposals(records: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} must be an array")
    normalized = []
    for index, record in enumerate(records):
        record_map = _require_mapping(record, f"{label}[{index}]")
        normalized.append(
            {
                "source": _require_int(
                    record_map.get("source"), f"{label}[{index}].source"
                ),
                "policy": _diplomacy_policy_name(
                    record_map.get("code"), f"{label}[{index}].policy"
                ),
            }
        )
    return normalized


def normalize_native_trade_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_TRADE_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable trade-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    trade = _require_mapping(ephemeral.get("trade"), "native ephemeral trade")
    for row in _require_mapping(
        trade.get("market"), "native trade.market"
    ).get("rows", {}).values():
        if isinstance(row, Mapping) and "adjusted_offer_count" in row:
            row["adjusted_offer_count"] = float(row["adjusted_offer_count"])
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_TRADE_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "last_processed_nation": ephemeral.get("last_processed_nation"),
        "trade": trade,
    }


_TRADE_NATION_INT_FIELDS = (
    "treasury",
    "available_merchant",
    "merchant_capacity",
    "transport_capacity",
    "reserved_transport",
    "unfilled_trade_offer_count",
    "diplomacy_eligibility",
    "grant_total",
    "budget_pool_base",
    "budget_pool_delta",
    "aid_allocation_total",
    "military_expenses",
)

_TRADE_NATION_ARRAY_FIELDS = (
    "item_potentials",
    "remembered_trade_offers",
    "purchased_items",
    "transported_items",
    "unfilled_trade_turns",
    "need_current",
    "need_target",
    "relation_delta",
    "city_stocks",
)


def _require_int_pairs(value: Any, label: str) -> list[list[int]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array of [index, value] pairs")
    pairs: list[list[int]] = []
    for index, pair in enumerate(value):
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError(f"{label}[{index}] must be a pair")
        pairs.append(
            [
                _require_int(pair[0], f"{label}[{index}][0]"),
                _require_int(pair[1], f"{label}[{index}][1]"),
            ]
        )
    return pairs


def normalize_retail_trade_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_TRADE_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB trade capture to the same stable schema."""
    rows_raw = raw.get("market_rows")
    if not isinstance(rows_raw, list) or len(rows_raw) != 17:
        raise ValueError("retail market_rows must hold the 17 priced categories")
    rows: dict[str, Any] = {}
    for index, row in enumerate(rows_raw):
        row_map = _require_mapping(row, f"retail market row {index}")
        rows[_RESOURCE_NAMES[index]] = {
            "previous_price": _require_int(
                row_map.get("previous_price"), f"retail previous_price[{index}]"
            ),
            "price": _require_int(row_map.get("price"), f"retail price[{index}]"),
            "base_price": _require_int(
                row_map.get("base_price"), f"retail base_price[{index}]"
            ),
            "request_count": _require_int(
                row_map.get("request_count"), f"retail request_count[{index}]"
            ),
            "offer_count": _require_int(
                row_map.get("offer_count"), f"retail offer_count[{index}]"
            ),
            "amount_offered": _require_int(
                row_map.get("amount_offered"), f"retail amount_offered[{index}]"
            ),
            "adjusted_offer_count": float(
                _require_number(
                    row_map.get("adjusted_offer_count"),
                    f"retail adjusted_offer_count[{index}]",
                )
            ),
            "current_offer_by_nation": _require_int_list(
                row_map.get("current_offer_by_nation"),
                f"retail current_offer_by_nation[{index}]",
            ),
            "maximum_offer_by_nation": _require_int_list(
                row_map.get("maximum_offer_by_nation"),
                f"retail maximum_offer_by_nation[{index}]",
            ),
        }
    nations_raw = raw.get("trade_nations")
    if not isinstance(nations_raw, list):
        raise ValueError("retail trade_nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"retail trade nation {slot}")
        entry: dict[str, Any] = {
            field: _require_int(
                nation_map.get(field), f"retail {field}[{slot}]"
            )
            for field in _TRADE_NATION_INT_FIELDS
        }
        for field in _TRADE_NATION_ARRAY_FIELDS:
            value = nation_map.get(field)
            entry[field] = (
                None
                if value is None
                else _require_int_list(value, f"retail {field}[{slot}]")
            )
        entry["aid_nonzero"] = _require_int_pairs(
            nation_map.get("aid_nonzero"), f"retail aid_nonzero[{slot}]"
        )
        power_flag = nation_map.get("city_power_flag")
        entry["city_power_flag"] = (
            None
            if power_flag is None
            else _require_int(power_flag, f"retail city_power_flag[{slot}]")
        )
        nations.append(entry)
    last_processed = raw.get("last_processed_nation")
    if last_processed == -1:
        last_processed = None
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_TRADE_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "last_processed_nation": last_processed,
        "trade": {"market": {"rows": rows}, "nations": nations},
    }


def normalize_native_nation_economy(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Trade-phase schema plus the scalar Finish() result (JSON null -> 0)."""
    observation = normalize_native_trade_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    toggle = _native_captures(result).get("result")
    observation["toggle"] = (
        int(toggle) if isinstance(toggle, (bool, int)) else 0
    )
    if checkpoint_id.startswith("turn_state_"):
        after = _require_mapping(
            _native_captures(result).get("after"), "native after capture"
        )
        ephemeral = _require_mapping(
            after.get("ephemeral"), "native after.ephemeral"
        )
        turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
        observation["dispatched_event"] = _require_int(
            turn.get("dispatched_event"), "native dispatched_event"
        )
        observation["rng"] = _rng_state(ephemeral.get("rng"), "native rng")
    return observation


def normalize_retail_nation_economy(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_trade_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    observation["toggle"] = _require_int(raw.get("toggle"), "retail toggle")
    if checkpoint_id.startswith("turn_state_"):
        observation["dispatched_event"] = _require_int(
            raw.get("dispatched_event"), "retail dispatched_event"
        )
        observation["rng"] = _rng_state(raw.get("rng"), "retail rng")
    return observation


_CITY_NATION_INT_FIELDS = ("treasury", "reserved_transport")

_CITY_NATION_ARRAY_FIELDS = (
    "pending_actions",
    "pending_payloads",
    "item_potentials",
    "transported_items",
    "purchased_items",
    "production_orders",
    "production_accum",
    "production_flags",
    "city_stocks",
)

_CITY_REGION_INT_FIELDS = (
    "region_id",
    "development_stage",
    "last_turn_tick",
    "city_score",
    "linked_tile",
    "linked_dev_class",
    "linked_edge0",
    "linked_edge1",
)


def _city_transport_nations(raw_nations: Any, label: str) -> list[Any]:
    if not isinstance(raw_nations, list):
        raise ValueError(f"{label} must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(raw_nations):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}[{slot}]")
        entry: dict[str, Any] = {
            field: _require_int(
                nation_map.get(field), f"{label}[{slot}].{field}"
            )
            for field in _CITY_NATION_INT_FIELDS
        }
        for field in _CITY_NATION_ARRAY_FIELDS:
            value = nation_map.get(field)
            entry[field] = (
                None
                if value is None
                else _require_int_list(value, f"{label}[{slot}].{field}")
            )
        nations.append(entry)
    return nations


def _city_transport_regions(raw_regions: Any, label: str) -> list[Any]:
    if not isinstance(raw_regions, list):
        raise ValueError(f"{label} must be an array")
    regions: list[Any] = []
    for index, region in enumerate(raw_regions):
        region_map = _require_mapping(region, f"{label}[{index}]")
        entry: dict[str, Any] = {}
        for field in _CITY_REGION_INT_FIELDS:
            value = region_map.get(field)
            entry[field] = (
                None
                if value is None
                else _require_int(value, f"{label}[{index}].{field}")
            )
        entry["dev_counts"] = _require_int_list(
            region_map.get("dev_counts"), f"{label}[{index}].dev_counts"
        )
        regions.append(entry)
    return regions


def _city_transport_ephemeral(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    return {
        "nations": _city_transport_nations(raw.get("nations"), f"{label}.nations"),
        "regions": _city_transport_regions(raw.get("regions"), f"{label}.regions"),
    }


def normalize_native_city_transport_phase(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native driver result to the stable city+transport schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    city_transport = _require_mapping(
        ephemeral.get("city_transport"), "native ephemeral city_transport"
    )
    return {
        "checkpoint_id": CHECKPOINT_CITY_TRANSPORT_PHASE,
        "action_id": ACTION_CITY_TRANSPORT_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "city_transport": _city_transport_ephemeral(
            city_transport, "native city_transport"
        ),
    }


def normalize_retail_city_transport_phase(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a retail GDB city+transport capture to the same schema."""
    return {
        "checkpoint_id": CHECKPOINT_CITY_TRANSPORT_PHASE,
        "action_id": ACTION_CITY_TRANSPORT_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "city_transport": _city_transport_ephemeral(
            _require_mapping(
                raw.get("city_transport"), "retail city_transport"
            ),
            "retail city_transport",
        ),
    }


_CIVILIAN_UNIT_INT_FIELDS = (
    "tile",
    "kind",
    "order",
    "target",
    "owner",
    "remaining_turns",
    "completion_marker",
)

_CIVILIAN_NATION_INT_FIELDS = ("treasury", "town_count", "home_tile")


def _civilians_ephemeral(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    units_raw = raw.get("units")
    if not isinstance(units_raw, list):
        raise ValueError(f"{label}.units must be an array")
    units: list[Any] = []
    for index, unit in enumerate(units_raw):
        unit_map = _require_mapping(unit, f"{label}.units[{index}]")
        units.append(
            {
                field: _require_int(
                    unit_map.get(field), f"{label}.units[{index}].{field}"
                )
                for field in _CIVILIAN_UNIT_INT_FIELDS
            }
        )
    nations_raw = raw.get("nations")
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label}.nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}.nations[{slot}]")
        entry: dict[str, Any] = {
            field: _require_int(
                nation_map.get(field), f"{label}.nations[{slot}].{field}"
            )
            for field in _CIVILIAN_NATION_INT_FIELDS
        }
        stocks = nation_map.get("city_stocks")
        entry["city_stocks"] = (
            None
            if stocks is None
            else _require_int_list(stocks, f"{label}.nations[{slot}].city_stocks")
        )
        order_counts = nation_map.get("order_counts")
        entry["order_counts"] = (
            None
            if order_counts is None
            else _require_int_list(
                order_counts, f"{label}.nations[{slot}].order_counts"
            )
        )
        towns_raw = nation_map.get("towns")
        if towns_raw is not None:
            if not isinstance(towns_raw, list):
                raise ValueError(
                    f"{label}.nations[{slot}].towns must be an array"
                )
            towns: list[Any] = []
            for town_index, town in enumerate(towns_raw):
                town_map = _require_mapping(
                    town, f"{label}.nations[{slot}].towns[{town_index}]"
                )
                towns.append(
                    {
                        "tile": _require_int(town_map.get("tile"), "town.tile"),
                        "owner": _require_int(
                            town_map.get("owner"), "town.owner"
                        ),
                        "yields": _require_int_list(
                            town_map.get("yields"), "town.yields"
                        ),
                        "transport_linked": _require_int(
                            town_map.get("transport_linked"),
                            "town.transport_linked",
                        ),
                        "enabled": _require_int(
                            town_map.get("enabled"), "town.enabled"
                        ),
                        "adjacent_city": _require_int(
                            town_map.get("adjacent_city"), "town.adjacent_city"
                        ),
                        "active": _require_int(
                            town_map.get("active"), "town.active"
                        ),
                    }
                )
            entry["towns"] = towns
        nations.append(entry)
    return {"units": units, "nations": nations}


def normalize_native_civilians_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_CIVILIANS_PHASE,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable civilians-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    civilians = _require_mapping(
        ephemeral.get("civilians"), "native ephemeral civilians"
    )
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_CIVILIANS_PHASE,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "civilians": _civilians_ephemeral(civilians, "native civilians"),
    }


def normalize_retail_civilians_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_CIVILIANS_PHASE,
) -> dict[str, Any]:
    """Reduce a retail GDB civilians capture to the same schema."""
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_CIVILIANS_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "civilians": _civilians_ephemeral(
            _require_mapping(raw.get("civilians"), "retail civilians"),
            "retail civilians",
        ),
    }


_MILITARY_UNIT_INT_FIELDS = (
    "kind",
    "tile",
    "order",
    "target",
    "owner",
    "strength",
    "experience",
    "battle_flags",
)

_MILITARY_SHIP_INT_FIELDS = (
    "type",
    "nation",
    "strength",
    "experience",
    "zone",
)

_MILITARY_TASK_FORCE_INT_FIELDS = (
    "nation",
    "aggression",
    "ship_orders",
    "zone",
    "child_count",
)


def _military_ephemeral(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    nations_raw = raw.get("nations")
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label}.nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}.nations[{slot}]")
        units_raw = nation_map.get("units")
        if not isinstance(units_raw, list):
            raise ValueError(f"{label}.nations[{slot}].units must be an array")
        units: list[Any] = []
        for index, unit in enumerate(units_raw):
            unit_map = _require_mapping(
                unit, f"{label}.nations[{slot}].units[{index}]"
            )
            units.append(
                {
                    field: _require_int(
                        unit_map.get(field),
                        f"{label}.nations[{slot}].units[{index}].{field}",
                    )
                    for field in _MILITARY_UNIT_INT_FIELDS
                }
            )
        nations.append(
            {
                "treasury": _require_int(
                    nation_map.get("treasury"),
                    f"{label}.nations[{slot}].treasury",
                ),
                "military_expenses": _require_int(
                    nation_map.get("military_expenses"),
                    f"{label}.nations[{slot}].military_expenses",
                ),
                "units": units,
            }
        )
    ships_raw = raw.get("ships")
    if not isinstance(ships_raw, list):
        raise ValueError(f"{label}.ships must be an array")
    ships: list[Any] = []
    for index, ship in enumerate(ships_raw):
        ship_map = _require_mapping(ship, f"{label}.ships[{index}]")
        ships.append(
            {
                field: _require_int(
                    ship_map.get(field), f"{label}.ships[{index}].{field}"
                )
                for field in _MILITARY_SHIP_INT_FIELDS
            }
        )
    forces_raw = raw.get("task_forces")
    if not isinstance(forces_raw, list):
        raise ValueError(f"{label}.task_forces must be an array")
    task_forces: list[Any] = []
    for index, force in enumerate(forces_raw):
        force_map = _require_mapping(force, f"{label}.task_forces[{index}]")
        task_forces.append(
            {
                field: _require_int(
                    force_map.get(field),
                    f"{label}.task_forces[{index}].{field}",
                )
                for field in _MILITARY_TASK_FORCE_INT_FIELDS
            }
            | {
                "defeated": _require_bool(
                    force_map.get("defeated"),
                    f"{label}.task_forces[{index}].defeated",
                )
            }
        )
    normalized = {
        "nations": nations,
        "ships": ships,
        "task_forces": task_forces,
    }
    owners_raw = raw.get("province_owners")
    if owners_raw is not None:
        if not isinstance(owners_raw, list):
            raise ValueError(f"{label}.province_owners must be an array")
        normalized["province_owners"] = [
            _require_int(owner, f"{label}.province_owners[{index}]")
            for index, owner in enumerate(owners_raw)
        ]
    battle_raw = raw.get("land_battle")
    if battle_raw is not None:
        battle_map = _require_mapping(battle_raw, f"{label}.land_battle")
        created = battle_map.get("created")
        if not isinstance(created, bool):
            raise ValueError(f"{label}.land_battle.created must be a boolean")
        normalized["land_battle"] = {
            "created": created,
            "outcome": _require_int(
                battle_map.get("outcome"), f"{label}.land_battle.outcome"
            ),
        }
    return normalized


def normalize_native_military_phase(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_MILITARY_PHASE,
    action_id: str = ACTION_MILITARY_PHASE,
    include_rng: bool = False,
) -> dict[str, Any]:
    """Reduce a native driver result to the stable military-phase schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    military = _require_mapping(
        ephemeral.get("military"), "native ephemeral military"
    )
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": action_id,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "military": _military_ephemeral(military, "native military"),
    }
    if include_rng:
        observation["dispatched_event"] = _require_int(
            turn.get("dispatched_event"), "native dispatched_event"
        )
        observation["rng"] = _rng_state(ephemeral.get("rng"), "native rng")
    return observation


def normalize_retail_military_phase(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_MILITARY_PHASE,
    action_id: str = ACTION_MILITARY_PHASE,
    include_rng: bool = False,
) -> dict[str, Any]:
    """Reduce a retail GDB military capture to the same schema."""
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": action_id,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "military": _military_ephemeral(
            _require_mapping(raw.get("military"), "retail military"),
            "retail military",
        ),
    }
    if include_rng:
        observation["dispatched_event"] = _require_int(
            raw.get("dispatched_event"), "retail dispatched_event"
        )
        observation["rng"] = _rng_state(raw.get("rng"), "retail rng")
    return observation


def _strategic_naval_matrix_side(
    raw: Any, label: str
) -> dict[str, Any]:
    side = _require_mapping(raw, label)
    ships_raw = side.get("ships")
    if not isinstance(ships_raw, list):
        raise ValueError(f"{label}.ships must be an array")
    ships = []
    for index, ship_raw in enumerate(ships_raw):
        ship = _require_mapping(ship_raw, f"{label}.ships[{index}]")
        alive = _require_bool(ship.get("alive"), f"{label}.ships[{index}].alive")
        strength = ship.get("strength")
        experience = ship.get("experience")
        if alive:
            strength = _require_int(strength, f"{label}.ships[{index}].strength")
            experience = _require_int(
                experience, f"{label}.ships[{index}].experience"
            )
        elif strength is not None or experience is not None:
            raise ValueError(f"{label}.ships[{index}] dead state must be null")
        ships.append(
            {
                "type": _require_int(
                    ship.get("type"), f"{label}.ships[{index}].type"
                ),
                "alive": alive,
                "strength": strength,
                "experience": experience,
            }
        )
    admiral_experience = side.get("admiral_experience")
    if admiral_experience is not None:
        admiral_experience = _require_int(
            admiral_experience, f"{label}.admiral_experience"
        )
    return {
        "aggression": _require_int(side.get("aggression"), f"{label}.aggression"),
        "initial_strength": _require_int(
            side.get("initial_strength"), f"{label}.initial_strength"
        ),
        "initial_experience": _require_int(
            side.get("initial_experience"), f"{label}.initial_experience"
        ),
        "initial_admiral_experience": _require_int(
            side.get("initial_admiral_experience"),
            f"{label}.initial_admiral_experience",
        ),
        "defeated": _require_bool(side.get("defeated"), f"{label}.defeated"),
        "admiral_experience": admiral_experience,
        "ships": ships,
    }


def _normalize_strategic_naval_battle_matrix(
    raw: Mapping[str, Any], label: str
) -> dict[str, Any]:
    cases_raw = raw.get("cases")
    if not isinstance(cases_raw, list) or len(cases_raw) != 20:
        raise ValueError(f"{label}.cases must contain 20 matrix rows")
    cases = []
    seen = set()
    for index, case_raw in enumerate(cases_raw):
        case = _require_mapping(case_raw, f"{label}.cases[{index}]")
        name = case.get("case")
        convergence = case.get("convergence")
        resolution = case.get("resolution")
        winner = case.get("winner")
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError(f"{label}.cases[{index}].case must be unique")
        seen.add(name)
        if convergence not in {
            "only_left_fails",
            "only_right_fails",
            "both_fail",
            "neither_fails",
        }:
            raise ValueError(f"{label}.cases[{index}].convergence is invalid")
        if resolution not in {
            "tier_exhaustion",
            "left_eliminated",
            "right_eliminated",
            "both_eliminated",
        }:
            raise ValueError(f"{label}.cases[{index}].resolution is invalid")
        if winner not in {"left", "right", "draw"}:
            raise ValueError(f"{label}.cases[{index}].winner is invalid")
        left = _strategic_naval_matrix_side(
            case.get("left"), f"{label}.cases[{index}].left"
        )
        right = _strategic_naval_matrix_side(
            case.get("right"), f"{label}.cases[{index}].right"
        )
        left_defeated = _require_bool(
            case.get("left_defeated"),
            f"{label}.cases[{index}].left_defeated",
        )
        right_defeated = _require_bool(
            case.get("right_defeated"),
            f"{label}.cases[{index}].right_defeated",
        )
        if left_defeated != left["defeated"] or right_defeated != right["defeated"]:
            raise ValueError(f"{label}.cases[{index}] defeated state is inconsistent")
        cases.append(
            {
                "case": name,
                "seed": _require_int(
                    case.get("seed"), f"{label}.cases[{index}].seed"
                ),
                "convergence": convergence,
                "resolution": resolution,
                "participant": _require_int(
                    case.get("participant"),
                    f"{label}.cases[{index}].participant",
                ),
                "winner": winner,
                "left_defeated": left_defeated,
                "right_defeated": right_defeated,
                "left": left,
                "right": right,
            }
        )
    return {
        "checkpoint_id": CHECKPOINT_STRATEGIC_NAVAL_BATTLE_MATRIX,
        "action_id": ACTION_STRATEGIC_NAVAL_BATTLE_MATRIX,
        "cases": cases,
    }


def normalize_native_strategic_naval_battle_matrix(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    return _normalize_strategic_naval_battle_matrix(
        _require_mapping(captures.get("result"), "native result"),
        "native",
    )


def normalize_retail_strategic_naval_battle_matrix(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    return _normalize_strategic_naval_battle_matrix(raw, "retail")


def normalize_native_province_loss(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native province-loss result: turn + military + civilians."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": "province_loss_with_stationed_unit.resolved",
        "action_id": "province_loss_with_stationed_unit.run",
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native flags"
            ),
        },
        "military": _military_ephemeral(
            _require_mapping(
                ephemeral.get("military"), "native ephemeral military"
            ),
            "native military",
        ),
        "civilians": _civilians_ephemeral(
            _require_mapping(
                ephemeral.get("civilians"), "native ephemeral civilians"
            ),
            "native civilians",
        ),
    }


def normalize_retail_province_loss(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a retail GDB province-loss capture to the same schema."""
    return {
        "checkpoint_id": "province_loss_with_stationed_unit.resolved",
        "action_id": "province_loss_with_stationed_unit.run",
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail flags"
            ),
        },
        "military": _military_ephemeral(
            _require_mapping(raw.get("military"), "retail military"),
            "retail military",
        ),
        "civilians": _civilians_ephemeral(
            _require_mapping(raw.get("civilians"), "retail civilians"),
            "retail civilians",
        ),
    }


def normalize_native_province_ocean(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native ocean-context result: turn + province owners + missions."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    military = _require_mapping(
        ephemeral.get("military"), "native ephemeral military"
    )
    owners_raw = military.get("province_owners")
    if not isinstance(owners_raw, list):
        raise ValueError("native military.province_owners must be an array")
    return {
        "checkpoint_id": "province_owner_ocean_context.resolved",
        "action_id": "province_owner_ocean_context.run",
        "turn": _mission_turn(turn, "native turn"),
        "province_owners": [
            _require_int(owner, f"native province_owners[{index}]")
            for index, owner in enumerate(owners_raw)
        ],
        "missions": _mission_records(
            ephemeral.get("missions"), "native missions"
        ),
    }


def normalize_retail_province_ocean(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a retail GDB ocean-context capture to the same schema."""
    military = _require_mapping(raw.get("military"), "retail military")
    owners_raw = military.get("province_owners")
    if not isinstance(owners_raw, list):
        raise ValueError("retail military.province_owners must be an array")
    return {
        "checkpoint_id": "province_owner_ocean_context.resolved",
        "action_id": "province_owner_ocean_context.run",
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail flags"
            ),
        },
        "province_owners": [
            _require_int(owner, f"retail province_owners[{index}]")
            for index, owner in enumerate(owners_raw)
        ],
        "missions": _mission_records(raw.get("missions"), "retail missions"),
    }


_TILE_RECORD_FIELDS = (
    "tile",
    "owner",
    "adjacency",
    "dev_nibbles",
    "pending",
    "rail_flags",
    "active_flags",
    "province",
)


def _tile_records(raw: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    records = []
    for index, entry in enumerate(raw):
        record = _require_mapping(entry, f"{label}[{index}]")
        records.append(
            {
                field: _require_int(
                    record.get(field), f"{label}[{index}].{field}"
                )
                for field in _TILE_RECORD_FIELDS
            }
        )
    return records


def normalize_native_development(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Civilians schema plus the touched-tile terrain fields the case emits."""
    observation = normalize_native_civilians_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    payload = _native_captures(result).get("result")
    tiles = payload.get("tiles") if isinstance(payload, Mapping) else []
    observation["tiles"] = _tile_records(tiles, "native result.tiles")
    return observation


def normalize_retail_development(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail GDB development capture to the same schema."""
    observation = normalize_retail_civilians_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    observation["tiles"] = _tile_records(
        raw.get("tiles"), "retail tiles"
    )
    return observation


def _province_record(raw: Any, label: str) -> dict[str, Any]:
    record = _require_mapping(raw, label)
    return {
        "province": _require_int(record.get("province"), f"{label}.province"),
        "owner": _require_int(record.get("owner"), f"{label}.owner"),
        "dev_stage": _require_int(
            record.get("dev_stage"), f"{label}.dev_stage"
        ),
        "last_turn": _require_int(
            record.get("last_turn"), f"{label}.last_turn"
        ),
        "dev_counts": _require_int_list(
            record.get("dev_counts"), f"{label}.dev_counts"
        ),
    }


def normalize_native_yield_rebuild(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Trade-phase nation state plus civilians (towns carry the rebuilt
    resourceYieldByType rows) and the optional provinces payload."""
    observation = normalize_native_trade_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    observation["civilians"] = _civilians_ephemeral(
        _require_mapping(
            ephemeral.get("civilians"), "native ephemeral civilians"
        ),
        "native civilians",
    )
    payload = captures.get("result")
    if isinstance(payload, Mapping) and payload.get("provinces") is not None:
        observation["provinces"] = _province_record(
            payload.get("provinces"), "native result.provinces"
        )
    return observation


def normalize_retail_yield_rebuild(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail GDB yield-rebuild capture to the same schema."""
    observation = normalize_retail_trade_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    observation["civilians"] = _civilians_ephemeral(
        _require_mapping(raw.get("civilians"), "retail civilians"),
        "retail civilians",
    )
    if raw.get("provinces") is not None:
        observation["provinces"] = _province_record(
            raw.get("provinces"), "retail provinces"
        )
    return observation


def normalize_native_specialist_recruitment(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Civilians schema for the specialist TUnitOrder::Produce path."""
    observation = normalize_native_civilians_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_retail_specialist_recruitment(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_civilians_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_native_growth(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Military schema for the DoCityAndTransport growth paths."""
    observation = normalize_native_military_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_retail_growth(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_military_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_native_advisory(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Mission schema for the advisory case-16 queueing path."""
    observation = normalize_native_reassess_missions(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_retail_advisory(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_reassess_missions(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_native_opening(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Civilians schema for the opening grant/home-city setup paths."""
    observation = normalize_native_civilians_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


def normalize_retail_opening(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_civilians_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    return observation


_PENDING_NATION_ARRAY_FIELDS = ("pending_actions", "pending_payloads")


def _pending_status_nations(raw: Any, label: str) -> list[Any]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label}[{slot}]")
        nations.append(
            {
                field: _require_int_list(
                    nation_map.get(field), f"{label}[{slot}].{field}"
                )
                for field in _PENDING_NATION_ARRAY_FIELDS
            }
        )
    return nations


def _turn_fields_from_native(ephemeral: Mapping[str, Any]) -> dict[str, int]:
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "phase": _require_int(turn.get("phase"), "native turn.phase"),
        "active": _require_int(turn.get("active_nation"), "native active_nation"),
        "economic_turn": _require_int(
            turn.get("economic_turn"), "native economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
        ),
    }


def _turn_fields_from_retail(raw: Mapping[str, Any]) -> dict[str, int]:
    return {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }


def normalize_native_pending_status(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Per-nation pending-action status/payload rows for the pending sweep."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    city_transport = _require_mapping(
        ephemeral.get("city_transport"), "native ephemeral city_transport"
    )
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _turn_fields_from_native(ephemeral),
        "pending_nations": _pending_status_nations(
            city_transport.get("nations"), "native pending_nations"
        ),
    }


def normalize_retail_pending_status(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _turn_fields_from_retail(raw),
        "pending_nations": _pending_status_nations(
            raw.get("pending_nations"), "retail pending_nations"
        ),
    }


def _news_story(raw: Any, label: str) -> dict[str, Any]:
    story = _require_mapping(raw, label)
    arguments = story.get("arguments")
    if not isinstance(arguments, list):
        raise ValueError(f"{label}.arguments must be an array")
    return {
        "template_index": _require_int(
            story.get("template_index"), f"{label}.template_index"
        ),
        "story_id": _require_int(story.get("story_id"), f"{label}.story_id"),
        "feature": bool(story.get("feature")),
        "arguments": [
            _require_mapping(argument, f"{label}.arguments[{index}]")
            for index, argument in enumerate(arguments)
        ],
    }


def _news_state(raw: Any, label: str) -> dict[str, Any]:
    news = _require_mapping(raw, label)
    pages_raw = news.get("pages")
    if not isinstance(pages_raw, list) or len(pages_raw) != 7:
        raise ValueError(f"{label}.pages must be a seven-nation array")
    pages: list[Any] = []
    for slot, page in enumerate(pages_raw):
        if page is None:
            pages.append(None)
            continue
        page_map = _require_mapping(page, f"{label}.pages[{slot}]")
        columns_raw = page_map.get("stories")
        if not isinstance(columns_raw, list) or len(columns_raw) != 3:
            raise ValueError(f"{label}.pages[{slot}].stories must be 3 columns")
        columns: list[Any] = []
        for column_index, column in enumerate(columns_raw):
            if not isinstance(column, list) or len(column) != 3:
                raise ValueError(
                    f"{label}.pages[{slot}].stories[{column_index}]"
                    " must be 3 rows"
                )
            columns.append(
                [
                    None
                    if story is None
                    else _news_story(
                        story,
                        f"{label}.pages[{slot}].stories[{column_index}]",
                    )
                    for story in column
                ]
            )
        pages.append({"stories": columns})
    last_used_raw = news.get("last_used_turn_by_nation_and_template")
    if not isinstance(last_used_raw, list) or len(last_used_raw) != 7:
        raise ValueError(
            f"{label}.last_used_turn_by_nation_and_template must be 7 rows"
        )
    return {
        "pages": pages,
        "last_used_turn_by_nation_and_template": [
            _require_int_list(row, f"{label}.last_used[{index}]")
            for index, row in enumerate(last_used_raw)
        ],
    }


def _news_events(raw: Any, label: str) -> list[Any]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    return [
        _require_mapping(event, f"{label}[{index}]")
        for index, event in enumerate(raw)
    ]


def _rng_state(raw: Any, label: str) -> dict[str, int]:
    rng = _require_mapping(raw, label)
    return {
        "crt_rand": _require_int(rng.get("crt_rand"), f"{label}.crt_rand"),
        "map_generation": _require_int(
            rng.get("map_generation"), f"{label}.map_generation"
        ),
        "zone_status": _require_int(
            rng.get("zone_status"), f"{label}.zone_status"
        ),
    }


def normalize_native_news(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Newspaper pages, template last-used ticks, and the shared event queue."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    pending = _require_mapping(
        ephemeral.get("pending"), "native ephemeral pending"
    )
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _turn_fields_from_native(ephemeral),
        "news": _news_state(ephemeral.get("news"), "native news"),
        "newspaper_events": _news_events(
            pending.get("newspaper_events"), "native newspaper_events"
        ),
    }
    if checkpoint_id == "turn_stop_newspaper.resolved":
        turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
        city_transport = _require_mapping(
            ephemeral.get("city_transport"), "native ephemeral city_transport"
        )
        observation["dispatched_event"] = _require_int(
            turn.get("dispatched_event"), "native dispatched_event"
        )
        observation["pending_nations"] = _pending_status_nations(
            city_transport.get("pending_nations"), "native pending_nations"
        )
        observation["rng"] = _rng_state(ephemeral.get("rng"), "native rng")
    return observation


def normalize_retail_news(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _turn_fields_from_retail(raw),
        "news": _news_state(raw.get("news"), "retail news"),
        "newspaper_events": _news_events(
            raw.get("newspaper_events"), "retail newspaper_events"
        ),
    }
    if checkpoint_id == "turn_stop_newspaper.resolved":
        observation["dispatched_event"] = _require_int(
            raw.get("dispatched_event"), "retail dispatched_event"
        )
        observation["pending_nations"] = _pending_status_nations(
            raw.get("pending_nations"), "retail pending_nations"
        )
        observation["rng"] = _rng_state(raw.get("rng"), "retail rng")
    return observation


def normalize_native_army_ui(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Military schema plus the case's result payload (cursor/selection state)."""
    observation = normalize_native_military_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    captures = _native_captures(result)
    observation["result"] = _require_mapping(
        captures.get("result"), "native result capture"
    )
    return observation


def normalize_retail_army_ui(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_military_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    observation["result"] = _require_mapping(
        raw.get("result"), "retail result"
    )
    return observation


def _normalize_navy_ui_result(
    value: Any, label: str
) -> Any:
    if isinstance(value, Mapping):
        return {
            key: (
                [
                    _require_int(entry, f"{label}.{key}[{index}]")
                    for index, entry in enumerate(item)
                ]
                if isinstance(item, list)
                else (
                    item
                    if isinstance(item, bool)
                    else _require_int(item, f"{label}.{key}")
                )
            )
            for key, item in value.items()
        }
    if value is None or isinstance(value, bool):
        return value
    return _require_int(value, label)


def normalize_native_navy_ui(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Military schema plus the case's result payload (scalar or object)."""
    observation = normalize_native_military_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    captures = _native_captures(result)
    observation["result"] = _normalize_navy_ui_result(
        captures.get("result"), "native result"
    )
    return observation


def normalize_retail_navy_ui(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_military_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    observation["result"] = _normalize_navy_ui_result(
        raw.get("result"), "retail result"
    )
    return observation


def _battle_snapshot_fields(
    payload: Mapping[str, Any], label: str
) -> dict[str, Any]:
    snapshots = payload.get("snapshots")
    if not isinstance(snapshots, list):
        raise ValueError(f"{label}.snapshots must be an array")
    fields: dict[str, Any] = {"snapshots": snapshots}
    for key in ("targets", "actuals"):
        values = payload.get(key)
        if values is not None:
            if not isinstance(values, list):
                raise ValueError(f"{label}.{key} must be an array")
            fields[key] = [
                _require_int(entry, f"{label}.{key}[{index}]")
                for index, entry in enumerate(values)
            ]
    return fields


def normalize_native_battle_snapshots(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Done/move/retreat cases: turn state plus the result payload's
    tactical snapshots (and move targets/actuals)."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    payload = _require_mapping(captures.get("result"), "native result capture")
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
    }
    observation.update(
        _battle_snapshot_fields(payload, "native result")
    )
    return observation


def normalize_retail_battle_snapshots(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
    }
    observation.update(_battle_snapshot_fields(raw, "retail"))
    return observation


_ITEM_ORDER_RESULT_FIELDS = (
    "applied",
    "quantity",
    "requested",
    "fabric_tracking",
)


def normalize_native_city_item_order(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Civilians schema plus the order-slot fields the case emits."""
    observation = normalize_native_civilians_phase(result, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    payload = _require_mapping(
        _native_captures(result).get("result"), "native result capture"
    )
    for field in _ITEM_ORDER_RESULT_FIELDS:
        observation[field] = _require_int(
            payload.get(field), f"native result.{field}"
        )
    return observation


def normalize_retail_city_item_order(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    observation = normalize_retail_civilians_phase(raw, checkpoint_id)
    observation["action_id"] = checkpoint_id.replace(".resolved", ".run")
    for field in _ITEM_ORDER_RESULT_FIELDS:
        observation[field] = _require_int(raw.get(field), f"retail {field}")
    return observation


_MILITARY_CLEANUP_METRIC_KEYS = (
    "queue_divergence",
    "mobile_score",
    "mobile_divergence",
    "combined_divergence",
    "weighted_military",
    "expansion_pressure",
    "unit_divergence",
    "mission_pressure",
)


def _military_cleanup_ephemeral(raw: Any, label: str) -> dict[str, Any]:
    mapping = _require_mapping(raw, label)
    normalized = {
        "region_scores": _require_int_list(
            mapping.get("region_scores"), f"{label}.region_scores"
        ),
        "city_score_total": _require_int(
            mapping.get("city_score_total"), f"{label}.city_score_total"
        ),
    }
    for key in _MILITARY_CLEANUP_METRIC_KEYS:
        normalized[key] = _require_int_list(
            mapping.get(key), f"{label}.{key}"
        )
    return normalized


def normalize_native_military_cleanup(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
    action_id: str = ACTION_MILITARY_CLEANUP,
    include_rng: bool = False,
) -> dict[str, Any]:
    """Reduce a native driver result to the military-cleanup schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    cleanup = _require_mapping(
        ephemeral.get("military_cleanup"), "native ephemeral military_cleanup"
    )
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": action_id,
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "military_cleanup": _military_cleanup_ephemeral(
            cleanup, "native military_cleanup"
        ),
    }
    if include_rng:
        observation["dispatched_event"] = _require_int(
            turn.get("dispatched_event"), "native dispatched_event"
        )
        observation["rng"] = _rng_state(ephemeral.get("rng"), "native rng")
    return observation


def normalize_retail_military_cleanup(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_SECOND_TURN_MILITARY_CLEANUP,
    action_id: str = ACTION_MILITARY_CLEANUP,
    include_rng: bool = False,
) -> dict[str, Any]:
    """Reduce a retail GDB military-cleanup capture to the same schema."""
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": action_id,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(raw.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
            ),
        },
        "military_cleanup": _military_cleanup_ephemeral(
            _require_mapping(raw.get("military_cleanup"), "retail military_cleanup"),
            "retail military_cleanup",
        ),
    }
    if include_rng:
        observation["dispatched_event"] = _require_int(
            raw.get("dispatched_event"), "retail dispatched_event"
        )
        observation["rng"] = _rng_state(raw.get("rng"), "retail rng")
    return observation


def normalize_native_turn_state_military_cleanup(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    observation = normalize_native_military_cleanup(
        result,
        checkpoint_id=CHECKPOINT_TURN_STATE_MILITARY_CLEANUP,
        action_id=ACTION_TURN_STATE_MILITARY_CLEANUP,
        include_rng=True,
    )
    observation["trade"] = normalize_native_trade_phase(
        result, CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
    )["trade"]
    observation["diplomacy"] = normalize_native_player_diplomacy_policy(
        result, CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
    )["diplomacy"]
    observation["missions"] = normalize_native_reassess_missions(
        result, CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
    )["missions"]
    return observation


def normalize_retail_turn_state_military_cleanup(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    observation = normalize_retail_military_cleanup(
        raw,
        checkpoint_id=CHECKPOINT_TURN_STATE_MILITARY_CLEANUP,
        action_id=ACTION_TURN_STATE_MILITARY_CLEANUP,
        include_rng=True,
    )
    observation["trade"] = normalize_retail_trade_phase(
        raw, CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
    )["trade"]
    observation["diplomacy"] = normalize_retail_player_diplomacy_policy(
        raw, CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
    )["diplomacy"]
    observation["missions"] = normalize_retail_reassess_missions(
        raw, CHECKPOINT_TURN_STATE_MILITARY_CLEANUP
    )["missions"]
    return observation


def _diplomacy_records(records: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} must be an array")
    normalized = []
    for index, record in enumerate(records):
        record_map = _require_mapping(record, f"{label}[{index}]")
        normalized.append(
            {
                "code": record_map.get("code"),
                "source": _require_int(
                    record_map.get("source"), f"{label}[{index}].source"
                ),
            }
        )
    return normalized


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _require_number(value: Any, label: str) -> "int | float":
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    return value


def _require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _require_int_list(value: Any, label: str) -> list[int]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in value
    ):
        raise ValueError(f"{label} must be an integer array")
    return value


_TURN_STATE_STOP_NAMES = {
    0x0E: "deal_book",
    0x12: "newspaper",
    0x05: "player_orders",
}


def normalize_native_second_turn_sequence(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native second-turn state-machine walk to its stop sequence."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    stops_raw = transition_result.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("native result stops must be an array")
    stops: list[str] = []
    for index, stop in enumerate(stops_raw):
        if not isinstance(stop, str):
            raise ValueError(f"native result stops[{index}] must be a string")
        stops.append(stop)
    return {
        "checkpoint_id": CHECKPOINT_SECOND_TURN_SEQUENCE,
        "action_id": ACTION_SECOND_TURN_SEQUENCE,
        "stops": stops,
        "economic_turn": _require_int(
            transition_result.get("economic_turn"), "native economic_turn"
        ),
    }


def normalize_native_consecutive_turn_sequence(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native 12-turn state-machine walk to stops + turn numbers."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    stops_raw = transition_result.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("native result stops must be an array")
    stops: list[str] = []
    for index, stop in enumerate(stops_raw):
        if not isinstance(stop, str):
            raise ValueError(f"native result stops[{index}] must be a string")
        stops.append(stop)
    return {
        "checkpoint_id": CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        "action_id": ACTION_CONSECUTIVE_TURN_SEQUENCE,
        "stops": stops,
        "economic_turns": _require_int_list(
            transition_result.get("economic_turns"), "native economic_turns"
        ),
    }


def normalize_retail_consecutive_turn_sequence(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail 12-turn state-machine walk to the same schema."""
    stops_raw = raw.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("retail stops must be an array")
    stops = []
    for index, code in enumerate(stops_raw):
        code = _require_int(code, f"retail stops[{index}]")
        name = _TURN_STATE_STOP_NAMES.get(code)
        if name is None:
            raise ValueError(f"retail stops[{index}] unknown state {code:#x}")
        stops.append(name)
    return {
        "checkpoint_id": CHECKPOINT_CONSECUTIVE_TURN_SEQUENCE,
        "action_id": ACTION_CONSECUTIVE_TURN_SEQUENCE,
        "stops": stops,
        "economic_turns": _require_int_list(
            raw.get("economic_turns"), "retail economic_turns"
        ),
    }


def normalize_native_recompute_metrics(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native metric case result payload to its float-bit arrays."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    normalized: dict[str, Any] = {
        "checkpoint_id": CHECKPOINT_RECOMPUTE_METRICS,
        "action_id": ACTION_RECOMPUTE_METRICS,
    }
    for key in _MILITARY_CLEANUP_METRIC_KEYS:
        normalized[key] = _require_int_list(
            transition_result.get(key), f"native result {key}"
        )
    return normalized


def normalize_retail_recompute_metrics(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail metric capture to the same float-bit arrays."""
    normalized = {
        "checkpoint_id": CHECKPOINT_RECOMPUTE_METRICS,
        "action_id": ACTION_RECOMPUTE_METRICS,
    }
    for key in _MILITARY_CLEANUP_METRIC_KEYS:
        normalized[key] = _require_int_list(raw.get(key), f"retail {key}")
    return normalized


def _mission_records(records: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{label} must be an array")
    normalized = []
    for index, record in enumerate(records):
        entry = _require_mapping(record, f"{label}[{index}]")
        mission = {
            "nation": _require_int(entry.get("nation"), f"{label}[{index}].nation"),
            "kind": entry.get("kind"),
            "nation_id": _require_int(
                entry.get("nation_id"), f"{label}[{index}].nation_id"
            ),
            "path_marker": _require_int(
                entry.get("path_marker"), f"{label}[{index}].path_marker"
            ),
            "state": _require_int(entry.get("state"), f"{label}[{index}].state"),
            "importance_bits": _require_int(
                entry.get("importance_bits"), f"{label}[{index}].importance_bits"
            ),
            "flag10": _require_int(
                entry.get("flag10"), f"{label}[{index}].flag10"
            ),
            "marker": _require_int(
                entry.get("marker"), f"{label}[{index}].marker"
            ),
        }
        if entry.get("navy_state") is not None:
            mission["target_zone"] = _require_int(
                entry.get("target_zone"), f"{label}[{index}].target_zone"
            )
            mission["resolved_port_zone"] = _require_int(
                entry.get("resolved_port_zone"),
                f"{label}[{index}].resolved_port_zone",
            )
            mission["navy_state"] = _require_int(
                entry.get("navy_state"), f"{label}[{index}].navy_state"
            )
            mission["has_orders"] = _require_bool(
                entry.get("has_orders"), f"{label}[{index}].has_orders"
            )
            mission["required_equipage_bits"] = _require_int_list(
                entry.get("required_equipage_bits"),
                f"{label}[{index}].required_equipage_bits",
            )
        normalized.append(mission)
    return normalized


def _mission_turn(raw: Mapping[str, Any], label: str) -> dict[str, Any]:
    return {
        "phase": _require_int(raw.get("phase"), f"{label}.phase"),
        "active": _require_int(
            raw.get("active_nation", raw.get("active")), f"{label}.active"
        ),
        "economic_turn": _require_int(
            raw.get("economic_turn"), f"{label}.economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), f"{label}.turn_flow_status_flags"
        ),
    }


def normalize_native_reassess_missions(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_REASSESS_MISSIONS,
) -> dict[str, Any]:
    """Reduce a native driver result to the mission-reassess schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_REASSESS_MISSIONS,
        "turn": _mission_turn(turn, "native turn"),
        "missions": _mission_records(
            ephemeral.get("missions"), "native missions"
        ),
    }


def normalize_retail_reassess_missions(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_REASSESS_MISSIONS,
) -> dict[str, Any]:
    """Reduce a retail GDB mission capture to the same schema."""
    turn = {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": ACTION_REASSESS_MISSIONS,
        "turn": turn,
        "missions": _mission_records(raw.get("missions"), "retail missions"),
    }


def _development_records(raw: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    records = []
    for index, entry in enumerate(raw):
        entry = _require_mapping(entry, f"{label}[{index}]")
        records.append(
            {
                "nation": _require_int(
                    entry.get("nation"), f"{label}[{index}].nation"
                ),
                "order_ba": _require_int_list(
                    entry.get("order_ba"), f"{label}[{index}].order_ba"
                ),
                "order_dc": _require_int_list(
                    entry.get("order_dc"), f"{label}[{index}].order_dc"
                ),
                "queued_orders": _require_int_list(
                    entry.get("queued_orders"),
                    f"{label}[{index}].queued_orders",
                ),
            }
        )
    return records


def normalize_native_ai_naval_development(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a native driver result to the AI-development schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        "action_id": ACTION_AI_NAVAL_DEVELOPMENT,
        "turn": _mission_turn(turn, "native turn"),
        "missions": _mission_records(
            ephemeral.get("missions"), "native missions"
        ),
        "development": _development_records(
            ephemeral.get("development"), "native development"
        ),
    }


def normalize_retail_ai_naval_development(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a retail GDB AI-development capture to the same schema."""
    turn = {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }
    return {
        "checkpoint_id": CHECKPOINT_AI_NAVAL_DEVELOPMENT,
        "action_id": ACTION_AI_NAVAL_DEVELOPMENT,
        "turn": turn,
        "missions": _mission_records(raw.get("missions"), "retail missions"),
        "development": _development_records(
            raw.get("development"), "retail development"
        ),
    }


def _upgrade_ship_records(raw: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    records = []
    for index, ship in enumerate(raw):
        ship_map = _require_mapping(ship, f"{label}[{index}]")
        records.append(
            {
                field: _require_int(
                    ship_map.get(field), f"{label}[{index}].{field}"
                )
                for field in ("nation", "type", "strength", "experience")
            }
        )
    return records


def _technology_record(raw: Any, label: str) -> dict[str, Any]:
    entry = _require_mapping(raw, label)
    nations_raw = entry.get("nations")
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label}.nations must be an array")
    nations = []
    for index, nation in enumerate(nations_raw):
        nation = _require_mapping(nation, f"{label}.nations[{index}]")
        nations.append(
            {
                "nation": _require_int(
                    nation.get("nation"), f"{label}.nations[{index}].nation"
                ),
                "treasury": _require_int(
                    nation.get("treasury"),
                    f"{label}.nations[{index}].treasury",
                ),
                "tech_status": _require_int_list(
                    nation.get("tech_status"),
                    f"{label}.nations[{index}].tech_status",
                ),
                "completion_years": _require_int_list(
                    nation.get("completion_years"),
                    f"{label}.nations[{index}].completion_years",
                ),
                "abilities": _require_int_list(
                    nation.get("abilities"),
                    f"{label}.nations[{index}].abilities",
                ),
                "university": _require_int_list(
                    nation.get("university"),
                    f"{label}.nations[{index}].university",
                ),
            }
        )
    result = {
        "marker": _require_int(entry.get("marker"), f"{label}.marker"),
        "prereq_primary": _require_int(
            entry.get("prereq_primary"), f"{label}.prereq_primary"
        ),
        "prereq_secondary": _require_int(
            entry.get("prereq_secondary"), f"{label}.prereq_secondary"
        ),
        "selector": _require_int(entry.get("selector"), f"{label}.selector"),
        "zone_index": _require_int(
            entry.get("zone_index"), f"{label}.zone_index"
        ),
        "unlock_flags": _require_int_list(
            entry.get("unlock_flags"), f"{label}.unlock_flags"
        ),
        "enabled_types": _require_int_list(
            entry.get("enabled_types"), f"{label}.enabled_types"
        ),
        "nations": nations,
    }
    cap_b_raw = entry.get("cap_b_selected")
    if not isinstance(cap_b_raw, list):
        raise ValueError(f"{label}.cap_b_selected must be an array")
    cap_b_selected = []
    for index, row in enumerate(cap_b_raw):
        cap_b_selected.append(
            _require_int_list(row, f"{label}.cap_b_selected[{index}]")
        )
    ship_orders_raw = entry.get("ship_order_types")
    if not isinstance(ship_orders_raw, list):
        raise ValueError(f"{label}.ship_order_types must be an array")
    ship_order_types = []
    for index, record in enumerate(ship_orders_raw):
        record_map = _require_mapping(
            record, f"{label}.ship_order_types[{index}]"
        )
        ship_order_types.append(
            {
                "nation": _require_int(
                    record_map.get("nation"),
                    f"{label}.ship_order_types[{index}].nation",
                ),
                "types": _require_int_list(
                    record_map.get("types"),
                    f"{label}.ship_order_types[{index}].types",
                ),
            }
        )
    tech_ships = _upgrade_ship_records(entry.get("ships"), f"{label}.ships")
    admirals_raw = entry.get("admirals")
    if not isinstance(admirals_raw, list):
        raise ValueError(f"{label}.admirals must be an array")
    admirals = []
    for index, admiral in enumerate(admirals_raw):
        admiral_map = _require_mapping(admiral, f"{label}.admirals[{index}]")
        admirals.append(
            {
                field: _require_int(
                    admiral_map.get(field),
                    f"{label}.admirals[{index}].{field}",
                )
                for field in ("nation", "experience", "ship")
            }
        )
    result["cap_b_selected"] = cap_b_selected
    result["ship_order_types"] = ship_order_types
    result["ships"] = tech_ships
    result["admirals"] = admirals
    return result


def normalize_native_check_technology_advances(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_CHECK_TECH_ADVANCES,
    action_id: str = ACTION_CHECK_TECH_ADVANCES,
) -> dict[str, Any]:
    """Reduce a native driver result to the technology-advance schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": action_id,
        "turn": _mission_turn(turn, "native turn"),
        "technology": _technology_record(
            ephemeral.get("technology"), "native technology"
        ),
    }


def normalize_retail_check_technology_advances(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_CHECK_TECH_ADVANCES,
    action_id: str = ACTION_CHECK_TECH_ADVANCES,
) -> dict[str, Any]:
    """Reduce a retail GDB technology capture to the same schema."""
    turn = {
        "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
        "active": _require_int(raw.get("active_nation"), "retail active_nation"),
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
        "turn_flow_status_flags": _require_int(
            raw.get("turn_flow_status_flags"), "retail turn_flow_status_flags"
        ),
    }
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": action_id,
        "turn": turn,
        "technology": _technology_record(
            raw.get("technology"), "retail technology"
        ),
    }


def normalize_native_season_advance(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a native driver result to the season-advance turn schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": CHECKPOINT_SEASON_ADVANCE,
        "action_id": ACTION_SEASON_ADVANCE,
        "turn": _mission_turn(turn, "native turn"),
    }


def normalize_retail_season_advance(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce a retail GDB turn capture to the same schema."""
    return {
        "checkpoint_id": CHECKPOINT_SEASON_ADVANCE,
        "action_id": ACTION_SEASON_ADVANCE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
    }


def _nation_statuses(raw: Any, label: str) -> list[dict[str, int] | None]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be an array")
    statuses: list[dict[str, int] | None] = []
    for index, entry in enumerate(raw):
        if entry is None:
            statuses.append(None)
            continue
        status = _require_mapping(entry, f"{label}[{index}]")
        statuses.append(
            {
                "encoded_slot": _require_int(
                    status.get("encoded_slot"),
                    f"{label}[{index}].encoded_slot",
                ),
                "owned_region_count": _require_int(
                    status.get("owned_region_count"),
                    f"{label}[{index}].owned_region_count",
                ),
            }
        )
    return statuses


def normalize_native_elimination_phase(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native elimination-phase case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    diplomacy = _require_mapping(
        ephemeral.get("diplomacy"), "native ephemeral diplomacy"
    )
    nations = diplomacy.get("nations")
    if not isinstance(nations, list):
        raise ValueError("native diplomacy nations must be an array")
    eligibility: list[Any] = []
    nation_encoded: list[Any] = []
    for slot, nation in enumerate(nations):
        if nation is None:
            eligibility.append(-1)
            nation_encoded.append(-1)
            continue
        nation_map = _require_mapping(nation, f"native diplomacy nation {slot}")
        eligibility.append(
            _require_int(
                nation_map.get("terrain_eligible"),
                f"native terrain_eligible[{slot}]",
            )
        )
        nation_encoded.append(
            _require_int(
                nation_map.get("encoded_slot"),
                f"native encoded_slot[{slot}]",
            )
        )
    return {
        "checkpoint_id": CHECKPOINT_ELIMINATION_PHASE,
        "action_id": ACTION_ELIMINATION_PHASE,
        "turn": _mission_turn(turn, "native turn"),
        "eligibility": eligibility,
        "nation_encoded": nation_encoded,
        "nation_status": _nation_statuses(
            ephemeral.get("nation_status"), "native nation_status"
        ),
        "dispatched_event": _require_int(
            turn.get("dispatched_event"), "native dispatched_event"
        ),
        "rng": _rng_state(ephemeral.get("rng"), "native rng"),
    }


def normalize_retail_elimination_phase(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail elimination-phase capture to the same schema."""
    eligibility_raw = raw.get("eligibility")
    if not isinstance(eligibility_raw, list):
        raise ValueError("retail eligibility must be an array")
    nation_encoded_raw = raw.get("nation_encoded")
    if not isinstance(nation_encoded_raw, list):
        raise ValueError("retail nation_encoded must be an array")
    return {
        "checkpoint_id": CHECKPOINT_ELIMINATION_PHASE,
        "action_id": ACTION_ELIMINATION_PHASE,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "eligibility": [
            _require_int(entry, f"retail eligibility[{index}]")
            for index, entry in enumerate(eligibility_raw)
        ],
        "nation_encoded": [
            _require_int(entry, f"retail nation_encoded[{index}]")
            for index, entry in enumerate(nation_encoded_raw)
        ],
        "nation_status": _nation_statuses(
            raw.get("nation_status"), "retail nation_status"
        ),
        "dispatched_event": _require_int(
            raw.get("dispatched_event"), "retail dispatched_event"
        ),
        "rng": _rng_state(raw.get("rng"), "retail rng"),
    }


def normalize_native_turn_alerts_first(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native first-turn alert-skip case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    shown = captures.get("result")
    if not isinstance(shown, (bool, int)):
        raise ValueError("native result must be a boolean")
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": CHECKPOINT_TURN_ALERTS_FIRST,
        "action_id": ACTION_TURN_ALERTS_FIRST,
        "turn": _mission_turn(turn, "native turn"),
        "shown": int(shown),
    }


def normalize_retail_turn_alerts_first(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail alert-skip capture to the same schema."""
    return {
        "checkpoint_id": CHECKPOINT_TURN_ALERTS_FIRST,
        "action_id": ACTION_TURN_ALERTS_FIRST,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "shown": _require_int(raw.get("shown"), "retail shown"),
    }


def _pressure_nations(nations_raw: Any, label: str) -> list[Any]:
    if not isinstance(nations_raw, list):
        raise ValueError(f"{label} nations must be an array")
    nations: list[Any] = []
    for slot, nation in enumerate(nations_raw):
        if nation is None:
            nations.append(None)
            continue
        nation_map = _require_mapping(nation, f"{label} nation {slot}")
        nations.append(
            {
                "treasury": _require_int(
                    nation_map.get("treasury"), f"{label} treasury[{slot}]"
                ),
                "budget_base": _require_int(
                    nation_map.get("budget_base"),
                    f"{label} budget_base[{slot}]",
                ),
                "escalation": _require_int(
                    nation_map.get("escalation"),
                    f"{label} escalation[{slot}]",
                ),
                "pressure": _require_int(
                    nation_map.get("pressure"), f"{label} pressure[{slot}]"
                ),
            }
        )
    return nations


def normalize_native_great_power_pressure(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a native great-power-pressure case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    lost = captures.get("result")
    if not isinstance(lost, (bool, int)):
        raise ValueError("native result must be a boolean")
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    diplomacy = _require_mapping(
        ephemeral.get("diplomacy"), "native ephemeral diplomacy"
    )
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
        "lost": int(lost),
        "nations": _pressure_nations(diplomacy.get("nations"), "native"),
    }


def normalize_retail_great_power_pressure(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail great-power-pressure capture to the same schema."""
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "lost": _require_int(raw.get("lost"), "retail lost"),
        "nations": _pressure_nations(raw.get("nations"), "retail"),
    }


def normalize_native_turn_alerts_later(
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the native later-turn alerts case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    alerts_raw = captures.get("result")
    if not isinstance(alerts_raw, list):
        raise ValueError("native result must be an array")
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": CHECKPOINT_TURN_ALERTS_LATER,
        "action_id": ACTION_TURN_ALERTS_LATER,
        "turn": _mission_turn(turn, "native turn"),
        "alerts": [
            _require_int(entry, f"native alerts[{index}]")
            for index, entry in enumerate(alerts_raw)
        ],
    }


def normalize_retail_turn_alerts_later(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail later-turn alerts capture to the same schema."""
    alerts_raw = raw.get("alerts")
    if not isinstance(alerts_raw, list):
        raise ValueError("retail alerts must be an array")
    return {
        "checkpoint_id": CHECKPOINT_TURN_ALERTS_LATER,
        "action_id": ACTION_TURN_ALERTS_LATER,
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "alerts": [
            _require_int(entry, f"retail alerts[{index}]")
            for index, entry in enumerate(alerts_raw)
        ],
    }


def normalize_native_turn_stop_state(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a native turn-stop case to the turn-state schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
    }


def normalize_retail_turn_stop_state(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail turn-stop capture to the same schema."""
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
    }


_TURN_STOP_TRADE_INT_FIELDS = (
    "phase",
    "category_index",
    "entry_ordinal",
    "buyer",
    "seller",
    "amount",
    "price",
    "commodity",
)

_TURN_STOP_TRADE_DEAL_FIELDS = (
    "source",
    "target",
    "delta",
    "standing",
    "score",
)


def _turn_stop_trade_deals(
    deals_raw: Any, side: str
) -> list[dict[str, int]]:
    if not isinstance(deals_raw, list):
        raise ValueError(f"{side} deals must be an array")
    deals = []
    for index, entry in enumerate(deals_raw):
        row = _require_mapping(entry, f"{side} deals[{index}]")
        deals.append(
            {
                field: _require_int(
                    row.get(field), f"{side} deals[{index}].{field}"
                )
                for field in _TURN_STOP_TRADE_DEAL_FIELDS
            }
        )
    return deals


def normalize_native_turn_stop_trade(
    result: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_TURN_STOP_TRADE,
) -> dict[str, Any]:
    """Reduce a native trade turn-stop case to the offer-sheet schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    normalized = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(turn.get("phase"), "native turn.phase"),
            "active": _require_int(turn.get("active_nation"), "native active_nation"),
            "economic_turn": _require_int(
                turn.get("economic_turn"), "native economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                turn.get("turn_flow_status_flags"), "native turn_flow_status_flags"
            ),
        },
        "stop": transition_result.get("stop"),
    }
    for field in _TURN_STOP_TRADE_INT_FIELDS:
        normalized[field] = _require_int(
            transition_result.get(field), f"native {field}"
        )
    normalized["deals"] = _turn_stop_trade_deals(
        transition_result.get("deals"), "native"
    )
    return normalized


def normalize_retail_turn_stop_trade(
    raw: Mapping[str, Any],
    checkpoint_id: str = CHECKPOINT_TURN_STOP_TRADE,
) -> dict[str, Any]:
    """Reduce a retail trade turn-stop capture to the same schema."""
    normalized = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "stop": raw.get("stop"),
    }
    for field in _TURN_STOP_TRADE_INT_FIELDS:
        normalized[field] = _require_int(
            raw.get(field), f"retail {field}"
        )
    normalized["deals"] = _turn_stop_trade_deals(
        raw.get("deals"), "retail"
    )
    return normalized


def normalize_native_battle_attack(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a native interactive-attack case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    kinds = transition_result.get("kinds")
    targets = transition_result.get("targets")
    actuals = transition_result.get("actuals")
    snapshots = transition_result.get("snapshots")
    for name, value in (
        ("kinds", kinds),
        ("targets", targets),
        ("actuals", actuals),
        ("snapshots", snapshots),
    ):
        if not isinstance(value, list):
            raise ValueError(f"native result {name} must be an array")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
        "kinds": [
            _require_int(entry, f"native kinds[{index}]")
            for index, entry in enumerate(kinds)
        ],
        "targets": [
            _require_int(entry, f"native targets[{index}]")
            for index, entry in enumerate(targets)
        ],
        "actuals": [
            _require_int(entry, f"native actuals[{index}]")
            for index, entry in enumerate(actuals)
        ],
        "snapshots": snapshots,
    }


def normalize_retail_battle_attack(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail interactive-attack capture to the same schema."""
    kinds = raw.get("kinds")
    targets = raw.get("targets")
    actuals = raw.get("actuals")
    snapshots = raw.get("snapshots")
    for name, value in (
        ("kinds", kinds),
        ("targets", targets),
        ("actuals", actuals),
        ("snapshots", snapshots),
    ):
        if not isinstance(value, list):
            raise ValueError(f"retail {name} must be an array")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
        "kinds": [
            _require_int(entry, f"retail kinds[{index}]")
            for index, entry in enumerate(kinds)
        ],
        "targets": [
            _require_int(entry, f"retail targets[{index}]")
            for index, entry in enumerate(targets)
        ],
        "actuals": [
            _require_int(entry, f"retail actuals[{index}]")
            for index, entry in enumerate(actuals)
        ],
        "snapshots": snapshots,
    }


def _combat_moves_battle(value: Any, label: str) -> dict[str, Any]:
    entry = _require_mapping(value, label)
    result = {
        "province": _require_int(entry.get("province"), f"{label}.province"),
        "attacker_nation": _require_int(
            entry.get("attacker_nation"), f"{label}.attacker_nation"
        ),
        "defender_nation": _require_int(
            entry.get("defender_nation"), f"{label}.defender_nation"
        ),
    }
    for key in ("attacker_units", "defender_units"):
        units = entry.get(key)
        if not isinstance(units, list):
            raise ValueError(f"{label}.{key} must be an array")
        result[key] = [
            _require_int(unit, f"{label}.{key}[{index}]")
            for index, unit in enumerate(units)
        ]
    return result


def _combat_moves_units(value: Any, label: str) -> list[dict[str, int]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    units = []
    for index, entry in enumerate(value):
        record = _require_mapping(entry, f"{label}[{index}]")
        units.append(
            {
                "id": _require_int(record.get("id"), f"{label}[{index}].id"),
                "tile": _require_int(
                    record.get("tile"), f"{label}[{index}].tile"
                ),
            }
        )
    return units


def normalize_native_combat_moves(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a native combat-moves case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    battles = transition_result.get("battles")
    if not isinstance(battles, list):
        raise ValueError("native result battles must be an array")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
        "battles": [
            _combat_moves_battle(battle, f"native battles[{index}]")
            for index, battle in enumerate(battles)
        ],
        "units": _combat_moves_units(
            transition_result.get("units"), "native units"
        ),
    }


def normalize_retail_combat_moves(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail combat-moves capture to the same schema."""
    battles = raw.get("battles")
    if not isinstance(battles, list):
        raise ValueError("retail battles must be an array")
    return {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail turn.active"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail turn.economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn.turn_flow_status_flags",
            ),
        },
        "battles": [
            _combat_moves_battle(battle, f"retail battles[{index}]")
            for index, battle in enumerate(battles)
        ],
        "units": _combat_moves_units(raw.get("units"), "retail units"),
    }


_NAVY_DEPLOY_SNAPSHOT_FIELDS = (
    "column_count",
    "current_side",
    "side0_nation",
    "side1_nation",
    "side0_selected",
    "side1_selected",
)


def _navy_deploy_snapshot(raw: Any, label: str) -> dict[str, Any]:
    snapshot = _require_mapping(raw, label)
    normalized = {
        field: _require_int(snapshot.get(field), f"{label}.{field}")
        for field in _NAVY_DEPLOY_SNAPSHOT_FIELDS
    }
    for side_field in ("side0_tiles", "side1_tiles"):
        tiles = snapshot.get(side_field)
        if not isinstance(tiles, list):
            raise ValueError(f"{label}.{side_field} must be an array")
        normalized[side_field] = [
            _require_int(tile, f"{label}.{side_field}[{index}]")
            for index, tile in enumerate(tiles)
        ]
    return normalized


def normalize_native_navy_battle_deploy(
    result: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a native navy-battle deploy case to the stable schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    transition_result = _require_mapping(
        captures.get("result"), "native result capture"
    )
    after = _require_mapping(captures.get("after"), "native after capture")
    ephemeral = _require_mapping(after.get("ephemeral"), "native after.ephemeral")
    turn = _require_mapping(ephemeral.get("turn"), "native ephemeral turn")
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": _mission_turn(turn, "native turn"),
    }
    observation.update(
        _navy_deploy_snapshot(transition_result, "native result")
    )
    return observation


def normalize_retail_navy_battle_deploy(
    raw: Mapping[str, Any],
    checkpoint_id: str,
) -> dict[str, Any]:
    """Reduce a retail navy-battle deploy capture to the same schema."""
    observation = {
        "checkpoint_id": checkpoint_id,
        "action_id": checkpoint_id.replace(".resolved", ".run"),
        "turn": {
            "phase": _require_int(raw.get("turn_phase"), "retail turn.phase"),
            "active": _require_int(
                raw.get("active_nation"), "retail active_nation"
            ),
            "economic_turn": _require_int(
                raw.get("economic_turn"), "retail economic_turn"
            ),
            "turn_flow_status_flags": _require_int(
                raw.get("turn_flow_status_flags"),
                "retail turn_flow_status_flags",
            ),
        },
    }
    observation.update(_navy_deploy_snapshot(raw, "retail result"))
    return observation


def normalize_retail_second_turn_sequence(
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce the retail state-machine walk to the same stop sequence."""
    stops_raw = raw.get("stops")
    if not isinstance(stops_raw, list):
        raise ValueError("retail stops must be an array")
    stops = []
    for index, code in enumerate(stops_raw):
        code = _require_int(code, f"retail stops[{index}]")
        name = _TURN_STATE_STOP_NAMES.get(code)
        if name is None:
            raise ValueError(f"retail stops[{index}] unknown state {code:#x}")
        stops.append(name)
    return {
        "checkpoint_id": CHECKPOINT_SECOND_TURN_SEQUENCE,
        "action_id": ACTION_SECOND_TURN_SEQUENCE,
        "stops": stops,
        "economic_turn": _require_int(
            raw.get("economic_turn"), "retail economic_turn"
        ),
    }


def normalize_native_combined_map(result: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a native driver result to the stable combined-map schema."""
    if result.get("status") != "passed":
        raise ValueError(f"native driver did not pass: {result.get('status')!r}")
    captures = _native_captures(result)
    map_state = _require_mapping(captures.get("map_state"), "native map_state")
    root_class = map_state.get("root_class")
    if root_class != "TMapUberPicture":
        raise ValueError(f"native active view is {root_class!r}, expected TMapUberPicture")
    return {
        "checkpoint_id": CHECKPOINT_COMBINED_MAP_READY,
        "action_id": ACTION_COMBINED_MAP_ENTRY,
        "turn_event": _require_int(map_state.get("turn_event"), "native turn_event"),
        "active_view": "strategic_map",
        "nation": {
            "active": _require_int(
                map_state.get("active_nation"), "native active_nation"
            ),
            "economic_turn": _require_int(
                map_state.get("economic_turn"), "native economic_turn"
            ),
        },
        "map": {
            "present": _require_bool(
                map_state.get("global_map"), "native global_map"
            ),
            "wrap": _require_int(map_state.get("wrap"), "native map wrap"),
        },
        "city_orders": {
            "city_present": _require_bool(
                map_state.get("city_present"), "native city_present"
            ),
            "production_orders": _require_int_list(
                map_state.get("production_orders"), "native production_orders"
            ),
            "production_flags": _require_int_list(
                map_state.get("production_flags"), "native production_flags"
            ),
        },
    }


def normalize_retail_combined_map(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a retail GDB capture to the same stable combined-map schema."""
    map_view_present = _require_bool(
        fields.get("combined_map_view_present"), "retail combined_map_view_present"
    )
    if not map_view_present:
        raise ValueError("retail combined map view is absent")
    return {
        "checkpoint_id": CHECKPOINT_COMBINED_MAP_READY,
        "action_id": ACTION_COMBINED_MAP_ENTRY,
        "turn_event": _require_int(fields.get("turn_event"), "retail turn_event"),
        "active_view": "strategic_map",
        "nation": {
            "active": _require_int(fields.get("active_nation"), "retail active_nation"),
            "economic_turn": _require_int(
                fields.get("economic_turn"), "retail economic_turn"
            ),
        },
        "map": {
            "present": _require_bool(fields.get("map_present"), "retail map_present"),
            "wrap": _require_int(fields.get("map_wrap"), "retail map_wrap"),
        },
        "city_orders": {
            "city_present": _require_bool(
                fields.get("city_present"), "retail city_present"
            ),
            "production_orders": [
                _require_int(fields.get(f"production_order_{slot:02d}"),
                             f"retail production_order_{slot:02d}")
                for slot in range(16)
            ],
            "production_flags": [
                _require_int(fields.get(f"production_flag_{slot:02d}"),
                             f"retail production_flag_{slot:02d}")
                for slot in range(16)
            ],
        },
    }


def first_checkpoint_difference(left: Any, right: Any, path: str = "$") -> dict | None:
    """Return the first typed semantic difference with a JSON-style field path."""
    if type(left) is not type(right):
        return {"path": path, "kind": "type_mismatch", "retail": left, "recomp": right}
    if isinstance(left, dict):
        keys = list(left)
        keys.extend(key for key in right if key not in left)
        for key in keys:
            child_path = f"{path}.{key}"
            if key not in left:
                return {"path": child_path, "kind": "missing_retail", "recomp": right[key]}
            if key not in right:
                return {"path": child_path, "kind": "missing_recomp", "retail": left[key]}
            difference = first_checkpoint_difference(left[key], right[key], child_path)
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {
                "path": path,
                "kind": "length_mismatch",
                "retail": len(left),
                "recomp": len(right),
            }
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
            difference = first_checkpoint_difference(
                left_item, right_item, f"{path}[{index}]"
            )
            if difference is not None:
                return difference
        return None
    if left != right:
        return {"path": path, "kind": "value_mismatch", "retail": left, "recomp": right}
    return None


def validate_checkpoint(observation: Mapping[str, Any]) -> None:
    checkpoint_id = observation.get("checkpoint_id")
    schema = SCHEMAS.get(checkpoint_id)
    if schema is None:
        raise ValueError(f"unknown checkpoint_id {checkpoint_id!r}")
    if observation.get("action_id") != schema.action_id:
        raise ValueError(
            f"checkpoint {checkpoint_id!r} requires action_id {schema.action_id!r}"
        )
    for path in schema.required_paths:
        current: Any = observation
        for component in path.split("."):
            if not isinstance(current, Mapping) or component not in current:
                raise ValueError(f"checkpoint {checkpoint_id!r} is missing {path}")
            current = current[component]
