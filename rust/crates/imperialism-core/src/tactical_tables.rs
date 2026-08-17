//! Numeric tables for headless land-battle Auto (`global_data_tables.cpp`).

use crate::units::TacticalCombatClass;
use crate::{MilitaryUnitTable, TacticalCombatClassTable};

pub(crate) const TACTICAL_TILE_COUNT: usize = 0x1b3;
pub(crate) const TACTICAL_STRIDE: i32 = 0x1d;
pub(crate) const TACTICAL_ROWS: i32 = 15;

pub(crate) const UNIT_RANGE: MilitaryUnitTable<i32> = MilitaryUnitTable::from_array([
    5, 5, 5, 5, 3, 3, 9, 11, 8, 8, 8, 8, 5, 5, 12, 14, 10, 10, 10, 10, 10, 12, 15, 17, 5, 8, 10, 0,
    0, 0,
]);

pub(crate) const BASE_ACTION_POINTS: MilitaryUnitTable<i32> = MilitaryUnitTable::from_array([
    40, 60, 40, 40, 110, 90, 50, 30, 40, 60, 40, 40, 110, 90, 60, 30, 50, 70, 50, 40, 110, 90, 80,
    30, 40, 40, 50, 90, 90, 90,
]);

/// `g_awTacticalUnitAiClassByUnitType_006693B8` / combat-category twin at 0x669858.
pub(crate) const AI_CLASS: MilitaryUnitTable<TacticalCombatClass> =
    MilitaryUnitTable::from_array([
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Cavalry,
        TacticalCombatClass::Cavalry,
        TacticalCombatClass::Artillery,
        TacticalCombatClass::Artillery,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Cavalry,
        TacticalCombatClass::Cavalry,
        TacticalCombatClass::Artillery,
        TacticalCombatClass::Artillery,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Infantry,
        TacticalCombatClass::Cavalry,
        TacticalCombatClass::Armor,
        TacticalCombatClass::Artillery,
        TacticalCombatClass::Artillery,
        TacticalCombatClass::Support,
        TacticalCombatClass::Support,
        TacticalCombatClass::Support,
        TacticalCombatClass::Support,
        TacticalCombatClass::Support,
        TacticalCombatClass::Support,
    ]);

pub(crate) const DIRECT_FIRE: [f32; 10] = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0];

pub(crate) const BASE_ATTACK_POWER: MilitaryUnitTable<f32> = MilitaryUnitTable::from_array([
    50.0, 50.0, 100.0, 125.0, 75.0, 150.0, 100.0, 160.0, 75.0, 100.0, 150.0, 175.0, 100.0, 200.0,
    175.0, 300.0, 100.0, 150.0, 225.0, 250.0, 225.0, 450.0, 250.0, 500.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0,
]);

pub(crate) const MELEE_MULTIPLIER: [f32; 8] = [1.0, 1.0, 1.0, 1.0, 1.3, 1.3, 0.2, 0.2];

pub(crate) const DAMAGE_SCALE: MilitaryUnitTable<f32> = MilitaryUnitTable::from_array([
    0.0025, 0.0015, 0.002, 0.002, 0.0015, 0.002, 0.004, 0.005, 0.0025, 0.0015, 0.0015, 0.0015,
    0.0015, 0.002, 0.003, 0.0035, 0.001, 0.0005, 0.0005, 0.0005, 0.001, 0.0005, 0.0005, 0.0005,
    0.003, 0.0025, 0.001, 0.002, 0.0015, 0.0005,
]);

pub(crate) const ATTACK_TERRAIN: [f32; 50] = [
    1.0, 0.75, 0.75, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.75, 0.75, 1.0, 0.0, 1.0, 0.75, 0.75,
    1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.75, 0.75, 1.0, 0.0, 1.0, 0.75, 0.75, 1.0, 0.0, 1.0,
    0.75, 0.75, 1.0, 0.0, 1.0, 0.75, 0.75, 1.0, 0.0, 1.0, 0.75, 0.75, 1.0, 0.0,
];

pub(crate) const DEFENSE_TERRAIN: [f32; 50] = [
    1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.8, 0.8, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0,
    0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0,
    1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0,
];

pub(crate) const COVER_DAMAGE: [f32; 50] = [
    1.0, 0.8, 0.7, 0.6, 0.5, 1.0, 0.8, 0.7, 0.6, 0.5, 1.0, 0.8, 0.7, 0.6, 0.5, 1.0, 0.8, 0.7, 0.6,
    0.5, 1.0, 1.0, 0.7, 0.6, 0.5, 1.0, 1.0, 0.7, 0.6, 0.5, 1.0, 0.8, 0.7, 0.6, 0.5, 1.0, 0.8, 0.7,
    0.6, 0.5, 1.0, 0.8, 0.7, 0.6, 0.5, 1.0, 0.8, 0.7, 0.6, 0.5,
];

pub(crate) const MOVE_COST: [i16; 50] = [
    10, 20, 30, 15, 999, 10, 10, 10, 10, 999, 10, 20, 30, 15, 999, 10, 20, 30, 15, 999, 10, 10, 10,
    10, 999, 10, 20, 30, 15, 999, 10, 20, 30, 15, 999, 10, 20, 30, 15, 999, 10, 20, 30, 15, 999,
    10, 20, 30, 15, 999,
];

pub(crate) const FORT_STRENGTH_BY_LEVEL: [i32; 6] = [0, 0, 500, 750, 1000, 0];

pub(crate) const GATE_FLAG_SCORE_BUCKET: [u8; 15] = [0, 0, 0, 0, 1, 1, 2, 2, 2, 3, 4, 2, 2, 7, 2];

pub(crate) const HEURISTIC_WEIGHTS: [[i32; 15]; 20] = [
    [1, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0],
    [0, 100, 0, 200, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, -10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 100, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 100, 0, 200, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 100, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, -1, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, -1, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    [1, 0, 0, 100, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 200, 0, 0, 0],
    [0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    [0, 1, 0, 0, -100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
];

pub(crate) const ATTACKER_DEPLOY_ZONE_SCORES: TacticalCombatClassTable<[i32; 6]> =
    TacticalCombatClassTable::from_array([
        [10, 30, 10, 20, 10, 10],
        [10, 20, 30, 40, 50, 60],
        [60, 40, 50, 30, 20, 10],
        [10, 20, 30, 40, 50, 60],
        [10, 20, 30, 40, 50, 60],
    ]);

pub(crate) const CURSOR_STRONG_RATIO: f32 = 3.0;
pub(crate) const CURSOR_OVERWHELM_RATIO: f32 = 4.0;
pub(crate) const CURSOR_WEAK_RATIO: f32 = 0.25;
pub(crate) const CURSOR_ARTILLERY_PARITY: f32 = 1.0;
pub(crate) const CURSOR_ARTILLERY_SUPERIORITY: f32 = 1.8;
pub(crate) const CURSOR_ASSAULT_RATIO: f32 = 2.5;
pub(crate) const CURSOR_RETREAT_RATIO: f32 = 0.8;
