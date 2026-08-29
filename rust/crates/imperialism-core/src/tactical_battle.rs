//! Retail `TArmyBattle` simulation. Hover classification returns [`HoverAction`];
//! combat records [`ArmyBattleEvent`]s as ordered observable effects.

#![allow(clippy::if_same_then_else)] // retail cursor-mode branches keep identical arms
#![allow(clippy::needless_range_loop)] // parallel C++ index walks
#![allow(clippy::neg_cmp_op_on_partial_ord)] // retail `!(a < b)` form

use crate::military::{ActionClassScores, ActionClassWeights, TACTICAL_COMPOSITION};
use crate::tactical_tables::*;
use crate::*;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Stable identity for a unit inside one army battle (`TTacticalUnit` source id).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArmyUnitId(MilitaryUnitId);

impl ArmyUnitId {
    pub const fn source(self) -> MilitaryUnitId {
        self.0
    }
}

/// Linear tactical-grid index (`TacticalTileIndex`), 15×29.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TacticalHex {
    index: i32,
}

impl TacticalHex {
    pub const COLUMNS: i32 = TACTICAL_STRIDE;
    pub const ROWS: i32 = TACTICAL_ROWS;

    pub const fn from_index(index: i32) -> Option<Self> {
        if index >= 0 && index < TACTICAL_TILE_COUNT as i32 {
            Some(Self { index })
        } else {
            None
        }
    }

    pub const fn from_row_column(row: i32, column: i32) -> Option<Self> {
        if row >= 0 && row < Self::ROWS && column >= 0 && column < Self::COLUMNS {
            Self::from_index(row * Self::COLUMNS + column)
        } else {
            None
        }
    }

    pub const fn index(self) -> i32 {
        self.index
    }

    pub const fn row(self) -> i32 {
        self.index / Self::COLUMNS
    }

    pub const fn column(self) -> i32 {
        self.index % Self::COLUMNS
    }
}

/// Attacker is side 0 (`TTacticalBattle::currentSideC`).
#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, PartialEq, Serialize)]
pub enum BattleSide {
    Attacker,
    Defender,
}

/// Snapshot of one deployed or retired tactical unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmyUnitView {
    pub id: ArmyUnitId,
    pub side: BattleSide,
    pub unit_type: MilitaryUnitKind,
    pub hex: Option<TacticalHex>,
    pub strength: i32,
    pub morale: i32,
    pub action_points: i32,
    pub quality: i16,
    pub selected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmyTargetCycle {
    pub center: Option<TacticalHex>,
    pub has_target: bool,
}

/// Presentation state read by `TTacArmyView::DrawTacticalTileInClipRect`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArmyTileView {
    pub hex: TacticalHex,
    pub trench_mask: u8,
    pub fort_wall: bool,
    pub fort_wall_intact: bool,
    pub occupied: bool,
    pub unit_cover: bool,
    pub threatened: bool,
}

/// Result of `MoveTacticalUnitTowardTile` for the UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveResult {
    pub unit: ArmyUnitId,
    pub from: TacticalHex,
    pub to: TacticalHex,
    pub path: Vec<TacticalHex>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArmyAction {
    Deploy {
        unit: ArmyUnitId,
        target: TacticalHex,
    },
    Move(MoveResult),
    Dig(MoveResult),
    Mine {
        unit: ArmyUnitId,
        target: TacticalHex,
    },
    Rally {
        unit: ArmyUnitId,
        target: ArmyUnitId,
    },
    Undeploy {
        unit: ArmyUnitId,
    },
    Attack {
        attacker: ArmyUnitId,
        target: TacticalHex,
    },
    Done,
}

/// Ordered observable combat effect from one army-battle mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmyBattleEvent {
    Move {
        unit: ArmyUnitId,
        from: TacticalHex,
        to: TacticalHex,
    },
    Attack {
        attacker: ArmyUnitId,
        target: TacticalHex,
        fort_target: bool,
    },
    Mine {
        target: TacticalHex,
    },
    Rally,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmyBattleProgress {
    pub stop: Option<TurnStop>,
    pub events: Vec<ArmyBattleEvent>,
}

/// Semantic hover result for a tactical hex (`ComputeTacticalHoverCursorStateIndex`
/// plus the reachability refinement in `ResolveTacticalHoverCursorResourceId`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoverAction {
    None,
    Wait,
    Invalid,
    Deploy,
    Move,
    Attack,
    Done,
    Dig,
    Rally,
    Mine,
    Melee,
    Undeploy,
    CanAttack,
    Unreachable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmyBattleStage {
    Deploying,
    Live,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmyActionRejection {
    NoLiveBattle,
    NoSelectedUnit,
    NotControlled,
    Unplaced,
    InvalidTarget,
}

/// Live `TArmyBattle` for one pending land battle. Mechanics stay in the private grid.
#[derive(Clone)]
pub struct ArmyBattle {
    inner: Battle,
}

impl std::fmt::Debug for ArmyBattle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmyBattle")
            .field("units", &self.inner.units.len())
            .field("column_count", &self.inner.column_count)
            .field("round", &self.inner.round)
            .finish_non_exhaustive()
    }
}

impl ArmyBattle {
    pub fn units(&self) -> impl Iterator<Item = ArmyUnitView> + '_ {
        self.inner.units.iter().filter_map(|unit| {
            if unit.state == TacticalUnitState::Destroyed
                || unit.state == TacticalUnitState::Retreated
            {
                return None;
            }
            Some(ArmyUnitView {
                id: ArmyUnitId(unit.source),
                side: unit.side,
                unit_type: unit.unit_type,
                hex: TacticalHex::from_index(unit.tile),
                strength: unit.strength,
                morale: unit.morale,
                action_points: unit.action_points,
                quality: unit.quality,
                selected: unit.selected,
            })
        })
    }

    pub fn unit(&self, id: ArmyUnitId) -> Option<ArmyUnitView> {
        self.units().find(|unit| unit.id == id)
    }

    pub fn tiles(&self) -> impl Iterator<Item = ArmyTileView> + '_ {
        self.inner.tiles.iter().enumerate().map(|(index, tile)| {
            let fort_wall = tile.deploy_mark.is_fort_wall();
            ArmyTileView {
                hex: TacticalHex::from_index(index as i32).expect("tactical grid index is valid"),
                trench_mask: tile.trench_mask,
                fort_wall,
                fort_wall_intact: fort_wall
                    && self.inner.fort_strength[index / TACTICAL_STRIDE as usize / 2] > 0,
                occupied: tile.occupant.is_some(),
                unit_cover: tile.deploy_mark == DeployMark::UnitCover,
                threatened: self.inner.threat[index] != 0,
            }
        })
    }

    pub fn active_side(&self) -> BattleSide {
        self.inner.current_side
    }

    pub fn nation(&self, side: BattleSide) -> NationId {
        self.inner.sides[side].nation
    }

    pub fn unit_at(&self, hex: TacticalHex) -> Option<ArmyUnitView> {
        self.inner.tiles[hex.index as usize]
            .occupant
            .and_then(|idx| self.unit(ArmyUnitId(self.inner.units[idx].source)))
    }

    /// Retail hover classifier for `hex` relative to the current side and selection.
    pub fn hover_action(&self, hex: TacticalHex, active_nation: NationId) -> HoverAction {
        let battle = &self.inner;
        let side = battle.current_side;
        if battle.sides[side].nation != active_nation || battle.sides[side].auto_play {
            return HoverAction::Wait;
        }
        let tile_index = hex.index;
        let tile = battle.tiles[tile_index as usize];
        if !battle.live {
            return if tile
                .occupant
                .is_some_and(|idx| battle.units[idx].side == side)
            {
                HoverAction::Undeploy
            } else if battle.deploy_guard(tile_index) != 0 {
                HoverAction::Deploy
            } else {
                HoverAction::Invalid
            };
        }
        let Some(selected) = battle.selected else {
            return HoverAction::None;
        };
        let unit = &battle.units[selected];
        let category = unit.unit_type.tactical_category();
        let adjacent = battle
            .neighbors(unit.tile)
            .values()
            .any(|&neighbor| neighbor == tile_index);
        let intact_fort = tile.deploy_mark.is_fort_wall()
            && battle.fort_strength[(tile_index / TACTICAL_STRIDE / 2) as usize] > 0;
        let mut action = HoverAction::None;
        if category == ArmyUnitCategory::Engineers && adjacent {
            if intact_fort {
                action = HoverAction::Mine;
            } else if unit.action_points >= unit.base_action_points() / 2
                && tile.trench_mask & 0x40 == 0
                && battle.tiles[unit.tile as usize].trench_mask & 0x40 == 0
                && tile.trench_mask & 0x80 == 0
                && tile.occupant.is_none()
                && tile.terrain != TacticalTerrain::Impassable
            {
                action = HoverAction::Dig;
            }
        } else if category == ArmyUnitCategory::Generals
            && adjacent
            && tile
                .occupant
                .is_some_and(|idx| battle.units[idx].side == unit.side)
        {
            action = HoverAction::Rally;
        }
        if action == HoverAction::None {
            if intact_fort {
                if !direct_fire(category)
                    && unit.selected
                    && battle.reachable_for_action(
                        unit.tile,
                        tile_index,
                        false,
                        battle.unit_range(selected),
                    )
                {
                    action = HoverAction::Attack;
                } else if battle.cost(tile_index) > 0 && tile.occupant.is_none() {
                    action = HoverAction::Move;
                }
            } else if battle.cost(tile_index) > 0 && tile.occupant.is_none() {
                action = HoverAction::Move;
            } else if let Some(occupant) = tile.occupant {
                if battle.units[occupant].side != side
                    && category != ArmyUnitCategory::Engineers
                    && unit.selected
                    && battle.reachable_for_action(
                        unit.tile,
                        tile_index,
                        direct_fire(category),
                        battle.unit_range(selected),
                    )
                {
                    action = if adjacent {
                        HoverAction::Melee
                    } else {
                        HoverAction::Attack
                    };
                } else if occupant == selected {
                    action = HoverAction::Done;
                }
            }
        }
        if action == HoverAction::None
            && (tile
                .occupant
                .is_some_and(|occupant| battle.units[occupant].side != side)
                || (!direct_fire(category) && intact_fort && unit.side == BattleSide::Attacker))
        {
            return if battle.reachable_for_action(
                unit.tile,
                tile_index,
                direct_fire(category),
                battle.unit_range(selected),
            ) {
                HoverAction::CanAttack
            } else {
                HoverAction::Unreachable
            };
        }
        action
    }

    fn selected_unit(&self) -> Option<ArmyUnitId> {
        self.inner
            .selected
            .map(|idx| ArmyUnitId(self.inner.units[idx].source))
    }

    pub fn column_count(&self) -> i32 {
        self.inner.column_count
    }

    pub fn composition_class(&self) -> i32 {
        self.inner.composition_class
    }

    pub fn fort_level(&self) -> FortLevel {
        self.inner.fort_level
    }

    pub fn stage(&self) -> ArmyBattleStage {
        if self.inner.live {
            ArmyBattleStage::Live
        } else {
            ArmyBattleStage::Deploying
        }
    }

    fn selected_unit_reachable_hexes(&self, active_nation: NationId) -> Vec<TacticalHex> {
        let Some(idx) = self.inner.selected else {
            return Vec::new();
        };
        if self.inner.units[idx].side != self.inner.current_side
            || self.inner.sides[self.inner.current_side].nation != active_nation
            || self.inner.sides[self.inner.current_side].auto_play
        {
            return Vec::new();
        }
        if !self.inner.live {
            return (0..TACTICAL_TILE_COUNT as i32)
                .filter(|&tile| self.inner.deploy_guard(tile) != 0)
                .filter_map(TacticalHex::from_index)
                .collect();
        }
        if self.inner.units[idx].tile < 0 {
            return Vec::new();
        }
        (0..TACTICAL_TILE_COUNT as i32)
            .filter(|&tile| self.inner.cost(tile) > 0)
            .filter_map(TacticalHex::from_index)
            .collect()
    }

    fn selected_unit_for_action(
        &self,
        active_nation: NationId,
    ) -> Result<usize, ArmyActionRejection> {
        let idx = self
            .inner
            .selected
            .ok_or(ArmyActionRejection::NoSelectedUnit)?;
        if self.inner.units[idx].side != self.inner.current_side
            || self.inner.sides[self.inner.current_side].nation != active_nation
            || self.inner.sides[self.inner.current_side].auto_play
        {
            return Err(ArmyActionRejection::NotControlled);
        }
        Ok(idx)
    }

    fn action_at(
        &mut self,
        target: TacticalHex,
        active_nation: NationId,
        state: &mut GameState,
    ) -> Result<ArmyAction, ArmyActionRejection> {
        let idx = self.selected_unit_for_action(active_nation)?;
        if !self.inner.live {
            if let Some(occupant) = self.inner.tiles[target.index as usize].occupant
                && self.inner.units[occupant].side == self.inner.current_side
            {
                let unit = ArmyUnitId(self.inner.units[occupant].source);
                self.inner.units[occupant].tile = -2;
                self.inner.tiles[target.index as usize].occupant = None;
                return Ok(ArmyAction::Undeploy { unit });
            }
            if self.inner.deploy_guard(target.index) == 0 {
                return Err(ArmyActionRejection::InvalidTarget);
            }
            let unit = ArmyUnitId(self.inner.units[idx].source);
            self.inner.deploy_to_tile(idx, target.index);
            return Ok(ArmyAction::Deploy { unit, target });
        }
        let from = TacticalHex::from_index(self.inner.units[idx].tile)
            .ok_or(ArmyActionRejection::Unplaced)?;
        self.inner.compute_reachable(idx);
        let tile = self.inner.tiles[target.index as usize];
        let category = self.inner.units[idx].unit_type.tactical_category();
        let adjacent = self
            .inner
            .neighbors(self.inner.units[idx].tile)
            .values()
            .any(|&neighbor| neighbor == target.index);
        let intact_fort = tile.deploy_mark.is_fort_wall()
            && self.inner.fort_strength[(target.index / TACTICAL_STRIDE / 2) as usize] > 0;
        if category == ArmyUnitCategory::Engineers && adjacent {
            if intact_fort {
                let unit = ArmyUnitId(self.inner.units[idx].source);
                self.inner.mine(state, idx, target.index);
                return Ok(ArmyAction::Mine { unit, target });
            }
            if self.inner.units[idx].action_points >= self.inner.units[idx].base_action_points() / 2
                && tile.trench_mask & 0x40 == 0
                && self.inner.tiles[from.index as usize].trench_mask & 0x40 == 0
                && tile.trench_mask & 0x80 == 0
                && tile.occupant.is_none()
                && tile.terrain != TacticalTerrain::Impassable
            {
                let path = self.inner.dig(state, idx, target.index);
                let to = TacticalHex::from_index(self.inner.units[idx].tile).unwrap_or(target);
                return Ok(ArmyAction::Dig(MoveResult {
                    unit: ArmyUnitId(self.inner.units[idx].source),
                    from,
                    to,
                    path,
                }));
            }
        }
        if category == ArmyUnitCategory::Generals
            && adjacent
            && let Some(occupant) = tile.occupant
            && self.inner.units[occupant].side == self.inner.units[idx].side
        {
            let unit = ArmyUnitId(self.inner.units[idx].source);
            let target = ArmyUnitId(self.inner.units[occupant].source);
            self.inner.rally(state, idx, occupant);
            return Ok(ArmyAction::Rally { unit, target });
        }
        if self.inner.cost(target.index) > 0 && tile.occupant.is_none() {
            let path = self.inner.move_and_maybe_finish(state, idx, target.index);
            return Ok(ArmyAction::Move(MoveResult {
                unit: ArmyUnitId(self.inner.units[idx].source),
                from,
                to: TacticalHex::from_index(self.inner.units[idx].tile).unwrap_or(target),
                path,
            }));
        }
        if tile.occupant == Some(idx) {
            self.inner.finish_action();
            return Ok(ArmyAction::Done);
        }
        let enemy = tile
            .occupant
            .is_some_and(|occupant| self.inner.units[occupant].side != self.inner.units[idx].side);
        let attackable = self.inner.units[idx].selected
            && category != ArmyUnitCategory::Engineers
            && ((!direct_fire(category) && intact_fort) || enemy)
            && self.inner.reachable_for_action(
                self.inner.units[idx].tile,
                target.index,
                direct_fire(category),
                self.inner.unit_range(idx),
            );
        if !attackable {
            return Err(ArmyActionRejection::InvalidTarget);
        }
        let attacker = ArmyUnitId(self.inner.units[idx].source);
        self.inner.fire_and_maybe_finish(state, idx, target.index);
        Ok(ArmyAction::Attack { attacker, target })
    }

    fn cycle_target(
        &mut self,
        active_nation: NationId,
    ) -> Result<ArmyTargetCycle, ArmyActionRejection> {
        let selected = self.selected_unit_for_action(active_nation)?;
        if !self.inner.live {
            return Err(ArmyActionRejection::InvalidTarget);
        }
        let side = self.inner.units[selected].side;
        let opponents = self.inner.sides[side.opponent()].units.clone();
        if opponents.is_empty() {
            self.inner.units[selected].attack_target = None;
            return Ok(ArmyTargetCycle {
                center: None,
                has_target: false,
            });
        }
        let mut marker = self.inner.units[selected].attack_target;
        let mut position = marker
            .and_then(|marker| opponents.iter().position(|&idx| idx == marker))
            .map_or(0, |position| position + 1);
        if position == 0 {
            marker = None;
        }
        let category = self.inner.units[selected].unit_type.tactical_category();
        let selected_tile = self.inner.units[selected].tile;
        let range = self.inner.unit_range(selected);
        let reachable = |battle: &Battle, candidate: usize| {
            battle.units[candidate].state == TacticalUnitState::Ready
                && battle.units[selected].selected
                && battle.reachable_for_action(
                    selected_tile,
                    battle.units[candidate].tile,
                    direct_fire(category),
                    range,
                )
        };
        let mut center = marker
            .filter(|&candidate| reachable(&self.inner, candidate))
            .and_then(|candidate| TacticalHex::from_index(self.inner.units[candidate].tile));
        if position == 0 || position == opponents.len() {
            position = 1;
        }
        let mut cursor = position;
        let mut result = None;
        loop {
            let next = if cursor + 1 > opponents.len() {
                1
            } else {
                cursor + 1
            };
            let candidate = opponents[next - 1];
            if reachable(&self.inner, candidate) {
                if marker.is_none() {
                    center = TacticalHex::from_index(self.inner.units[candidate].tile);
                    marker = Some(candidate);
                } else {
                    result = Some(candidate);
                }
            }
            cursor = next;
            if cursor == position || result.is_some() {
                break;
            }
        }
        self.inner.units[selected].attack_target = result;
        Ok(ArmyTargetCycle {
            center,
            has_target: result.is_some(),
        })
    }
}

const TACTICAL_TERRAIN: [&str; 4] = [
    concat!(
        "333433333333333333333333333333300000033443333333333343333333133330000440000333333000044",
        "333333333300440003333333111043333133333300000333003333333000033100000000001110000000000",
        "000000100000000000000000000000010000000000000000000000000000000011010000000000000000000",
        "000000011100000000000000001000000000000000400000000000001000000000000004000000000000000",
        "000100000000100000000000000000001100044000000000000000000000000000040000000000000000000",
        "000000000000000"
    ),
    concat!(
        "100000000000000000000111111111110000000011100000000001111111100000000000100000000211111",
        "111001000000000000000022111111111001000001000000000022011111111000100011000000002220000",
        "111111100000000000000020000000011111000000000000110200000001111111000000000000002200000",
        "010111111000000000000222100000001111111000001000000222000100440011111000000001000000000",
        "000400001111000000000000000010110000001111110110011100001110000000011111110011111110010",
        "110101111101111"
    ),
    concat!(
        "000000000000400100000000000001000000000000001100000000000011110000001000011000000000000",
        "000000000000000100000000000004001000000004400100044000000000001000010004401010444000000",
        "000011040011000000010444044000000011000000000000010000000000000111100000000001000000000",
        "000000011100100000000000000110000000011110001100000000000010000000000111111000000004400",
        "000000000000111111110110000000410000000000111111110001000444144000040001111111111100011",
        "111110000100111"
    ),
    concat!(
        "041111140444414400444440440440011111404004000001000000001100001414404000000000000000000",
        "000001100000000000000040000000000000000000400000004000000000000000000044000000000000000",
        "010000410000040000000040004000000000414000044000100004000000001100114000000000444000000",
        "000000011040004000004000000000000000000440004000000140010000000000000400000000000014004",
        "001001100000040000011000000004000000000000440110000000400004000400000011100000000001110",
        "000001110000011"
    ),
];

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum TacticalUnitState {
    Ready,
    MoraleBroken,
    Retreated,
    Destroyed,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum MineRun {
    None,
    First,
    Second,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum DeployMark {
    Clear,
    UnitCover,
    FortWallLevelOne,
    FortWallLevelTwo,
    FortWallLevelThree,
}

impl DeployMark {
    const fn is_fort_wall(self) -> bool {
        matches!(
            self,
            Self::FortWallLevelOne | Self::FortWallLevelTwo | Self::FortWallLevelThree
        )
    }

    const fn is_present(self) -> bool {
        !matches!(self, Self::Clear)
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum TacticalStance {
    Hold,
    Retreat,
    Bombard,
    Siege,
    Assault,
    Standoff,
    Unopposed,
    Garrison,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
enum BattleOutcome {
    InProgress,
    AttackerWon,
    DefenderWon,
}

impl BattleSide {
    pub(crate) const fn opponent(self) -> Self {
        match self {
            Self::Attacker => Self::Defender,
            Self::Defender => Self::Attacker,
        }
    }
}

type BattleSideTable<T> = EnumMap<BattleSide, T>;

#[derive(Clone, Copy, Deserialize, Serialize)]
struct Tile {
    terrain: TacticalTerrain,
    #[serde(skip)]
    occupant: Option<usize>,
    deploy_mark: DeployMark,
    mine_run: MineRun,
    trench_mask: u8,
}

#[derive(Clone, Deserialize, Serialize)]
struct TacUnit {
    source: MilitaryUnitId,
    unit_type: MilitaryUnitKind,
    tile: i32,
    selected: bool,
    state: TacticalUnitState,
    action_points: i32,
    ai_state: i32,
    strength: i32,
    morale: i32,
    quality: i16,
    sap_target: i32,
    flag3c: bool,
    side: BattleSide,
    field24: i16,
    projection: ActionClassScores,
    #[serde(skip)]
    attack_target: Option<usize>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Side {
    is_our: bool,
    ready: bool,
    auto_play: bool,
    nation: NationId,
    cursor: i32,
    #[serde(skip)]
    units: Vec<usize>,
    #[serde(skip)]
    secondary: Vec<usize>,
    projection_sums: ActionClassScores,
    baseline_similarity: f32,
    composition_similarity: f32,
    max_range: i16,
    max_non_artillery_range: i16,
    field20: bool,
    allow_broken_targets: bool,
    has_artillery_or_engineers: bool,
    field_f: bool,
    last_stance: Option<TacticalStance>,
    retreat_toward_north: bool,
    cached_bombard_tile: i32,
}

#[derive(Clone, Deserialize, Serialize)]
struct Battle {
    #[serde(with = "tile_array")]
    tiles: [Tile; TACTICAL_TILE_COUNT],
    #[serde(skip, default = "empty_move_costs")]
    move_costs: [i16; TACTICAL_TILE_COUNT + 1],
    #[serde(skip, default = "empty_threat")]
    threat: [i8; TACTICAL_TILE_COUNT],
    #[serde(skip, default = "empty_i32_grid")]
    candidate_scores: [i32; TACTICAL_TILE_COUNT],
    #[serde(skip, default = "empty_i32_grid")]
    distance_field: [i32; TACTICAL_TILE_COUNT],
    units: Vec<TacUnit>,
    sides: BattleSideTable<Side>,
    #[serde(skip)]
    records: Vec<usize>,
    current_side: BattleSide,
    #[serde(skip)]
    selected: Option<usize>,
    column_count: i32,
    outcome: BattleOutcome,
    pending_end: bool,
    fort_level: FortLevel,
    fort_strength: [i32; 8],
    battle_site: ProvinceId,
    round: i32,
    composition_class: i32,
    live: bool,
    #[serde(skip)]
    events: Vec<ArmyBattleEvent>,
}

const fn empty_move_costs() -> [i16; TACTICAL_TILE_COUNT + 1] {
    [0; TACTICAL_TILE_COUNT + 1]
}

const fn empty_threat() -> [i8; TACTICAL_TILE_COUNT] {
    [0; TACTICAL_TILE_COUNT]
}

const fn empty_i32_grid() -> [i32; TACTICAL_TILE_COUNT] {
    [0; TACTICAL_TILE_COUNT]
}

mod tile_array {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(
        tiles: &[Tile; TACTICAL_TILE_COUNT],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        tiles.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[Tile; TACTICAL_TILE_COUNT], D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<Tile>::deserialize(deserializer)?
            .try_into()
            .map_err(|_: Vec<Tile>| D::Error::custom("army battle tile count is not retail-sized"))
    }
}

#[derive(Deserialize, Serialize)]
struct ArmyBattleState {
    battle: Battle,
    selected_unit: Option<MilitaryUnitId>,
    tile_occupants: Vec<Option<MilitaryUnitId>>,
    side_units: BattleSideTable<Vec<MilitaryUnitId>>,
    side_secondary: BattleSideTable<Vec<MilitaryUnitId>>,
    action_order: Vec<MilitaryUnitId>,
}

impl Serialize for ArmyBattle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = |index: usize| self.inner.units[index].source;
        ArmyBattleState {
            battle: self.inner.clone(),
            selected_unit: self.inner.selected.map(source),
            tile_occupants: self
                .inner
                .tiles
                .iter()
                .map(|tile| tile.occupant.map(source))
                .collect(),
            side_units: BattleSideTable::from_fn(|side| {
                self.inner.sides[side]
                    .units
                    .iter()
                    .copied()
                    .map(source)
                    .collect()
            }),
            side_secondary: BattleSideTable::from_fn(|side| {
                self.inner.sides[side]
                    .secondary
                    .iter()
                    .copied()
                    .map(source)
                    .collect()
            }),
            action_order: self.inner.records.iter().copied().map(source).collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArmyBattle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ArmyBattleState {
            mut battle,
            selected_unit,
            tile_occupants,
            side_units,
            side_secondary,
            action_order,
        } = ArmyBattleState::deserialize(deserializer)?;
        if tile_occupants.len() != TACTICAL_TILE_COUNT {
            return Err(D::Error::custom(
                "army battle tile occupant count is not retail-sized",
            ));
        }
        let resolve = |source: MilitaryUnitId| {
            battle
                .units
                .iter()
                .position(|unit| unit.source == source)
                .ok_or_else(|| D::Error::custom("army battle references an unknown source unit"))
        };
        battle.selected = selected_unit.map(resolve).transpose()?;
        for (tile, occupant) in battle.tiles.iter_mut().zip(tile_occupants) {
            tile.occupant = occupant.map(resolve).transpose()?;
        }
        for side in [BattleSide::Attacker, BattleSide::Defender] {
            battle.sides[side].units = side_units[side]
                .iter()
                .copied()
                .map(resolve)
                .collect::<Result<_, _>>()?;
            battle.sides[side].secondary = side_secondary[side]
                .iter()
                .copied()
                .map(resolve)
                .collect::<Result<_, _>>()?;
        }
        battle.records = action_order
            .into_iter()
            .map(resolve)
            .collect::<Result<_, _>>()?;
        if battle.live
            && let Some(selected) = battle.selected
        {
            battle.compute_reachable(selected);
        }
        Ok(Self { inner: battle })
    }
}

impl GameState {
    #[cfg(feature = "oracle")]
    pub(crate) fn auto_deploy_army_battle_for_differential(&mut self) {
        self.ensure_army_battle();
        let mut battle = self.take_army_battle().expect("live army battle");
        while !battle.inner.live {
            let side = battle.inner.current_side;
            battle.inner.sides[side].auto_play = true;
            battle.inner.auto_deploy(self, side);
            battle.inner.handover_deployment(self);
        }
        for side in [BattleSide::Attacker, BattleSide::Defender] {
            battle.inner.sides[side].auto_play =
                battle.inner.sides[side].nation != self.turn.active_nation;
        }
        assert!(!battle.inner.pump_until_active_input(self));
        self.store_army_battle(battle);
    }

    #[cfg(feature = "oracle")]
    pub(crate) fn army_battle_differential_snapshot(
        &self,
    ) -> Option<crate::differential::ArmyBattleSnapshot> {
        use crate::differential::{ArmyBattleSnapshot, ArmyBattleUnitSnapshot};

        let battle = &self.army_battle()?.inner;
        let mut units = battle
            .units
            .iter()
            .map(|unit| ArmyBattleUnitSnapshot {
                source: unit.source,
                side: match unit.side {
                    BattleSide::Attacker => 0,
                    BattleSide::Defender => 1,
                },
                tile: unit.tile,
                action_points: unit.action_points,
                strength: unit.strength,
                morale: unit.morale,
                state: match unit.state {
                    TacticalUnitState::Ready => 0,
                    TacticalUnitState::MoraleBroken => 1,
                    TacticalUnitState::Retreated => 2,
                    TacticalUnitState::Destroyed => 3,
                },
            })
            .collect::<Vec<_>>();
        units.sort_by_key(|unit| unit.source.get());
        Some(ArmyBattleSnapshot {
            selected: battle.selected.map(|unit| battle.units[unit].source),
            current_side: match battle.current_side {
                BattleSide::Attacker => 0,
                BattleSide::Defender => 1,
            },
            round: battle.round,
            outcome: match battle.outcome {
                BattleOutcome::InProgress => 0,
                BattleOutcome::AttackerWon => 1,
                BattleOutcome::DefenderWon => 2,
            },
            units,
            fort_strength: battle.fort_strength,
            crt_rand: self.rng.crt_rand.state(),
        })
    }

    /// Applies retail's tactical-battle preference and participant watch flags.
    /// Unwatched battles run headlessly until the next observable turn stop.
    pub fn apply_land_battle_watch_policy(
        &mut self,
        mut stop: TurnStop,
        tactical_battles_enabled: bool,
    ) -> TurnStop {
        while stop == TurnStop::LandBattle
            && !self.pending_land_battle_is_watched(tactical_battles_enabled)
        {
            stop = self.auto_resolve_land_battle();
        }
        stop
    }

    fn pending_land_battle_is_watched(&self, tactical_battles_enabled: bool) -> bool {
        if !tactical_battles_enabled {
            return false;
        }
        let battle = self
            .pending_land_battle()
            .expect("land-battle stop retains its participants");
        [battle.attacker_nation, battle.defender_nation]
            .into_iter()
            .filter_map(MajorNationId::from_nation)
            .any(|nation| self.nations.major(nation).economy.diplomacy_eligible)
    }

    /// Headless retail Auto: TArmyPlayer auto-deploy + Auto turn pump + ApplyChanges
    /// + ApplyPostBattleStackOutcomeAndGrowUnitMeters, then remaining combat-moves.
    pub fn auto_resolve_land_battle(&mut self) -> TurnStop {
        let crate::turn_flow::TurnFlow::LandBattle(_) = &self.turn_flow else {
            panic!("land-battle auto-resolve requires a combat-moves continuation");
        };
        let mut battle = match self.take_army_battle() {
            Some(mut live) => {
                let was_live = live.inner.live;
                if !was_live {
                    let side = live.inner.current_side;
                    live.inner.sides[side].auto_play = true;
                    live.inner.auto_deploy(self, side);
                    live.inner.handover_deployment(self);
                }
                if was_live && live.inner.outcome == BattleOutcome::InProgress {
                    live.inner.advance_auto_pulse(self, live.inner.current_side);
                }
                live.inner
            }
            None => {
                let mut battle = Battle::init(self);
                battle.sides[BattleSide::Attacker].auto_play = true;
                battle.sides[BattleSide::Defender].auto_play = true;
                battle.start(self);
                battle
            }
        };
        let mut guard = 20_000;
        loop {
            assert!(guard > 0, "tactical auto did not terminate");
            guard -= 1;
            if battle.next_move(self) {
                break;
            }
        }
        self.resume_after_land_battle()
    }

    pub fn army_battle(&self) -> Option<&ArmyBattle> {
        match &self.turn_flow {
            crate::turn_flow::TurnFlow::LandBattle(continuation) => {
                continuation.army_battle.as_deref()
            }
            _ => None,
        }
    }

    #[cfg(test)]
    fn army_battle_mut(&mut self) -> Option<&mut ArmyBattle> {
        match &mut self.turn_flow {
            crate::turn_flow::TurnFlow::LandBattle(continuation) => {
                continuation.army_battle.as_deref_mut()
            }
            _ => None,
        }
    }

    /// Opens the pending land battle and pumps to local deployment or live input.
    pub fn ensure_army_battle(&mut self) -> &ArmyBattle {
        let stop = self
            .synchronize_army_battle()
            .and_then(|progress| progress.stop);
        assert!(
            stop.is_none(),
            "interactive army battle ended before reaching local input"
        );
        self.army_battle()
            .expect("interactive army battle was just stored")
    }

    /// Creates the live battle for the current combat-moves continuation, if needed.
    ///
    /// Returns a turn stop only if forced/opponent actions finish the battle before
    /// the active nation receives input.
    pub fn synchronize_army_battle(&mut self) -> Option<ArmyBattleProgress> {
        if self.army_battle().is_some() {
            return None;
        }
        let crate::turn_flow::TurnFlow::LandBattle(_) = &self.turn_flow else {
            return None;
        };
        let mut inner = Battle::init(self);
        inner.start(self);
        if inner.live && inner.pump_until_active_input(self) {
            let events = std::mem::take(&mut inner.events);
            return Some(ArmyBattleProgress {
                stop: Some(self.resume_after_land_battle()),
                events,
            });
        }
        let events = std::mem::take(&mut inner.events);
        self.store_army_battle(ArmyBattle { inner });
        Some(ArmyBattleProgress { stop: None, events })
    }

    pub fn selected_army_unit(&self) -> Option<ArmyUnitView> {
        let battle = self.army_battle()?;
        battle.selected_unit().and_then(|id| battle.unit(id))
    }

    pub fn selected_army_unit_reachable_hexes(&self) -> Vec<TacticalHex> {
        let active_nation = self.turn.active_nation;
        match self.army_battle() {
            Some(battle) => battle.selected_unit_reachable_hexes(active_nation),
            None => Vec::new(),
        }
    }

    pub fn army_action_at(
        &mut self,
        target: TacticalHex,
    ) -> Result<(ArmyAction, ArmyBattleProgress), ArmyActionRejection> {
        let active_nation = self.turn.active_nation;
        let Some(mut battle) = self.take_army_battle() else {
            return Err(ArmyActionRejection::NoLiveBattle);
        };
        let result = match battle.action_at(target, active_nation, self) {
            Ok(result) => result,
            Err(error) => {
                self.store_army_battle(battle);
                return Err(error);
            }
        };
        if !battle.inner.live {
            if battle.inner.sides[battle.inner.current_side].ready {
                battle.inner.handover_deployment(self);
            }
            if !battle.inner.live {
                let events = std::mem::take(&mut battle.inner.events);
                self.store_army_battle(battle);
                return Ok((result, ArmyBattleProgress { stop: None, events }));
            }
        }
        let progress = self.finish_interactive_army_action(battle);
        Ok((result, progress))
    }

    pub fn finish_selected_army_unit_action(
        &mut self,
    ) -> Result<ArmyBattleProgress, ArmyActionRejection> {
        let active_nation = self.turn.active_nation;
        let Some(mut battle) = self.take_army_battle() else {
            return Err(ArmyActionRejection::NoLiveBattle);
        };
        if let Err(error) = battle.selected_unit_for_action(active_nation) {
            self.store_army_battle(battle);
            return Err(error);
        }
        if !battle.inner.live {
            let side = battle.inner.current_side;
            battle.inner.selected = battle.inner.select_next_undeployed(side);
            battle.inner.clear_move_costs();
            let events = std::mem::take(&mut battle.inner.events);
            self.store_army_battle(battle);
            return Ok(ArmyBattleProgress { stop: None, events });
        }
        battle.inner.finish_action();
        Ok(self.finish_interactive_army_action(battle))
    }

    pub fn cycle_selected_army_target(&mut self) -> Result<ArmyTargetCycle, ArmyActionRejection> {
        let active_nation = self.turn.active_nation;
        let Some(mut battle) = self.take_army_battle() else {
            return Err(ArmyActionRejection::NoLiveBattle);
        };
        let result = battle.cycle_target(active_nation);
        self.store_army_battle(battle);
        result
    }

    pub fn auto_play_army_battle_side(
        &mut self,
    ) -> Result<ArmyBattleProgress, ArmyActionRejection> {
        let active_nation = self.turn.active_nation;
        let Some(mut battle) = self.take_army_battle() else {
            return Err(ArmyActionRejection::NoLiveBattle);
        };
        let side = battle.inner.current_side;
        if let Err(error) = battle.selected_unit_for_action(active_nation) {
            self.store_army_battle(battle);
            return Err(error);
        }
        battle.inner.sides[side].auto_play = true;
        if !battle.inner.live {
            battle.inner.auto_deploy(self, side);
            battle.inner.handover_deployment(self);
            if !battle.inner.live {
                let events = std::mem::take(&mut battle.inner.events);
                self.store_army_battle(battle);
                return Ok(ArmyBattleProgress { stop: None, events });
            }
        } else {
            battle.inner.select_and_apply_cursor_mode(self, side);
            battle.inner.advance_auto_pulse(self, side);
        }
        Ok(self.finish_interactive_army_action(battle))
    }

    pub fn skip_selected_army_unit_action(
        &mut self,
    ) -> Result<ArmyBattleProgress, ArmyActionRejection> {
        let active_nation = self.turn.active_nation;
        let Some(mut battle) = self.take_army_battle() else {
            return Err(ArmyActionRejection::NoLiveBattle);
        };
        let selected = match battle.selected_unit_for_action(active_nation) {
            Ok(selected) => selected,
            Err(error) => {
                self.store_army_battle(battle);
                return Err(error);
            }
        };
        if battle.inner.units[selected].unit_type.tactical_category() == ArmyUnitCategory::Engineers
        {
            let events = std::mem::take(&mut battle.inner.events);
            self.store_army_battle(battle);
            return Ok(ArmyBattleProgress { stop: None, events });
        }
        battle.inner.sides[battle.inner.current_side].field20 = true;
        battle.inner.finish_action();
        Ok(self.finish_interactive_army_action(battle))
    }

    pub fn retreat_from_army_battle(&mut self) -> Result<ArmyBattleProgress, ArmyActionRejection> {
        let active_nation = self.turn.active_nation;
        let Some(mut battle) = self.take_army_battle() else {
            return Err(ArmyActionRejection::NoLiveBattle);
        };
        if let Err(error) = battle.selected_unit_for_action(active_nation) {
            self.store_army_battle(battle);
            return Err(error);
        }
        if !battle.inner.live {
            battle.inner.handover_deployment(self);
            if !battle.inner.live {
                let events = std::mem::take(&mut battle.inner.events);
                self.store_army_battle(battle);
                return Ok(ArmyBattleProgress { stop: None, events });
            }
            return Ok(self.finish_interactive_army_action(battle));
        }
        let side = battle.inner.current_side;
        battle.inner.sides[side].field_f = true;
        battle.inner.sides[side].auto_play = true;
        battle.inner.sides[side].last_stance = None;
        battle.inner.select_and_apply_cursor_mode(self, side);
        battle.inner.advance_auto_pulse(self, side);
        Ok(self.finish_interactive_army_action(battle))
    }

    fn finish_interactive_army_action(&mut self, mut battle: ArmyBattle) -> ArmyBattleProgress {
        let ended = battle.inner.pump_until_active_input(self);
        let events = std::mem::take(&mut battle.inner.events);
        let stop = if ended {
            Some(self.resume_after_land_battle())
        } else {
            self.store_army_battle(battle);
            None
        };
        ArmyBattleProgress { stop, events }
    }

    fn take_army_battle(&mut self) -> Option<ArmyBattle> {
        match &mut self.turn_flow {
            crate::turn_flow::TurnFlow::LandBattle(continuation) => {
                continuation.army_battle.take().map(|battle| *battle)
            }
            _ => None,
        }
    }

    fn store_army_battle(&mut self, battle: ArmyBattle) {
        let crate::turn_flow::TurnFlow::LandBattle(continuation) = &mut self.turn_flow else {
            panic!("interactive army battle requires a combat-moves continuation");
        };
        continuation.army_battle = Some(Box::new(battle));
    }
}

impl Battle {
    fn init(state: &mut GameState) -> Self {
        let battle = state
            .pending_land_battle()
            .cloned()
            .expect("auto-resolve requires a pending land battle");
        let fort_level = state.map.provinces[battle.province].fort_level();
        let composition = classify_city_gate_terrain(state, battle.province);

        let empty_side = |is_our: bool, nation: NationId, retreat_toward_north: bool| Side {
            is_our,
            ready: false,
            auto_play: nation != state.turn.active_nation,
            nation,
            cursor: 0,
            units: Vec::new(),
            secondary: Vec::new(),
            projection_sums: ActionClassScores::default(),
            baseline_similarity: 0.0,
            composition_similarity: 0.0,
            max_range: 0,
            max_non_artillery_range: 0,
            field20: false,
            allow_broken_targets: false,
            has_artillery_or_engineers: false,
            field_f: false,
            last_stance: None,
            retreat_toward_north,
            cached_bombard_tile: -1,
        };
        let our_retreat_toward_north = state.rng.next_crt_rand() & 1 != 0;
        let enemy_retreat_toward_north = state.rng.next_crt_rand() & 1 != 0;
        let mut this = Self {
            tiles: [Tile {
                terrain: TacticalTerrain::Class0,
                occupant: None,
                deploy_mark: DeployMark::Clear,
                mine_run: MineRun::None,
                trench_mask: 0,
            }; TACTICAL_TILE_COUNT],
            move_costs: [-1; TACTICAL_TILE_COUNT + 1],
            threat: [0; TACTICAL_TILE_COUNT],
            candidate_scores: [0; TACTICAL_TILE_COUNT],
            distance_field: [0; TACTICAL_TILE_COUNT],
            units: Vec::new(),
            sides: BattleSideTable::from_array([
                empty_side(true, battle.attacker_nation, our_retreat_toward_north),
                empty_side(false, battle.defender_nation, enemy_retreat_toward_north),
            ]),
            records: Vec::new(),
            current_side: BattleSide::Defender,
            selected: None,
            column_count: 0,
            outcome: BattleOutcome::InProgress,
            pending_end: false,
            fort_level,
            fort_strength: [0; 8],
            battle_site: battle.province,
            round: 0,
            composition_class: composition,
            live: false,
            events: Vec::new(),
        };

        for &id in &battle.attacker_units {
            if !state.military_units.contains_key(&id) {
                continue;
            }
            this.push_unit(state, id, BattleSide::Attacker, false);
        }
        for &id in &battle.defender_units {
            if !state.military_units.contains_key(&id) {
                continue;
            }
            this.push_unit(state, id, BattleSide::Defender, true);
        }

        for unit in &mut this.units {
            unit.field24 = state.rng.next_crt_rand() as i16;
        }
        this.records.extend(
            this.units
                .iter()
                .enumerate()
                .filter(|(_, unit)| unit.side == BattleSide::Attacker)
                .map(|(idx, _)| idx),
        );
        this.records.extend(
            this.units
                .iter()
                .enumerate()
                .filter(|(_, unit)| unit.side == BattleSide::Defender)
                .map(|(idx, _)| idx),
        );

        this.selected = this.select_next_undeployed(BattleSide::Defender);
        let mut max_range = 0;
        for &idx in &this.records {
            let range = this.unit_range(idx);
            if range > max_range {
                max_range = range;
            }
        }
        this.column_count = max_range + 11;
        this.load_setup(composition);
        this
    }

    fn push_unit(
        &mut self,
        state: &GameState,
        source: MilitaryUnitId,
        side: BattleSide,
        enemy_selected: bool,
    ) {
        let unit = &state.military_units[&source];
        let unit_type = unit.unit_type;
        let mut record = TacUnit {
            source,
            unit_type,
            tile: -2,
            selected: enemy_selected,
            state: TacticalUnitState::Ready,
            action_points: BASE_ACTION_POINTS[unit_type],
            ai_state: 0,
            strength: i32::from(unit.strength),
            morale: i32::from(unit.strength),
            quality: unit.experience / 100,
            sap_target: -1,
            flag3c: unit.order.code() == MilitaryOrderCode::Sleep
                && combat_category(unit.unit_type) == TacticalCombatClass::Infantry,
            side,
            field24: 0,
            projection: ActionClassScores::default(),
            attack_target: None,
        };
        record.action_points = record.base_action_points();
        let idx = self.units.len();
        self.units.push(record);
        self.sides[side].units.push(idx);
    }

    fn load_setup(&mut self, composition: i32) {
        for tile in &mut self.tiles {
            *tile = Tile {
                terrain: TacticalTerrain::Class0,
                occupant: None,
                deploy_mark: DeployMark::Clear,
                mine_run: MineRun::None,
                trench_mask: 0,
            };
        }
        let terrain = TACTICAL_TERRAIN[composition as usize].as_bytes();
        let margin = (TACTICAL_STRIDE - self.column_count) as usize;
        for row in 0..TACTICAL_ROWS as usize {
            for column in 0..self.column_count as usize {
                let source_column = margin + column;
                let terrain = if self.fort_level != FortLevel::None && source_column > 23 {
                    b'0'
                } else {
                    terrain[row * (TACTICAL_STRIDE as usize + 1) + source_column]
                };
                self.tiles[row * TACTICAL_STRIDE as usize + column].terrain = match terrain {
                    b'0' => TacticalTerrain::Class0,
                    b'1' => TacticalTerrain::Class1,
                    b'2' => TacticalTerrain::Class2,
                    b'3' => TacticalTerrain::Class3,
                    b'4' => TacticalTerrain::Impassable,
                    _ => unreachable!("retail tactical terrain uses classes 0 through 4"),
                };
            }
        }
        let (wall, points) = match self.fort_level {
            FortLevel::None => return,
            FortLevel::One => (
                DeployMark::FortWallLevelOne,
                FORT_STRENGTH_BY_LEVEL[FortLevel::One],
            ),
            FortLevel::Two => (
                DeployMark::FortWallLevelTwo,
                FORT_STRENGTH_BY_LEVEL[FortLevel::Two],
            ),
            FortLevel::Three => (
                DeployMark::FortWallLevelThree,
                FORT_STRENGTH_BY_LEVEL[FortLevel::Three],
            ),
        };
        {
            let mut tile = self.column_count - 6;
            while tile < TACTICAL_TILE_COUNT as i32 {
                self.tiles[tile as usize].deploy_mark = wall;
                tile += TACTICAL_STRIDE;
            }
            self.fort_strength = [points; 8];
        }
    }

    fn start(&mut self, state: &mut GameState) {
        self.start_side(state, BattleSide::Defender);
        if self.sides[BattleSide::Defender].ready {
            self.handover_deployment(state);
        }
    }

    fn start_side(&mut self, state: &mut GameState, side: BattleSide) {
        self.current_side = side;
        self.selected = self.select_next_undeployed(side);
        if self.sides[side].auto_play {
            self.select_and_apply_cursor_mode(state, side);
            self.auto_deploy(state, side);
        }
    }

    fn handover_deployment(&mut self, state: &mut GameState) {
        let incoming = self.current_side.opponent();
        self.current_side = incoming;
        self.selected = self.select_next_undeployed(incoming);
        if self.sides[incoming].ready {
            self.finalize_turn_state(state);
            return;
        }
        self.start_side(state, incoming);
        if self.sides[incoming].ready {
            let next = incoming.opponent();
            self.current_side = next;
            self.selected = self.select_next_undeployed(next);
            if self.sides[next].ready {
                self.finalize_turn_state(state);
            }
        }
    }

    fn auto_deploy(&mut self, state: &mut GameState, side: BattleSide) {
        self.current_side = side;
        let free = self.count_free_deploy_tiles();
        if self.sides[side].units.len() as i32 > free {
            self.prune_to(state, side, free);
        }
        if self.sides[side].is_our {
            self.deploy_attacker(state, side);
        } else {
            self.deploy_defender(state, side);
        }
        self.sides[side].ready = true;
    }

    fn deploy_attacker(&mut self, state: &mut GameState, side: BattleSide) {
        self.sort_side_units(state, side, compare_deploy_priority);
        let units = self.sides[side].units.clone();
        for idx in units {
            let mut best_score = 0;
            let mut best_tile = -1;
            for tile in 0..TACTICAL_TILE_COUNT as i32 {
                if self.deploy_guard(tile) == 0 {
                    continue;
                }
                let row = tile / TACTICAL_STRIDE;
                let column = tile % TACTICAL_STRIDE;
                let score_slot = usize::try_from(11 - 2 * column - (row & 1))
                    .expect("attacker deployment column has a score slot");
                let mut score =
                    ATTACKER_DEPLOY_ZONE_SCORES[AI_CLASS[self.units[idx].unit_type]][score_slot];
                let mut edge = row;
                if edge > 7 {
                    edge = TACTICAL_ROWS - edge;
                }
                score += edge;
                if score > best_score {
                    best_score = score;
                    best_tile = tile;
                }
            }
            self.deploy_to_tile(idx, best_tile);
        }
    }

    fn deploy_defender(&mut self, state: &mut GameState, side: BattleSide) {
        self.sort_side_units(state, side, compare_deploy_priority);
        let units = self.sides[side].units.clone();
        for idx in units {
            let tile = match AI_CLASS[self.units[idx].unit_type] {
                TacticalCombatClass::Infantry => self.select_defender_melee_tile(),
                TacticalCombatClass::Artillery => self.select_defender_artillery_tile(),
                _ => self.select_defender_other_tile(),
            };
            self.deploy_to_tile(idx, tile);
        }
    }

    fn select_defender_artillery_tile(&mut self) -> i32 {
        let mut best_score = 0;
        let mut best_tile = -1;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.deploy_guard(tile) == 0 {
                continue;
            }
            let row = tile / TACTICAL_STRIDE;
            let column = tile % TACTICAL_STRIDE;
            let zone_cell = (row & 1) + 2 * (column - self.column_count) + 10;
            let mut score = if zone_cell == 0 {
                10
            } else {
                (7 - zone_cell) * 10
            };
            let mut row_distance = row;
            if row_distance > 7 {
                row_distance = TACTICAL_ROWS - row_distance;
            }
            score += row_distance;
            let mut adjacent_artillery = 0;
            let neighbors = self.neighbors(tile);
            for &neighbor in neighbors.values() {
                if neighbor == -1 {
                    continue;
                }
                if let Some(occupant) = self.tiles[neighbor as usize].occupant
                    && AI_CLASS[self.units[occupant].unit_type] == TacticalCombatClass::Artillery
                {
                    adjacent_artillery = 0x64;
                }
            }
            score += adjacent_artillery;
            self.candidate_scores[tile as usize] = score;
            if score > best_score {
                best_score = score;
                best_tile = tile;
            }
        }
        best_tile
    }

    fn select_defender_melee_tile(&self) -> i32 {
        let mut best_score = 0;
        let mut best_tile = -1;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.deploy_guard(tile) == 0 {
                continue;
            }
            let row = tile / TACTICAL_STRIDE;
            let column = tile % TACTICAL_STRIDE;
            let mut score = (2 * (self.column_count - column) - (row & 1) - 3) * 10;
            let mut row_distance = row;
            if row_distance > 7 {
                row_distance = TACTICAL_ROWS - row_distance;
            }
            score += row_distance;
            let neighbors = self.neighbors(tile);
            let mut adjacency = 0;
            for &neighbor in neighbors.values() {
                if neighbor == -1 {
                    continue;
                }
                if let Some(occupant) = self.tiles[neighbor as usize].occupant {
                    if AI_CLASS[self.units[occupant].unit_type] == TacticalCombatClass::Artillery {
                        adjacency = 0x64;
                    } else if adjacency == 0 {
                        adjacency = 0xa;
                    }
                }
            }
            score += adjacency;
            if score > best_score {
                best_score = score;
                best_tile = tile;
            }
        }
        best_tile
    }

    fn select_defender_other_tile(&self) -> i32 {
        let mut best_score = 0;
        let mut best_tile = -1;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.deploy_guard(tile) == 0 {
                continue;
            }
            let mut row = tile / TACTICAL_STRIDE;
            let mut score = (self.column_count - 5) * 20;
            if row > 7 {
                row = TACTICAL_ROWS - row;
            }
            score += row;
            let neighbors = self.neighbors(tile);
            let mut occupied = 0;
            for &neighbor in neighbors.values() {
                if occupied != 0 {
                    break;
                }
                if neighbor != -1 && self.tiles[neighbor as usize].occupant.is_some() {
                    occupied = 0xa;
                }
            }
            score += occupied;
            if score > best_score {
                best_score = score;
                best_tile = tile;
            }
        }
        best_tile
    }

    fn deploy_to_tile(&mut self, unit: usize, tile: i32) {
        let column = tile % TACTICAL_STRIDE;
        if tile < TACTICAL_STRIDE {
            return;
        }
        if self.tiles[tile as usize].terrain == TacticalTerrain::Impassable {
            return;
        }
        if self.tiles[tile as usize].occupant.is_some() {
            return;
        }
        if self.current_side == BattleSide::Attacker {
            if !(3..=5).contains(&column) {
                return;
            }
        } else if column > self.column_count - 3 || column < self.column_count - 5 {
            return;
        }
        self.place_deployed(unit, tile);
        let side = self.current_side;
        self.selected = self.select_next_undeployed(side);
        self.clear_move_costs();
    }

    fn place_deployed(&mut self, unit: usize, tile: i32) {
        self.units[unit].tile = tile;
        self.tiles[tile as usize].occupant = Some(unit);
        if self.units[unit].flag3c && self.fort_level == FortLevel::None {
            self.tiles[tile as usize].deploy_mark = DeployMark::UnitCover;
        }
    }

    fn finalize_turn_state(&mut self, state: &mut GameState) {
        self.retire_undeployed(BattleSide::Attacker);
        self.retire_undeployed(BattleSide::Defender);
        self.sort_records(state);
        self.selected = self.records.last().copied();
        self.live = true;
        self.pending_end = false;
    }

    fn retire_undeployed(&mut self, side: BattleSide) {
        let mut ordinal = self.sides[side].units.len() as i32;
        while ordinal > 0 {
            let idx = self.sides[side].units[(ordinal - 1) as usize];
            if self.units[idx].tile == -2 {
                self.sides[side].units.remove((ordinal - 1) as usize);
                self.sides[side].secondary.insert(0, idx);
            }
            ordinal -= 1;
        }
        for &retired in &self.sides[side].secondary {
            if let Some(pos) = self.records.iter().position(|&idx| idx == retired) {
                self.records.remove(pos);
            }
        }
    }

    fn selected_unit_is_controlled(&self, active_nation: NationId) -> bool {
        self.selected.is_some_and(|unit| {
            self.units[unit].side == self.current_side
                && self.sides[self.current_side].nation == active_nation
                && !self.sides[self.current_side].auto_play
                && self.units[unit].state == TacticalUnitState::Ready
        })
    }

    /// Synchronous `TNextMoveCommand::DoIt` pump for an interactive battle.
    /// Returns true after committing a terminal battle, false at local input.
    fn pump_until_active_input(&mut self, state: &mut GameState) -> bool {
        let mut guard = 20_000;
        loop {
            assert!(
                guard > 0,
                "interactive tactical pump did not reach an input boundary"
            );
            guard -= 1;
            if self.outcome != BattleOutcome::InProgress {
                self.commit_outcome(state);
                return true;
            }
            if self.pending_end {
                if self.selected_unit_is_controlled(state.turn.active_nation) {
                    return false;
                }
                self.advance_auto_pulse(state, self.current_side);
                continue;
            }
            self.pending_end = true;
            self.advance_turn_step(state, true);
        }
    }

    fn select_next_record_unit(&mut self) -> Option<usize> {
        let mut position = if let Some(selected) = self.selected {
            1 + self
                .records
                .iter()
                .position(|&idx| idx == selected)
                .unwrap_or(0) as i32
        } else {
            1
        };
        loop {
            let total = self.records.len() as i32;
            if total == 0 {
                return None;
            }
            if position == total {
                self.round += 1;
                if self.round >= 0x23 {
                    self.evaluate_outcome();
                    self.finish_action();
                    return None;
                }
                position = 1;
            } else {
                position += 1;
            }
            let idx = self.records[(position - 1) as usize];
            if self.units[idx].state != TacticalUnitState::Destroyed {
                return Some(idx);
            }
        }
    }

    fn next_move(&mut self, state: &mut GameState) -> bool {
        if self.outcome != BattleOutcome::InProgress {
            self.commit_outcome(state);
            return true;
        }
        self.pending_end = true;
        self.advance_turn_step(state, false);
        false
    }

    fn commit_outcome(&mut self, state: &mut GameState) {
        let attacker_won = self.outcome == BattleOutcome::AttackerWon;
        let destroyed = self.apply_changes(state);
        state.resolve_land_battle(attacker_won);
        for source in destroyed {
            detach_unit(state, source);
        }
    }

    fn finish_action(&mut self) {
        self.pending_end = false;
    }

    fn advance_turn_step(&mut self, state: &mut GameState, stop_for_active_nation: bool) {
        let Some(candidate) = self.select_next_record_unit() else {
            return;
        };
        self.set_current_selection(candidate);
        if self.units[candidate].state == TacticalUnitState::MoraleBroken {
            self.process_morale_broken(state, candidate);
            return;
        }
        if self.units[candidate].unit_type.tactical_category() == ArmyUnitCategory::Engineers
            && self.units[candidate].sap_target != -1
        {
            self.advance_mine_run(candidate);
            return;
        }
        self.current_side = self.units[candidate].side;
        if stop_for_active_nation && self.selected_unit_is_controlled(state.turn.active_nation) {
            return;
        }
        self.advance_auto_pulse(state, self.current_side);
    }

    fn set_current_selection(&mut self, unit: usize) {
        self.current_side = self.units[unit].side;
        self.units[unit].action_points = self.units[unit].base_action_points();
        self.units[unit].selected = true;
        self.selected = Some(unit);
        self.compute_reachable(unit);
    }

    fn apply_changes(&mut self, state: &mut GameState) -> Vec<MilitaryUnitId> {
        let mut destroyed = Vec::new();
        for side in [BattleSide::Attacker, BattleSide::Defender] {
            let lists = [
                self.sides[side].units.clone(),
                self.sides[side].secondary.clone(),
            ];
            for list in lists {
                for idx in list {
                    let source = self.units[idx].source;
                    let strength = self.units[idx].strength as i16;
                    state.military_units[&source].strength = strength;
                    if strength == 0 {
                        destroyed.push(source);
                    }
                }
            }
        }
        destroyed
    }
}

fn detach_unit(state: &mut GameState, id: MilitaryUnitId) {
    for mission in state.missions.values_mut() {
        match &mut mission.data {
            MissionData::DefendProvince { army, .. }
            | MissionData::AttackProvince(AttackMissionState { army, .. })
            | MissionData::Invade {
                attack: AttackMissionState { army, .. },
                ..
            } => {
                army.units.shift_remove(&id);
            }
            _ => {}
        }
    }
    state.military_units.shift_remove(&id);
}

fn combat_category(kind: MilitaryUnitKind) -> TacticalCombatClass {
    AI_CLASS[kind]
}

fn general(kind: MilitaryUnitKind) -> bool {
    matches!(
        kind,
        MilitaryUnitKind::GeneralEra1
            | MilitaryUnitKind::GeneralEra2
            | MilitaryUnitKind::GeneralEra3
    )
}

fn category_value(category: ArmyUnitCategory) -> i32 {
    match category {
        ArmyUnitCategory::Garrison
        | ArmyUnitCategory::LightInfantry
        | ArmyUnitCategory::LineInfantry
        | ArmyUnitCategory::EliteInfantry => 0x1f4,
        ArmyUnitCategory::LightCavalry => 0x258,
        ArmyUnitCategory::HeavyCavalry => 0x2bc,
        ArmyUnitCategory::FieldArtillery => 0x320,
        ArmyUnitCategory::SiegeArtillery => 0x384,
        ArmyUnitCategory::Engineers => 0x64,
        ArmyUnitCategory::Generals => 0x190,
    }
}

fn direct_fire(category: ArmyUnitCategory) -> bool {
    !matches!(
        category,
        ArmyUnitCategory::FieldArtillery | ArmyUnitCategory::SiegeArtillery
    )
}

fn cover_damage(category: ArmyUnitCategory, mark: DeployMark) -> f32 {
    match mark {
        DeployMark::Clear => COVER_DAMAGE[category][0],
        DeployMark::UnitCover => COVER_DAMAGE[category][1],
        DeployMark::FortWallLevelOne => COVER_DAMAGE[category][2],
        DeployMark::FortWallLevelTwo => COVER_DAMAGE[category][3],
        DeployMark::FortWallLevelThree => COVER_DAMAGE[category][4],
    }
}

fn classify_city_gate_terrain(state: &GameState, province: ProvinceId) -> i32 {
    let city = &state.map.provinces[province];
    if let Some(tile) = city.city_tile()
        && state.map[tile].flags.has_base_transport()
    {
        return 3;
    }
    let mut tally_a = 0;
    let mut tally_b = 0;
    let mut tally_c = 0;
    for &tile in &city.linked_tiles {
        let gate = i32::from(state.map[tile].gate);
        if !(1..=15).contains(&gate) {
            continue;
        }
        match GATE_FLAG_SCORE_BUCKET[(gate - 1) as usize] {
            0 => tally_b += 1,
            1 => tally_b += 2,
            2 => tally_a += 2,
            3 => tally_a += 4,
            4 => tally_c += 6,
            _ => {}
        }
    }
    if tally_c > tally_a && tally_c > tally_b {
        2
    } else if tally_a > tally_b {
        1
    } else {
        0
    }
}

fn composition_row(row: usize) -> ActionClassWeights {
    match row {
        1 => TACTICAL_COMPOSITION.fort_siege,
        2 => TACTICAL_COMPOSITION.open_field,
        3 => TACTICAL_COMPOSITION.fort_garrison,
        _ => TACTICAL_COMPOSITION.baseline,
    }
}

fn compare_deploy_priority(a: &TacUnit, b: &TacUnit) -> i16 {
    const PRIORITY: TacticalCombatClassTable<i16> =
        TacticalCombatClassTable::from_array([1, 0, 2, 0, 0]);
    let priority_a = PRIORITY[AI_CLASS[a.unit_type]];
    let priority_b = PRIORITY[AI_CLASS[b.unit_type]];
    if priority_a < priority_b {
        1
    } else {
        -i16::from(priority_a != priority_b)
    }
}

fn compare_turn_order(a: &TacUnit, b: &TacUnit) -> i16 {
    let ap_a = a.base_action_points();
    let ap_b = b.base_action_points();
    if ap_b < ap_a {
        return -1;
    }
    if ap_b > ap_a {
        return 1;
    }
    if b.quality < a.quality {
        return -1;
    }
    if b.quality > a.quality {
        return 1;
    }
    i16::from(a.field24 <= b.field24) * 2 - 1
}

fn hex_distance(a: i32, b: i32) -> i32 {
    let row_a = a / TACTICAL_STRIDE;
    let mut col_a = (row_a & 1) + (a % TACTICAL_STRIDE) * 2;
    let mut row_b = b / TACTICAL_STRIDE;
    let mut col_b = (row_b & 1) + (b % TACTICAL_STRIDE) * 2;
    if col_b < col_a {
        col_b = col_a * 2 - col_b;
    }
    if row_b < row_a {
        row_b = row_a * 2 - row_b;
    }
    let row_delta = row_b - row_a;
    col_a = (col_b - row_delta) - col_a;
    if col_a > 0 {
        col_a / 2 + row_delta
    } else {
        row_delta
    }
}

impl TacUnit {
    fn base_action_points(&self) -> i32 {
        BASE_ACTION_POINTS[self.unit_type]
    }
}

impl Battle {
    fn unit_range(&self, idx: usize) -> i32 {
        let mut range = UNIT_RANGE[self.units[idx].unit_type];
        if self.units[idx].side == BattleSide::Defender
            && combat_category_of(self.units[idx].unit_type) == TacticalCombatClass::Artillery
        {
            range += 1;
        }
        range
    }

    fn cost(&self, tile: i32) -> i16 {
        self.move_costs[(tile + 1) as usize]
    }

    fn set_cost(&mut self, tile: i32, value: i16) {
        self.move_costs[(tile + 1) as usize] = value;
    }

    fn clear_move_costs(&mut self) {
        self.move_costs = [-1; TACTICAL_TILE_COUNT + 1];
    }

    fn neighbors(&self, tile: i32) -> HexDirectionTable<i32> {
        neighbor_list(tile)
    }

    fn deploy_guard(&self, tile: i32) -> u8 {
        let column = tile % TACTICAL_STRIDE;
        if tile < TACTICAL_STRIDE {
            return 0;
        }
        let record = &self.tiles[tile as usize];
        if record.terrain == TacticalTerrain::Impassable || record.occupant.is_some() {
            return 0;
        }
        if self.current_side == BattleSide::Attacker {
            u8::from((3..=5).contains(&column))
        } else {
            u8::from(column <= self.column_count - 3 && column >= self.column_count - 5)
        }
    }

    fn count_free_deploy_tiles(&self) -> i32 {
        (0..TACTICAL_TILE_COUNT as i32)
            .filter(|&tile| self.deploy_guard(tile) != 0)
            .count() as i32
    }

    fn select_next_undeployed(&mut self, side: BattleSide) -> Option<usize> {
        let list_len = self.sides[side].units.len();
        if list_len == 0 {
            self.sides[side].ready = true;
            return None;
        }
        let start = self.sides[side].cursor;
        let mut scanned = 0;
        loop {
            self.sides[side].cursor += 1;
            if self.sides[side].cursor > list_len as i32 {
                self.sides[side].cursor = 1;
            }
            let idx = self.sides[side].units[(self.sides[side].cursor - 1) as usize];
            if self.units[idx].tile == -2 {
                return Some(idx);
            }
            scanned += 1;
            if self.sides[side].cursor == start || scanned >= list_len {
                break;
            }
        }
        let idx = self.sides[side].units[(self.sides[side].cursor.max(1) - 1) as usize];
        if self.units[idx].tile != -2 {
            self.sides[side].ready = true;
        }
        Some(idx)
    }

    fn sort_side_units(
        &mut self,
        state: &mut GameState,
        side: BattleSide,
        cmp: fn(&TacUnit, &TacUnit) -> i16,
    ) {
        let mut list = std::mem::take(&mut self.sides[side].units);
        retail_sort(&mut list, &mut state.rng, |a, b| {
            cmp(&self.units[a], &self.units[b])
        });
        self.sides[side].units = list;
    }

    fn sort_records(&mut self, state: &mut GameState) {
        let mut list = std::mem::take(&mut self.records);
        retail_sort(&mut list, &mut state.rng, |a, b| {
            compare_turn_order(&self.units[a], &self.units[b])
        });
        self.records = list;
    }

    fn prune_to(&mut self, state: &GameState, side: BattleSide, max_count: i32) {
        let profile_row = if self.sides[side].is_our {
            usize::from(self.fort_level != FortLevel::None) + 1
        } else {
            0
        };
        let mut secondary = Vec::new();
        for ordinal in (1..=self.sides[side].units.len()).rev() {
            let idx = self.sides[side].units[ordinal - 1];
            self.compute_projection(state, idx);
            secondary.push(idx);
        }
        secondary.reverse();
        self.sides[side].units.clear();
        let mut remaining = max_count;
        if remaining != 0
            && let Some(pos) = secondary.iter().position(|&idx| {
                self.units[idx].unit_type.tactical_category() == ArmyUnitCategory::Generals
            })
        {
            let kept = secondary.remove(pos);
            self.sides[side].units.push(kept);
            remaining -= 1;
        }
        let mut kept_sum = ActionClassScores::default();
        for _ in 0..remaining {
            let mut best_ordinal = 0;
            let mut best_score = 0.0f32;
            for candidate_ordinal in 1..secondary.len() {
                let candidate = secondary[candidate_ordinal - 1];
                kept_sum.add_assign(self.units[candidate].projection);
                let score = kept_sum.similarity(composition_row(profile_row));
                if score > best_score {
                    best_score = score;
                    best_ordinal = candidate_ordinal as i32;
                }
                kept_sum.subtract_assign(self.units[candidate].projection);
            }
            if best_ordinal == 0 || best_ordinal as usize > secondary.len() {
                continue;
            }
            let kept = secondary.remove((best_ordinal - 1) as usize);
            self.sides[side].units.push(kept);
            kept_sum.add_assign(self.units[kept].projection);
        }
        self.sides[side].secondary = secondary;
        for &pruned in &self.sides[side].secondary {
            if let Some(pos) = self.records.iter().position(|&idx| idx == pruned) {
                self.records.remove(pos);
            }
        }
    }

    fn compute_projection(&mut self, state: &GameState, idx: usize) {
        let source = &state.military_units[&self.units[idx].source];
        let quality = source.experience / 100;
        let quality_factor = 1.0 - f64::from(quality) * -0.1;
        let strength_term = self.units[idx].strength as f32 * 0.002;
        let scale = strength_term * quality_factor as f32;
        let kind = source.unit_type;
        self.units[idx].projection = ActionClassScores {
            infantry: f32::from(kind.tactical_attribute(TacticalCombatClass::Infantry))
                * scale
                * strength_term,
            cavalry: f32::from(kind.tactical_attribute(TacticalCombatClass::Cavalry)) * scale,
            artillery: f32::from(kind.tactical_attribute(TacticalCombatClass::Artillery)) * scale,
            armor: f32::from(kind.tactical_attribute(TacticalCombatClass::Armor)) * scale,
            support: f32::from(kind.tactical_attribute(TacticalCombatClass::Support)) * scale,
        };
    }

    fn accumulate_metrics(&mut self, state: &GameState, side: BattleSide) {
        self.sides[side].max_non_artillery_range = 0;
        self.sides[side].max_range = 0;
        self.sides[side].projection_sums = ActionClassScores::default();
        self.sides[side].has_artillery_or_engineers = false;
        let units = self.sides[side].units.clone();
        for idx in units {
            if self.units[idx].state != TacticalUnitState::Ready {
                continue;
            }
            self.compute_projection(state, idx);
            self.sides[side]
                .projection_sums
                .add_assign(self.units[idx].projection);
            let range = self.unit_range(idx) as i16;
            if range > self.sides[side].max_range {
                self.sides[side].max_range = range;
            }
            if AI_CLASS[self.units[idx].unit_type] != TacticalCombatClass::Artillery
                && range > self.sides[side].max_non_artillery_range
            {
                self.sides[side].max_non_artillery_range = range;
            }
            if AI_CLASS[self.units[idx].unit_type] == TacticalCombatClass::Artillery
                || self.units[idx].unit_type.tactical_category() == ArmyUnitCategory::Engineers
            {
                self.sides[side].has_artillery_or_engineers = true;
            }
        }
        let sums = self.sides[side].projection_sums;
        let baseline = sums.similarity(TACTICAL_COMPOSITION.baseline);
        let row = if self.fort_level != FortLevel::None {
            1
        } else {
            2
        };
        self.sides[side].baseline_similarity = baseline;
        self.sides[side].composition_similarity = sums.similarity(composition_row(row));
    }

    fn site_is_home_capital(&self, state: &GameState, side: BattleSide) -> bool {
        let Some(home) = state.nations.home_tile(self.sides[side].nation) else {
            return false;
        };
        state.map[home].province == Some(self.battle_site)
    }

    fn fort_breached(&self) -> bool {
        if self.fort_level == FortLevel::None {
            return true;
        }
        self.fort_strength.iter().any(|&pool| pool <= 0)
    }

    fn opponent_has_artillery(&self, side: BattleSide) -> bool {
        let enemy = side.opponent();
        self.sides[enemy].units.iter().any(|&idx| {
            self.units[idx].tile >= 0
                && AI_CLASS[self.units[idx].unit_type] == TacticalCombatClass::Artillery
                && self.units[idx].state == TacticalUnitState::Ready
        })
    }

    fn select_and_apply_cursor_mode(&mut self, state: &GameState, side: BattleSide) {
        let opponent = side.opponent();
        self.accumulate_metrics(state, side);
        self.accumulate_metrics(state, opponent);
        let opponent_projection = self.sides[opponent].projection_sums;
        let opponent_baseline_similarity = self.sides[opponent].baseline_similarity;
        let opponent_composition_similarity = self.sides[opponent].composition_similarity;
        let enemy_has_active = self.sides[opponent]
            .units
            .iter()
            .any(|&idx| self.units[idx].state == TacticalUnitState::Ready);
        self.sides[side].allow_broken_targets = !enemy_has_active;
        let mut stance;
        if !self.sides[side].is_our {
            if !enemy_has_active {
                stance = TacticalStance::Unopposed;
            } else if !self.sides[opponent].has_artillery_or_engineers && !self.fort_breached() {
                stance = TacticalStance::Garrison;
            } else if self.sides[side].composition_similarity / opponent_composition_similarity
                > CURSOR_STRONG_RATIO
            {
                if self.fort_breached() {
                    stance = TacticalStance::Bombard;
                } else if self.sides[side].composition_similarity / opponent_composition_similarity
                    > CURSOR_OVERWHELM_RATIO
                {
                    stance = TacticalStance::Bombard;
                } else {
                    stance = TacticalStance::Hold;
                }
            } else if self.sides[side].baseline_similarity / opponent_composition_similarity
                < CURSOR_WEAK_RATIO
                && !self.site_is_home_capital(state, side)
            {
                stance = TacticalStance::Retreat;
            } else {
                stance = if self.sides[side].max_range < self.sides[opponent].max_range {
                    TacticalStance::Bombard
                } else {
                    TacticalStance::Hold
                };
            }
        } else {
            let strength_ratio =
                self.sides[side].composition_similarity / opponent_baseline_similarity;
            let have_sapper = self.sides[side].units.iter().any(|&idx| {
                self.units[idx].unit_type.tactical_category() == ArmyUnitCategory::Engineers
                    && self.units[idx].state == TacticalUnitState::Ready
            });
            let have_artillery = self.sides[side].units.iter().any(|&idx| {
                AI_CLASS[self.units[idx].unit_type] == TacticalCombatClass::Artillery
                    && self.units[idx].state == TacticalUnitState::Ready
            });
            if !self.fort_breached() {
                if have_sapper {
                    stance = TacticalStance::Siege;
                } else if !have_artillery {
                    stance = TacticalStance::Retreat;
                } else if self.sides[side].projection_sums.armor / opponent_projection.armor
                    < CURSOR_ARTILLERY_PARITY
                {
                    stance = TacticalStance::Retreat;
                } else {
                    stance = TacticalStance::Siege;
                }
            } else if !enemy_has_active {
                stance = TacticalStance::Unopposed;
            } else if strength_ratio > CURSOR_STRONG_RATIO {
                stance = TacticalStance::Assault;
            } else if !(self.sides[side].projection_sums.armor / opponent_projection.armor
                < CURSOR_ARTILLERY_SUPERIORITY)
                && have_artillery
            {
                stance = TacticalStance::Siege;
            } else if !(strength_ratio < CURSOR_ASSAULT_RATIO) {
                stance = TacticalStance::Assault;
            } else if strength_ratio < CURSOR_RETREAT_RATIO
                && !self.site_is_home_capital(state, side)
            {
                stance = TacticalStance::Retreat;
            } else {
                stance = TacticalStance::Standoff;
            }
        }
        if self.sides[side].field_f {
            stance = TacticalStance::Retreat;
        }
        if stance == TacticalStance::Retreat {
            self.sides[side].allow_broken_targets = true;
        }
        if self.sides[side].last_stance == Some(stance) {
            return;
        }
        self.sides[side].last_stance = Some(stance);
        self.apply_stance(side, stance);
    }

    fn apply_stance(&mut self, side: BattleSide, stance: TacticalStance) {
        match stance {
            TacticalStance::Hold => self.stance_hold(side),
            TacticalStance::Retreat => self.stance_retreat(side),
            TacticalStance::Bombard => self.stance_bombard(side),
            TacticalStance::Siege => self.stance_siege(side),
            TacticalStance::Assault => self.stance_assault(side),
            TacticalStance::Standoff => self.stance_standoff(side),
            TacticalStance::Unopposed => self.stance_unopposed(side),
            TacticalStance::Garrison => self.stance_garrison(side),
        }
    }

    fn stance_retreat(&mut self, side: BattleSide) {
        for &idx in &self.sides[side].units.clone() {
            self.units[idx].ai_state =
                if self.units[idx].unit_type.tactical_category() != ArmyUnitCategory::Garrison {
                    0xc
                } else {
                    7
                };
        }
    }

    fn stance_garrison(&mut self, side: BattleSide) {
        for &idx in &self.sides[side].units.clone() {
            self.units[idx].ai_state = 0x13;
        }
    }

    fn stance_hold(&mut self, side: BattleSide) {
        for &idx in &self.sides[side].units.clone() {
            if self.units[idx].state != TacticalUnitState::Ready {
                continue;
            }
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                TacticalCombatClass::Infantry => 0,
                TacticalCombatClass::Artillery => 9,
                TacticalCombatClass::Cavalry | TacticalCombatClass::Armor => 0xe,
                TacticalCombatClass::Support if general(self.units[idx].unit_type) => 0xb,
                TacticalCombatClass::Support => 0xc,
            };
        }
    }

    fn stance_bombard(&mut self, side: BattleSide) {
        for &idx in &self.sides[side].units.clone() {
            if self.units[idx].state != TacticalUnitState::Ready {
                continue;
            }
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                TacticalCombatClass::Infantry => 7,
                TacticalCombatClass::Artillery => 8,
                TacticalCombatClass::Cavalry | TacticalCombatClass::Armor => 5,
                TacticalCombatClass::Support if general(self.units[idx].unit_type) => 0xb,
                TacticalCombatClass::Support => 0xc,
            };
        }
    }

    fn stance_siege(&mut self, side: BattleSide) {
        let enemy_artillery = self.opponent_has_artillery(side);
        let opponent_range = self.sides[side.opponent()].max_non_artillery_range;
        let wall_up = self.tiles[174].deploy_mark.is_fort_wall();
        for &idx in &self.sides[side].units.clone() {
            if self.units[idx].unit_type.tactical_category() == ArmyUnitCategory::Engineers {
                self.units[idx].ai_state = if wall_up { 0xd } else { 0xc };
                continue;
            }
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                TacticalCombatClass::Infantry
                    if self.unit_range(idx) > i32::from(opponent_range) =>
                {
                    0x11
                }
                TacticalCombatClass::Infantry
                    if self.units[idx].unit_type.tactical_category()
                        == ArmyUnitCategory::LightInfantry =>
                {
                    if enemy_artillery {
                        0x10
                    } else {
                        0xa
                    }
                }
                TacticalCombatClass::Infantry => 1,
                TacticalCombatClass::Cavalry | TacticalCombatClass::Armor => 0xe,
                TacticalCombatClass::Artillery
                    if self.units[idx].unit_type.tactical_category()
                        == ArmyUnitCategory::FieldArtillery =>
                {
                    0x11
                }
                TacticalCombatClass::Artillery => 8,
                TacticalCombatClass::Support => 0xb,
            };
        }
    }

    fn stance_assault(&mut self, side: BattleSide) {
        self.stance_assault_or_standoff(side, 5);
    }

    fn stance_standoff(&mut self, side: BattleSide) {
        self.stance_assault_or_standoff(side, 2);
    }

    fn stance_assault_or_standoff(&mut self, side: BattleSide, flank: i32) {
        let enemy_artillery = self.opponent_has_artillery(side);
        let opponent_range = self.sides[side.opponent()].max_non_artillery_range;
        for &idx in &self.sides[side].units.clone() {
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                TacticalCombatClass::Infantry
                    if self.unit_range(idx) > i32::from(opponent_range) =>
                {
                    0x11
                }
                TacticalCombatClass::Infantry
                    if self.units[idx].unit_type.tactical_category()
                        == ArmyUnitCategory::LightInfantry =>
                {
                    if enemy_artillery {
                        0x10
                    } else {
                        0xa
                    }
                }
                TacticalCombatClass::Infantry => 7,
                TacticalCombatClass::Cavalry | TacticalCombatClass::Armor => flank,
                TacticalCombatClass::Artillery
                    if self.units[idx].unit_type.tactical_category()
                        == ArmyUnitCategory::FieldArtillery =>
                {
                    0x11
                }
                TacticalCombatClass::Artillery => 8,
                TacticalCombatClass::Support
                    if self.units[idx].unit_type.tactical_category()
                        == ArmyUnitCategory::Engineers =>
                {
                    0xc
                }
                TacticalCombatClass::Support => 0xb,
            };
        }
    }

    fn stance_unopposed(&mut self, side: BattleSide) {
        for &idx in &self.sides[side].units.clone() {
            self.units[idx].ai_state = match AI_CLASS[self.units[idx].unit_type] {
                TacticalCombatClass::Infantry => 7,
                TacticalCombatClass::Cavalry | TacticalCombatClass::Armor => 5,
                TacticalCombatClass::Artillery => 8,
                TacticalCombatClass::Support
                    if self.units[idx].unit_type.tactical_category()
                        == ArmyUnitCategory::Engineers =>
                {
                    0xc
                }
                TacticalCombatClass::Support => 0xb,
            };
        }
    }

    fn advance_auto_pulse(&mut self, state: &mut GameState, side: BattleSide) {
        if self.sides[side].field20 {
            let selected = self.selected;
            for &idx in &self.sides[side].units.clone() {
                if self.units[idx].unit_type.tactical_category() == ArmyUnitCategory::Engineers
                    && self.units[idx].state == TacticalUnitState::Ready
                {
                    if selected.is_none_or(|sel| {
                        self.units[sel].unit_type.tactical_category() != ArmyUnitCategory::Engineers
                    }) {
                        self.finish_action();
                        return;
                    }
                    self.sides[side].field20 = false;
                    return;
                }
            }
            self.sides[side].field20 = false;
            return;
        }
        self.run_auto_controller(state, side);
    }

    fn run_auto_controller(&mut self, state: &mut GameState, side: BattleSide) {
        let Some(unit) = self.selected else {
            self.finish_action();
            return;
        };
        if AI_CLASS[self.units[unit].unit_type] != TacticalCombatClass::Artillery
            || self.units[unit].side == BattleSide::Defender
        {
            self.select_and_apply_cursor_mode(state, side);
        }
        let home = self.units[unit].tile;
        let category = self.units[unit].unit_type.tactical_category();
        let mut target = if category == ArmyUnitCategory::Engineers
            && self.units[unit].ai_state != 0xc
        {
            if self.fort_breached() {
                self.best_tile(state, unit, side, 12)
            } else if self.tiles[home as usize].trench_mask != 0 || self.threat[home as usize] != 0
            {
                home
            } else {
                self.best_tile(state, unit, side, 13)
            }
        } else if (self.units[unit].ai_state == 5
            || self.units[unit].ai_state == 2
            || category == ArmyUnitCategory::LightCavalry)
            && self.round < 2
        {
            home
        } else if category == ArmyUnitCategory::FieldArtillery && self.round < 2 {
            self.best_tile(state, unit, side, 18)
        } else {
            self.best_tile(state, unit, side, self.units[unit].ai_state)
        };
        if target == -1 {
            target = self.units[unit].tile;
        }
        if target != self.units[unit].tile {
            let mut guard = 200;
            while self.pending_end
                && self.units[unit].state == TacticalUnitState::Ready
                && self.units[unit].tile != target
            {
                if guard == 0 {
                    break;
                }
                guard -= 1;
                self.move_and_maybe_finish(state, unit, target);
            }
        }
        if self.pending_end && self.units[unit].state == TacticalUnitState::Ready {
            if general(self.units[unit].unit_type) {
                let neighbors = self.neighbors(self.units[unit].tile);
                let mut rally = None;
                for &neighbor in neighbors.values() {
                    if neighbor == -1 {
                        continue;
                    }
                    if let Some(occupant) = self.tiles[neighbor as usize].occupant
                        && self.units[occupant].side == self.units[unit].side
                        && self.units[occupant].morale < self.units[occupant].strength
                    {
                        rally = Some(occupant);
                        break;
                    }
                }
                if let Some(target_unit) = rally {
                    self.rally(state, unit, target_unit);
                }
            } else if self.units[unit].unit_type.tactical_category() == ArmyUnitCategory::Engineers
            {
                if self.units[unit].tile == home {
                    while self.units[unit].action_points
                        >= BASE_ACTION_POINTS[self.units[unit].unit_type] / 2
                    {
                        let wall = self.units[unit].tile + 1;
                        if wall < 0 || wall >= TACTICAL_TILE_COUNT as i32 {
                            break;
                        }
                        if self.tiles[wall as usize].deploy_mark.is_fort_wall() {
                            self.mine(state, unit, wall);
                            return;
                        }
                        if self.tiles[wall as usize].occupant.is_none()
                            && self.tiles[wall as usize].trench_mask == 0
                        {
                            self.dig(state, unit, wall);
                        } else {
                            break;
                        }
                    }
                }
            } else if self.units[unit].selected {
                let fire_tile = self.best_target(state, unit, side, true);
                let fire_target = if fire_tile != -1 {
                    self.tiles[fire_tile as usize].occupant
                } else {
                    None
                };
                if let Some(target_unit) = fire_target {
                    let tile = self.units[target_unit].tile;
                    self.fire_and_maybe_finish(state, unit, tile);
                    if self.pending_end
                        && AI_CLASS[self.units[unit].unit_type] == TacticalCombatClass::Cavalry
                        && self.units[unit].action_points != 0
                    {
                        let ai_state = self.units[unit].ai_state;
                        if ai_state == 2 || ai_state == 5 || ai_state == 0xe {
                            let advance = self.best_tile(state, unit, side, ai_state + 1);
                            if advance != self.units[unit].tile {
                                let mut guard = 200;
                                while self.selected == Some(unit)
                                    && self.units[unit].state == TacticalUnitState::Ready
                                    && self.units[unit].tile != advance
                                {
                                    if guard == 0 {
                                        break;
                                    }
                                    guard -= 1;
                                    self.move_and_maybe_finish(state, unit, advance);
                                }
                            }
                        }
                    }
                }
            }
        }
        if self.pending_end {
            self.finish_action();
        }
    }

    fn best_tile(&mut self, state: &mut GameState, unit: usize, side: BattleSide, row: i32) -> i32 {
        let row = row.clamp(0, 19) as usize;
        self.select_best_tile(state, unit, side, HEURISTIC_WEIGHTS[row])
    }

    fn select_best_tile(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: BattleSide,
        weights: [i32; 15],
    ) -> i32 {
        let mut best_tile = -1;
        let mut best_score = -99999;
        let mut distance_built = false;
        if weights[8] > 0 {
            self.build_distance_field(self.sides[side].is_our);
            distance_built = true;
        }
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            let column = tile % TACTICAL_STRIDE;
            if self.cost(tile) == -1 {
                self.candidate_scores[tile as usize] = 0;
                continue;
            }
            if !distance_built && (column == 0 || column == self.column_count - 1) {
                self.candidate_scores[tile as usize] = 0;
                continue;
            }
            let mut score = 0;
            for heuristic in 0..15 {
                if weights[heuristic] != 0 {
                    score += self.score_heuristic(state, unit, side, tile, heuristic)
                        * weights[heuristic];
                }
            }
            let cheaper = best_tile != -1 && self.cost(tile) < self.cost(best_tile);
            if score > best_score || (score == best_score && (best_tile == -1 || cheaper)) {
                best_tile = tile;
                best_score = score;
            }
            self.candidate_scores[tile as usize] = score;
        }
        best_tile
    }

    fn score_heuristic(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: BattleSide,
        tile: i32,
        heuristic: usize,
    ) -> i32 {
        match heuristic {
            0 => i32::from(self.units[unit].tile == tile) * 0x64,
            1 => self.score_fire_opportunity(state, unit, side, tile),
            2 => self.score_sapper_column(unit, tile),
            3 => self.score_adjacent_enemy(unit, side, tile),
            4 => self.score_exposure(unit, side, tile, false),
            5 => self.score_retreat_edge(side, tile),
            6 => {
                let terrain = self.tiles[tile as usize].terrain;
                i32::from(matches!(
                    terrain,
                    TacticalTerrain::Class1 | TacticalTerrain::Class2
                )) * 0x64
            }
            7 => self.score_rally(unit, tile),
            8 => {
                let value = self.distance_field[tile as usize];
                if value != -1 { 0x64 - value } else { 0 }
            }
            9 => self.score_artillery_spacing(side, tile),
            10 => self.score_firing_lane(tile),
            11 => self.score_exposure(unit, side, tile, true),
            12 => self.score_standoff(state, unit, side, tile),
            13 => self.score_hunt_artillery(unit, tile),
            14 => i32::from(tile % TACTICAL_STRIDE > self.column_count - 5) * 0x64,
            _ => 0,
        }
    }

    fn score_fire_opportunity(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: BattleSide,
        tile: i32,
    ) -> i32 {
        let _ = self.unit_range(unit);
        let mut score = 0;
        let mut scan = 0;
        while score == 0 && scan < TACTICAL_TILE_COUNT as i32 {
            if let Some(occupant) = self.tiles[scan as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && (self.units[occupant].state == TacticalUnitState::Ready
                    || self.sides[side].allow_broken_targets)
            {
                let category = self.units[unit].unit_type.tactical_category();
                if self.reachable_for_action(
                    tile,
                    scan,
                    direct_fire(category),
                    self.unit_range(unit),
                ) {
                    score = 0x32;
                }
            }
            scan += 1;
        }
        let target = self.best_target(state, unit, side, false);
        if target != -1
            && (AI_CLASS[self.units[unit].unit_type] != TacticalCombatClass::Artillery
                || score == 0)
        {
            score += 0x32 - hex_distance(tile, target);
        }
        score
    }

    fn score_sapper_column(&self, unit: usize, tile: i32) -> i32 {
        if tile % TACTICAL_STRIDE != 6 {
            return 0;
        }
        let mut score = if self.tiles[tile as usize].deploy_mark.is_present() {
            0x14
        } else {
            0
        } + 0x50;
        if tile + 1 < TACTICAL_TILE_COUNT as i32
            && let Some(right) = self.tiles[(tile + 1) as usize].occupant
            && self.units[right].side == self.units[unit].side
        {
            score -= 0x14;
        }
        if tile > 0
            && let Some(left) = self.tiles[(tile - 1) as usize].occupant
            && self.units[left].side == self.units[unit].side
        {
            score -= 0x14;
        }
        score
    }

    fn score_adjacent_enemy(&self, unit: usize, side: BattleSide, tile: i32) -> i32 {
        for &neighbor in self.neighbors(tile).values() {
            if neighbor == -1 {
                continue;
            }
            if let Some(occupant) = self.tiles[neighbor as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && (self.units[occupant].state == TacticalUnitState::Ready
                    || self.sides[side].allow_broken_targets)
            {
                return 0x64;
            }
        }
        0
    }

    fn score_exposure(
        &self,
        _unit: usize,
        side: BattleSide,
        tile: i32,
        artillery_only: bool,
    ) -> i32 {
        let enemy = side.opponent();
        let mut count = 0;
        for &idx in &self.sides[enemy].units {
            if self.units[idx].tile < 0 {
                continue;
            }
            if artillery_only
                && AI_CLASS[self.units[idx].unit_type] != TacticalCombatClass::Artillery
            {
                continue;
            }
            let category = self.units[idx].unit_type.tactical_category();
            if self.reachable_for_action(
                tile,
                self.units[idx].tile,
                direct_fire(category),
                self.unit_range(idx),
            ) {
                count += 1;
            }
        }
        count
    }

    fn score_retreat_edge(&self, side: BattleSide, tile: i32) -> i32 {
        let row = tile / TACTICAL_STRIDE;
        if self.sides[side].retreat_toward_north {
            if row <= 1 {
                0x64
            } else {
                (0xf - row) * 50 / 15
            }
        } else if row >= 0xd {
            0x64
        } else {
            row * 50 / 15
        }
    }

    fn score_rally(&self, unit: usize, tile: i32) -> i32 {
        for &neighbor in self.neighbors(tile).values() {
            if neighbor == -1 {
                continue;
            }
            if let Some(occupant) = self.tiles[neighbor as usize].occupant
                && self.units[occupant].side == self.units[unit].side
                && self.units[occupant].morale < self.units[occupant].strength
            {
                return 0x64;
            }
        }
        0
    }

    fn score_artillery_spacing(&self, side: BattleSide, tile: i32) -> i32 {
        let mut best = 0;
        for &idx in &self.sides[side].units {
            if AI_CLASS[self.units[idx].unit_type] != TacticalCombatClass::Artillery {
                continue;
            }
            let distance = hex_distance(tile, self.units[idx].tile);
            if distance <= 2 {
                return 0;
            }
            let score = 0x64 - distance * 100 / 10;
            if score > best {
                best = score;
            }
        }
        best
    }

    fn score_firing_lane(&self, tile: i32) -> i32 {
        let column = tile % TACTICAL_STRIDE;
        let wall = self.column_count - 6;
        if column < wall {
            for scan in column..wall {
                let scan_tile = tile - column + scan;
                if self.tiles[scan_tile as usize].terrain == TacticalTerrain::Impassable {
                    return 0;
                }
            }
        }
        if self.threat[tile as usize] != 0 || column > wall {
            return 0;
        }
        column
    }

    fn score_standoff(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: BattleSide,
        tile: i32,
    ) -> i32 {
        let range = self.unit_range(unit);
        let mut score = 0;
        let target = self.best_target(state, unit, side, false);
        let category = self.units[unit].unit_type.tactical_category();
        for scan in 0..TACTICAL_TILE_COUNT as i32 {
            if let Some(occupant) = self.tiles[scan as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && self.units[occupant].state == TacticalUnitState::Ready
                && self.reachable_for_action(tile, scan, direct_fire(category), range)
            {
                let candidate = hex_distance(tile, scan) + 0x32;
                if score == 0 || candidate < score {
                    score = candidate;
                }
            }
        }
        if score > 0 {
            if target != -1 && self.reachable_for_action(tile, target, direct_fire(category), range)
            {
                score += 5;
            }
            if score > 0 {
                return score;
            }
        }
        if target != -1 {
            0x32 - hex_distance(tile, target)
        } else {
            0
        }
    }

    fn score_hunt_artillery(&self, unit: usize, tile: i32) -> i32 {
        let range = self.unit_range(unit);
        let category = self.units[unit].unit_type.tactical_category();
        for scan in 0..TACTICAL_TILE_COUNT as i32 {
            if let Some(occupant) = self.tiles[scan as usize].occupant
                && self.units[occupant].side != self.units[unit].side
                && self.units[occupant].state == TacticalUnitState::Ready
                && AI_CLASS[self.units[occupant].unit_type] == TacticalCombatClass::Artillery
                && self.reachable_for_action(tile, scan, direct_fire(category), range)
            {
                return 0x64;
            }
        }
        0
    }

    fn best_target(
        &mut self,
        state: &mut GameState,
        unit: usize,
        side: BattleSide,
        require_reach: bool,
    ) -> i32 {
        let enemy = side.opponent();
        let neighbors = self.neighbors(self.units[unit].tile);
        let mut best_tile = -1;
        let mut best_score = 0;
        for &idx in &self.sides[enemy].units.clone() {
            let broken_ok = self.sides[side].allow_broken_targets
                && self.units[idx].state == TacticalUnitState::MoraleBroken;
            if !broken_ok && self.units[idx].state != TacticalUnitState::Ready {
                continue;
            }
            if require_reach {
                let category = self.units[unit].unit_type.tactical_category();
                if !self.reachable_for_action(
                    self.units[unit].tile,
                    self.units[idx].tile,
                    direct_fire(category),
                    self.unit_range(unit),
                ) {
                    continue;
                }
            }
            let category = self.units[idx].unit_type.tactical_category();
            let mut score = category_value(category);
            if self.sides[side].allow_broken_targets {
                score += 0x1f4 - self.units[idx].morale;
            } else {
                score += self.units[idx].strength;
            }
            let record_tile = self.units[idx].tile;
            let adjacent = neighbors.values().any(|&neighbor| neighbor == record_tile);
            if adjacent {
                if self.tiles[record_tile as usize].deploy_mark == DeployMark::UnitCover {
                    score += score;
                }
                if AI_CLASS[self.units[unit].unit_type] == TacticalCombatClass::Cavalry {
                    score += score;
                }
            }
            if best_tile == -1 || score > best_score {
                best_tile = record_tile;
                best_score = score;
            }
        }
        if best_tile == -1
            && self.units[unit].side == BattleSide::Attacker
            && !direct_fire(self.units[unit].unit_type.tactical_category())
            && !self.fort_breached()
        {
            if self.sides[side].cached_bombard_tile == -1 {
                loop {
                    let rolled = (state.rng.next_crt_rand() % 0xd) * 29 + self.column_count + 0x17;
                    self.sides[side].cached_bombard_tile = rolled;
                    if self.fort_gun_slot(rolled) == 0 {
                        break;
                    }
                }
            }
            best_tile = self.sides[side].cached_bombard_tile;
        }
        best_tile
    }

    fn fort_gun_slot(&self, tile: i32) -> u8 {
        let row = tile / TACTICAL_STRIDE;
        let doubled = (row & 1) + (tile % TACTICAL_STRIDE) * 2;
        u8::from((row == 5 || row == 7 || row == 9) && doubled / 2 == self.column_count - 6)
    }

    fn evaluate_outcome(&mut self) {
        let mut live = BattleSideTable::default();
        for &idx in &self.records {
            if self.units[idx].state == TacticalUnitState::Ready
                || self.units[idx].state == TacticalUnitState::MoraleBroken
            {
                live[self.units[idx].side] = true;
                if live[BattleSide::Attacker] && live[BattleSide::Defender] {
                    break;
                }
            }
        }
        if live[BattleSide::Attacker] && live[BattleSide::Defender] && self.round < 0x23 {
            return;
        }
        self.outcome = if live[BattleSide::Attacker] && self.round < 0x23 {
            BattleOutcome::AttackerWon
        } else {
            BattleOutcome::DefenderWon
        };
    }
}

fn combat_category_of(unit_type: MilitaryUnitKind) -> TacticalCombatClass {
    AI_CLASS[unit_type]
}

/// Retail's second flanking lookup is asymmetric: every direction except north-west
/// checks the east slot. This is confirmed compiled behavior, not normal hex rotation.
const fn retail_second_flank_direction(direction: HexDirection) -> HexDirection {
    match direction {
        HexDirection::NorthWest => HexDirection::NorthEast,
        _ => HexDirection::East,
    }
}

fn neighbor_list(tile: i32) -> HexDirectionTable<i32> {
    let mut out = HexDirectionTable::from_array(if (tile / TACTICAL_STRIDE) & 1 != 0 {
        [
            tile - TACTICAL_STRIDE + 1,
            tile + 1,
            tile + TACTICAL_STRIDE + 1,
            tile + TACTICAL_STRIDE,
            tile - 1,
            tile - TACTICAL_STRIDE,
        ]
    } else {
        [
            tile - TACTICAL_STRIDE,
            tile + 1,
            tile + TACTICAL_STRIDE,
            tile + TACTICAL_STRIDE - 1,
            tile - 1,
            tile - TACTICAL_STRIDE - 1,
        ]
    });
    if (tile + 1) % TACTICAL_STRIDE == 0 {
        out[HexDirection::East] = -1;
        if (tile / TACTICAL_STRIDE) & 1 != 0 {
            out[HexDirection::NorthEast] = -1;
            out[HexDirection::SouthEast] = -1;
        }
    } else if tile % TACTICAL_STRIDE == 0 {
        out[HexDirection::West] = -1;
        if (tile / TACTICAL_STRIDE) & 1 == 0 {
            out[HexDirection::SouthWest] = -1;
            out[HexDirection::NorthWest] = -1;
        }
    }
    if tile >= TACTICAL_TILE_COUNT as i32 - TACTICAL_STRIDE {
        out[HexDirection::SouthEast] = -1;
        out[HexDirection::SouthWest] = -1;
    } else if tile < TACTICAL_STRIDE {
        out[HexDirection::NorthEast] = -1;
        out[HexDirection::NorthWest] = -1;
    }
    out
}

fn retail_sort(
    list: &mut [usize],
    rng: &mut crate::rng::RngState,
    cmp: impl Fn(usize, usize) -> i16,
) {
    if !list.is_empty() {
        // TSortedList comparators return 0 for the same object; without that, Hoare
        // partition can return `hi` unchanged and QuickSort(lo, hi) never shrinks.
        retail_quicksort(list, 1, list.len() as i32, rng, &|a, b| {
            if a == b { 0 } else { cmp(a, b) }
        });
    }
}

fn retail_quicksort(
    list: &mut [usize],
    lo: i32,
    hi: i32,
    rng: &mut crate::rng::RngState,
    cmp: &impl Fn(usize, usize) -> i16,
) {
    if lo < hi {
        let pivot = retail_partition(list, lo, hi, rng, cmp);
        retail_quicksort(list, lo, pivot, rng, cmp);
        retail_quicksort(list, pivot + 1, hi, rng, cmp);
    }
}

fn retail_partition(
    list: &mut [usize],
    lo: i32,
    hi: i32,
    rng: &mut crate::rng::RngState,
    cmp: &impl Fn(usize, usize) -> i16,
) -> i32 {
    let mut pivot_ordinal = lo;
    if lo != hi {
        pivot_ordinal = rng.next_crt_rand() % (hi - lo).abs() + lo;
    }
    list.swap((lo - 1) as usize, (pivot_ordinal - 1) as usize);
    retail_partition_core(list, lo, hi, cmp)
}

fn retail_partition_core(
    list: &mut [usize],
    lo: i32,
    hi: i32,
    cmp: &impl Fn(usize, usize) -> i16,
) -> i32 {
    if lo >= hi {
        return hi;
    }
    let pivot = list[(lo - 1) as usize];
    let mut below = lo - 1;
    let mut above = hi + 1;
    loop {
        loop {
            above -= 1;
            if cmp(pivot, list[(above - 1) as usize]) > -1 {
                break;
            }
        }
        loop {
            below += 1;
            if cmp(pivot, list[(below - 1) as usize]) < 1 {
                break;
            }
        }
        if above <= below {
            return above;
        }
        list.swap((below - 1) as usize, (above - 1) as usize);
    }
}

impl Battle {
    fn compute_reachable(&mut self, unit: usize) {
        let category = self.units[unit].unit_type.tactical_category();
        let action_points = self.units[unit].action_points;
        self.clear_move_costs();
        let start = self.units[unit].tile;
        if start < 0 || start >= TACTICAL_TILE_COUNT as i32 {
            return;
        }
        let edge_column = if self.units[unit].side == BattleSide::Attacker {
            self.column_count - 1
        } else {
            0
        };
        self.set_cost(start, 0);
        let mut cost_level = 0;
        while cost_level <= action_points {
            let mut column = 0;
            for tile in TACTICAL_STRIDE..TACTICAL_TILE_COUNT as i32 {
                if column < self.column_count
                    && column != edge_column
                    && self.cost(tile) >= cost_level as i16
                {
                    let neighbors = self.neighbors(tile);
                    for direction in HexDirection::ALL {
                        let neighbor = neighbors[direction];
                        let neighbor_index = neighbor as i16;
                        if neighbor_index == -1 {
                            continue;
                        }
                        let record = self.tiles[neighbor as usize];
                        if record.occupant.is_some() || neighbor < TACTICAL_STRIDE {
                            continue;
                        }
                        if record.deploy_mark.is_fort_wall()
                            && self.fort_strength[(neighbor / TACTICAL_STRIDE / 2) as usize] > 0
                        {
                            let wall_row = neighbor / TACTICAL_STRIDE;
                            let wall_column = neighbor % TACTICAL_STRIDE;
                            if wall_row != 5 && wall_row != 7 && wall_row != 9 {
                                continue;
                            }
                            if ((wall_row & 1) + wall_column * 2) / 2 != self.column_count - 6 {
                                continue;
                            }
                            if self.units[unit].side != BattleSide::Defender {
                                continue;
                            }
                        }
                        let new_cost = MOVE_COST[category][record.terrain] + self.cost(tile);
                        if i32::from(new_cost) > action_points {
                            continue;
                        }
                        let existing = self.cost(neighbor);
                        if existing != -1 && existing <= new_cost {
                            continue;
                        }
                        let mut blocked = false;
                        let prev_neighbor = neighbors[direction.previous_clockwise()];
                        if prev_neighbor != -1
                            && let Some(prev) = self.tiles[prev_neighbor as usize].occupant
                            && self.units[prev].side != self.units[unit].side
                        {
                            blocked = true;
                        }
                        // The retail code mistakenly checks East for directions 0..4,
                        // and NorthEast only for direction 5, rather than the next
                        // clockwise neighbor.
                        let next_neighbor = neighbors[retail_second_flank_direction(direction)];
                        if next_neighbor != -1
                            && let Some(next) = self.tiles[next_neighbor as usize].occupant
                            && self.units[next].side != self.units[unit].side
                        {
                            blocked = true;
                        }
                        if blocked || neighbor % TACTICAL_STRIDE == edge_column {
                            continue;
                        }
                        self.set_cost(neighbor, new_cost);
                    }
                }
                column += 1;
                if column == TACTICAL_STRIDE {
                    column = 0;
                }
            }
            cost_level += 10;
        }
        self.propagate_threat(unit);
    }

    fn propagate_threat(&mut self, unit: usize) {
        let side = self.units[unit].side;
        for tile in 0..TACTICAL_TILE_COUNT {
            if let Some(occupant) = self.tiles[tile].occupant
                && self.units[occupant].side != side
                && self.units[occupant].state == TacticalUnitState::Ready
            {
                self.threat[tile] = (self.unit_range(occupant) + 1) as i8;
            } else {
                self.threat[tile] = 0;
            }
        }
        for level in (1..=0x13).rev() {
            for tile in 0..TACTICAL_TILE_COUNT {
                if self.threat[tile] == level {
                    for &neighbor in self.neighbors(tile as i32).values() {
                        if neighbor != -1 && self.threat[neighbor as usize] < level - 1 {
                            self.threat[neighbor as usize] = level - 1;
                        }
                    }
                }
            }
        }
    }

    fn build_distance_field(&mut self, our_side: bool) {
        self.distance_field = [-1; TACTICAL_TILE_COUNT];
        if our_side {
            let mut row_start = 0;
            while row_start < TACTICAL_TILE_COUNT as i32 {
                if self.tiles[row_start as usize].terrain != TacticalTerrain::Impassable {
                    self.distance_field[row_start as usize] = 0;
                }
                row_start += TACTICAL_STRIDE;
            }
        } else {
            let mut row_start = 0;
            while row_start < TACTICAL_TILE_COUNT as i32 {
                let edge = self.column_count + row_start - 1;
                if self.tiles[edge as usize].terrain != TacticalTerrain::Impassable {
                    self.distance_field[edge as usize] = 0;
                }
                row_start += TACTICAL_STRIDE;
            }
        }
        let mut distance = 0;
        loop {
            let mut expanded = false;
            for tile in 0..TACTICAL_TILE_COUNT {
                if self.distance_field[tile] != distance {
                    continue;
                }
                for &neighbor in self.neighbors(tile as i32).values() {
                    if neighbor == -1 || self.distance_field[neighbor as usize] != -1 {
                        continue;
                    }
                    let record = self.tiles[neighbor as usize];
                    if record.occupant.is_some() {
                        continue;
                    }
                    if record.deploy_mark.is_fort_wall() {
                        let wall_row = neighbor / TACTICAL_STRIDE;
                        if self.fort_strength[(wall_row / 2) as usize] > 0 {
                            let doubled = (wall_row & 1) + (neighbor % TACTICAL_STRIDE) * 2;
                            if wall_row != 5 && wall_row != 7 && wall_row != 9 {
                                continue;
                            }
                            if doubled / 2 != self.column_count - 6 {
                                continue;
                            }
                            if our_side {
                                continue;
                            }
                        }
                    }
                    if record.terrain != TacticalTerrain::Impassable {
                        expanded = true;
                        self.distance_field[neighbor as usize] = distance + 1;
                    }
                }
            }
            distance += 1;
            if !expanded {
                break;
            }
        }
    }

    fn reachable_for_action(
        &self,
        attacker_tile: i32,
        target_tile: i32,
        direct_fire: bool,
        range: i32,
    ) -> bool {
        if hex_distance(attacker_tile, target_tile) > range {
            return false;
        }
        let target = &self.tiles[target_tile as usize];
        if let Some(occupant) = target.occupant
            && self.units[occupant].unit_type.tactical_category() == ArmyUnitCategory::Engineers
            && target.trench_mask != 0
        {
            let neighbors = self.neighbors(attacker_tile);
            if !neighbors.values().any(|&neighbor| neighbor == target_tile) {
                return false;
            }
        }
        if !direct_fire {
            return true;
        }
        let wall = self.wall_on_firing_line(target_tile, attacker_tile);
        if wall == 0 {
            return true;
        }
        if !self.tiles[wall as usize].deploy_mark.is_fort_wall() {
            return true;
        }
        if self.fort_strength[(wall / TACTICAL_STRIDE / 2) as usize] <= 0 {
            return true;
        }
        let target_column = target_tile % TACTICAL_STRIDE;
        let attacker_column = attacker_tile % TACTICAL_STRIDE;
        target_column <= self.column_count - 5 || attacker_column == self.column_count - 5
    }

    fn wall_on_firing_line(&self, target: i32, attacker: i32) -> i32 {
        let wall_x = (2 * self.column_count - 12) as f32;
        let mut x1 = 2 * (target % TACTICAL_STRIDE) + ((target / TACTICAL_STRIDE) & 1);
        let mut y1 = 2 * (target / TACTICAL_STRIDE);
        let mut x2 = 2 * (attacker % TACTICAL_STRIDE) + ((attacker / TACTICAL_STRIDE) & 1);
        let mut y2 = 2 * (attacker / TACTICAL_STRIDE);
        if x2 == x1 {
            return 0;
        }
        if x2 > x1 {
            std::mem::swap(&mut x1, &mut x2);
            std::mem::swap(&mut y1, &mut y2);
        }
        let left_x = x2 as f32;
        if left_x > wall_x || (x1 as f32) < wall_x {
            return 0;
        }
        if y1 == y2 {
            return TACTICAL_STRIDE * y1 / 2 + self.column_count - 6;
        }
        self.column_count
            - ((y2 as f32 + (wall_x - left_x) * ((y1 - y2) as f32 / (x1 - x2) as f32)) * -0.5)
                as i32
                * TACTICAL_STRIDE
            - 6
    }

    fn consume_fort(&mut self, tile: i32, amount: i32) {
        let pool = (tile / TACTICAL_STRIDE / 2) as usize;
        let remaining = self.fort_strength[pool] - amount;
        self.fort_strength[pool] = remaining.max(0);
    }

    fn move_and_maybe_finish(
        &mut self,
        state: &mut GameState,
        unit: usize,
        target: i32,
    ) -> Vec<TacticalHex> {
        let path = self.move_toward(state, unit, target);
        if self.units[unit].unit_type.tactical_category() == ArmyUnitCategory::SiegeArtillery {
            self.units[unit].selected = false;
        }
        if self.units[unit].state == TacticalUnitState::Ready
            && self.outcome == BattleOutcome::InProgress
        {
            if self.units[unit].selected && self.has_followup(unit) {
                return path;
            }
            if self.has_adjacent_reachable(unit) {
                return path;
            }
        }
        self.finish_action();
        path
    }

    fn fire_and_maybe_finish(&mut self, state: &mut GameState, unit: usize, target: i32) {
        self.resolve_action(state, unit, target);
        let category = self.units[unit].unit_type.tactical_category();
        if matches!(
            category,
            ArmyUnitCategory::LightCavalry | ArmyUnitCategory::HeavyCavalry
        ) && self.has_adjacent_reachable(self.selected.unwrap_or(unit))
        {
            if self.outcome != BattleOutcome::InProgress {
                self.finish_action();
            }
            return;
        }
        self.finish_action();
    }

    fn has_adjacent_reachable(&self, unit: usize) -> bool {
        for &neighbor in self.neighbors(self.units[unit].tile).values() {
            if neighbor != -1 {
                let cost = self.cost(neighbor);
                if cost != -1 && i32::from(cost) <= self.units[unit].action_points {
                    return true;
                }
            }
        }
        false
    }

    fn has_followup(&self, unit: usize) -> bool {
        let category = self.units[unit].unit_type.tactical_category();
        if category == ArmyUnitCategory::Generals {
            return self
                .neighbors(self.units[unit].tile)
                .values()
                .any(|&neighbor| {
                    neighbor != -1
                        && self.tiles[neighbor as usize]
                            .occupant
                            .is_some_and(|occ| self.units[occ].side == self.units[unit].side)
                });
        }
        if category == ArmyUnitCategory::Engineers {
            return false;
        }
        let enemy = self.units[unit].side.opponent();
        self.sides[enemy].units.iter().any(|&idx| {
            self.units[idx].tile >= 0
                && self.units[unit].selected
                && self.reachable_for_action(
                    self.units[unit].tile,
                    self.units[idx].tile,
                    direct_fire(self.units[unit].unit_type.tactical_category()),
                    self.unit_range(unit),
                )
        })
    }

    fn move_toward(&mut self, state: &mut GameState, unit: usize, target: i32) -> Vec<TacticalHex> {
        let mut moved = TacticalHex::from_index(self.units[unit].tile)
            .into_iter()
            .collect::<Vec<_>>();
        let mut path = [0; 12];
        path[0] = target;
        let mut step_count = self.build_path(target, 0, self.units[unit].tile, &mut path, state);
        if step_count == -1 {
            return moved;
        }
        if step_count != 0 {
            let mut stopped = false;
            while step_count != 0 && !stopped {
                let from = path[step_count as usize];
                let to = path[(step_count - 1) as usize];
                self.move_between(unit, from, to);
                if let Some(hex) = TacticalHex::from_index(to) {
                    moved.push(hex);
                }
                step_count -= 1;
                stopped = self.reaction_fire(state, path[step_count as usize]);
            }
        }
        self.units[unit].action_points -= i32::from(self.cost(path[step_count as usize]));
        let arrived = path[step_count as usize];
        let exit_column = (((arrived / 29) & 1) + 2 * (arrived % 29)) / 2;
        let side = self.units[unit].side;
        if (side == BattleSide::Defender && exit_column >= self.column_count - 1)
            || (side == BattleSide::Attacker && exit_column == 0)
        {
            // Headless unbroken-morale path leaves unitMayLeave uninitialized in retail.
            // Use 0 (do not leave) for determinism.
            let unit_may_leave = self.units[unit].state == TacticalUnitState::MoraleBroken;
            if unit_may_leave {
                self.units[unit].state = TacticalUnitState::Retreated;
                self.tiles[arrived as usize].occupant = None;
                self.units[unit].tile = -2;
                self.evaluate_outcome();
            }
        }
        self.compute_reachable(unit);
        moved
    }

    fn build_path(
        &mut self,
        walk: i32,
        depth: i32,
        goal: i32,
        out: &mut [i32; 12],
        state: &mut GameState,
    ) -> i32 {
        // Retail writes a 12-slot path buffer with no depth cap.
        if depth < 0 || depth >= out.len() as i32 {
            return -1;
        }
        if walk == goal {
            out[depth as usize] = walk;
            return depth;
        }
        let walk_cost = self.cost(walk);
        let neighbors = self.neighbors(walk);
        let mut candidates = [0; 6];
        let mut count = 0;
        for &neighbor in neighbors.values() {
            let neighbor_cost = self.cost(neighbor);
            if neighbor_cost != -1 && neighbor_cost < walk_cost {
                candidates[count] = neighbor;
                count += 1;
            }
        }
        if count == 0 {
            return -1;
        }
        if count > 1 {
            for outer in 0..count - 1 {
                for inner in 1..count {
                    let next_tile = candidates[inner];
                    let cur_tile = candidates[outer];
                    let mut swap = self.cost(next_tile) < self.cost(cur_tile);
                    if !swap && self.cost(next_tile) == self.cost(cur_tile) {
                        let next_threat = self.threat.get(next_tile as usize).copied().unwrap_or(0);
                        let cur_threat = self.threat.get(cur_tile as usize).copied().unwrap_or(0);
                        if next_threat == 0 {
                            swap = if cur_threat != 0 {
                                true
                            } else {
                                state.rng.next_crt_rand() & 1 != 0
                            };
                        } else if cur_threat != 0 {
                            swap = state.rng.next_crt_rand() & 1 != 0;
                        }
                    }
                    if swap {
                        candidates[outer] = next_tile;
                        candidates[inner] = cur_tile;
                    }
                }
            }
        }
        for &candidate in candidates.iter().take(count) {
            let found = self.build_path(candidate, depth + 1, goal, out, state);
            if found != -1 {
                out[depth as usize] = walk;
                return found;
            }
        }
        -1
    }

    fn move_between(&mut self, unit: usize, from: i32, to: i32) {
        if let (Some(from), Some(to)) = (TacticalHex::from_index(from), TacticalHex::from_index(to))
        {
            self.events.push(ArmyBattleEvent::Move {
                unit: ArmyUnitId(self.units[unit].source),
                from,
                to,
            });
        }
        self.tiles[from as usize].occupant = None;
        self.units[unit].tile = to;
        self.tiles[to as usize].occupant = Some(unit);
    }

    fn reaction_fire(&mut self, state: &mut GameState, tile: i32) -> bool {
        let Some(occupant) = self.tiles[tile as usize].occupant else {
            return false;
        };
        let reacting = self.units[occupant].side.opponent();
        let reactors = self.sides[reacting].units.clone();
        let mut fired = false;
        for reactor in reactors {
            if self.units[reactor].state == TacticalUnitState::Ready && self.units[reactor].selected
            {
                let category = self.units[reactor].unit_type.tactical_category();
                if self.reachable_for_action(
                    self.units[reactor].tile,
                    tile,
                    direct_fire(category),
                    self.unit_range(reactor),
                ) {
                    self.resolve_action(state, reactor, tile);
                    fired = true;
                }
            }
            if self.units[occupant].strength == 0 {
                break;
            }
        }
        fired
    }

    fn resolve_action(&mut self, _state: &mut GameState, attacker: usize, target: i32) {
        let defender = self.tiles[target as usize].occupant;
        let fort_wall_targeted = self.tiles[target as usize].deploy_mark.is_fort_wall()
            && self.fort_strength[(target / TACTICAL_STRIDE / 2) as usize] > 0
            && defender.is_none();
        if let Some(target) = TacticalHex::from_index(target) {
            self.events.push(ArmyBattleEvent::Attack {
                attacker: ArmyUnitId(self.units[attacker].source),
                target,
                fort_target: fort_wall_targeted,
            });
        }
        let wall = self.wall_on_firing_line(target, self.units[attacker].tile);
        let mut melee = self
            .neighbors(self.units[attacker].tile)
            .values()
            .any(|&neighbor| neighbor == target);
        if wall != 0
            && self.tiles[wall as usize].deploy_mark.is_fort_wall()
            && self.fort_strength[(wall / TACTICAL_STRIDE / 2) as usize] > 0
        {
            melee = false;
        }
        let attacker_category = self.units[attacker].unit_type.tactical_category();
        let mut strength_factor = 1.0 - f64::from(self.units[attacker].quality) * -0.1;
        strength_factor *= f64::from(BASE_ATTACK_POWER[self.units[attacker].unit_type]);
        if melee {
            strength_factor *= f64::from(MELEE_MULTIPLIER[attacker_category]);
        }
        let attack_power = self.units[attacker].strength as f32
            * strength_factor as f32
            * ATTACK_TERRAIN[attacker_category]
                [self.tiles[self.units[attacker].tile as usize].terrain];
        if fort_wall_targeted {
            self.consume_fort(wall, (0.001 * attack_power) as i32);
            return;
        }
        let Some(defender) = defender else {
            return;
        };
        let defender_category = self.units[defender].unit_type.tactical_category();
        let mut damage = DEFENSE_TERRAIN[defender_category][self.tiles[target as usize].terrain]
            * DAMAGE_SCALE[self.units[defender].unit_type]
            * attack_power;
        if wall != 0
            && self.tiles[wall as usize].deploy_mark.is_fort_wall()
            && self.fort_strength[(wall / TACTICAL_STRIDE / 2) as usize] > 0
        {
            if !direct_fire(attacker_category) {
                self.consume_fort(wall, (0.001 * attack_power) as i32);
            }
            damage *= cover_damage(defender_category, self.tiles[wall as usize].deploy_mark);
        }
        if self.tiles[target as usize].deploy_mark == DeployMark::UnitCover
            && hex_distance(self.units[attacker].tile, target) > 1
        {
            damage *= COVER_DAMAGE[defender_category][1];
        }
        let mut leader = 2.0f32;
        let defender_side = self.units[defender].side;
        for &idx in &self.sides[defender_side].units {
            if general(self.units[idx].unit_type)
                && self.units[idx].state == TacticalUnitState::Ready
            {
                let value = (2.0 - f64::from(self.units[idx].quality) * 0.2 - 0.2) as f32;
                if value < leader {
                    leader = value;
                }
            }
        }
        let morale_damage = leader * damage;
        self.apply_damage(defender, damage as i32, morale_damage as i32);
        self.units[attacker].selected = false;
        self.sides[defender_side].field20 = false;
    }

    fn apply_damage(&mut self, target: usize, damage_a: i32, damage_b: i32) {
        self.units[target].morale -= damage_b;
        if self.units[target].morale <= 0 {
            self.units[target].morale = 0;
            self.units[target].state = TacticalUnitState::MoraleBroken;
        }
        self.units[target].strength -= damage_a;
        if self.units[target].strength <= 0 {
            self.units[target].strength = 0;
            self.units[target].state = TacticalUnitState::Destroyed;
        }
        if self.units[target].state == TacticalUnitState::Destroyed {
            let tile = self.units[target].tile;
            if tile >= 0 {
                self.tiles[tile as usize].occupant = None;
            }
            self.units[target].tile = -1;
        }
        self.evaluate_outcome();
    }

    fn process_morale_broken(&mut self, state: &mut GameState, unit: usize) {
        let original = self.units[unit].tile;
        self.build_distance_field(self.units[unit].side == BattleSide::Attacker);
        let mut best_distance = 999;
        let mut best_tile = original;
        for tile in 0..TACTICAL_TILE_COUNT as i32 {
            if self.cost(tile) != -1
                && self.distance_field[tile as usize] != -1
                && (self.distance_field[tile as usize] < best_distance
                    || (self.distance_field[tile as usize] == best_distance
                        && state.rng.next_crt_rand() & 1 != 0))
            {
                best_distance = self.distance_field[tile as usize];
                best_tile = tile;
            }
        }
        if best_tile != self.units[unit].tile {
            let _ = self.move_toward(state, unit, best_tile);
        }
        if self.units[unit].state == TacticalUnitState::MoraleBroken {
            let enemy = self.units[unit].side.opponent();
            let mut nearby = 0;
            for &idx in &self.sides[enemy].units {
                if self.units[idx].state != TacticalUnitState::Ready {
                    continue;
                }
                if hex_distance(self.units[unit].tile, self.units[idx].tile) < 3 {
                    nearby += (BASE_ATTACK_POWER[self.units[idx].unit_type]
                        * self.units[idx].strength as f32) as i32;
                }
            }
            let own = (BASE_ATTACK_POWER[self.units[unit].unit_type]
                * (self.units[unit].strength * 3) as f32) as i32;
            if nearby > own {
                nearby = own;
            }
            let mut destroy = true;
            if self.units[unit].tile != original {
                destroy = false;
                if nearby > 0 {
                    let remainder = state.rng.next_crt_rand() % nearby;
                    if (BASE_ATTACK_POWER[self.units[unit].unit_type]
                        * (self.units[unit].strength as f32))
                        < (remainder as f32)
                    {
                        destroy = true;
                    }
                }
            }
            if destroy {
                let strength = self.units[unit].strength;
                self.apply_damage(unit, strength, 0);
            }
        }
        self.evaluate_outcome();
        self.finish_action();
    }

    fn advance_mine_run(&mut self, unit: usize) {
        let target = self.units[unit].sap_target;
        if !self.tiles[target as usize].deploy_mark.is_fort_wall() {
            self.units[unit].sap_target = -1;
            return;
        }
        let mut run = self.units[unit].tile;
        if run != target {
            loop {
                if self.tiles[run as usize].mine_run == MineRun::None {
                    break;
                }
                run -= TACTICAL_STRIDE;
                if run == target {
                    break;
                }
            }
        }
        if run == target {
            self.tiles[self.units[unit].sap_target as usize].deploy_mark = DeployMark::Clear;
            self.units[unit].sap_target = -1;
        } else if ((run / TACTICAL_STRIDE) & 1) != 0 {
            self.tiles[run as usize].mine_run = MineRun::First;
        } else {
            self.tiles[run as usize].mine_run = MineRun::Second;
        }
        if self.units[unit].action_points == 0 {
            self.finish_action();
            return;
        }
        self.units[unit].action_points = 0;
    }

    fn mine(&mut self, state: &mut GameState, unit: usize, tile: i32) {
        if let Some(target) = TacticalHex::from_index(tile) {
            self.events.push(ArmyBattleEvent::Mine { target });
        }
        let amount =
            state.rng.next_crt_rand() % 400 + self.units[unit].unit_type as i32 * 250 - 5600;
        self.consume_fort(tile, amount);
        self.finish_action();
    }

    fn dig(&mut self, state: &mut GameState, unit: usize, tile: i32) -> Vec<TacticalHex> {
        let before = self.units[unit].action_points;
        self.dig_trench(unit, tile);
        let path = self.move_toward(state, unit, tile);
        self.units[unit].action_points =
            before - BASE_ACTION_POINTS[self.units[unit].unit_type] / 2;
        self.compute_reachable(unit);
        if self.units[unit].action_points == 0 {
            self.finish_action();
        }
        path
    }

    fn dig_trench(&mut self, unit: usize, target: i32) {
        let from = self.units[unit].tile;
        let neighbors = self.neighbors(from);
        let direction = HexDirection::ALL
            .into_iter()
            .find(|&direction| neighbors[direction] == target)
            .expect("trench target must neighbor its source");
        let src = self.tiles[from as usize].trench_mask;
        if src == 0 {
            self.tiles[from as usize].trench_mask = 0x80;
        } else {
            self.tiles[from as usize].trench_mask = (src & 0x7f) | 0x40;
        }
        self.tiles[from as usize].trench_mask |= direction.bit();
        let dst = self.tiles[target as usize].trench_mask;
        if dst != 0 {
            self.tiles[target as usize].trench_mask = (dst & 0x7f) | 0x40;
        }
        self.tiles[target as usize].trench_mask |= direction.opposite().bit();
    }

    fn rally(&mut self, state: &mut GameState, rallier: usize, target: usize) {
        self.events.push(ArmyBattleEvent::Rally);
        let mut new_state = self.units[target].state;
        let mut new_morale = self.units[target].morale;
        if new_state == TacticalUnitState::Ready {
            new_morale +=
                self.units[target].strength / 10 * (i32::from(self.units[rallier].quality) + 3);
        } else if new_state == TacticalUnitState::MoraleBroken {
            let quality = i32::from(self.units[rallier].quality);
            if state.rng.next_crt_rand() % 100 < (quality + 5) * 10 {
                new_morale = self.units[target].strength / 10 + 20;
                new_state = TacticalUnitState::Ready;
            }
        }
        let strength = self.units[target].strength;
        self.units[target].state = new_state;
        self.units[target].morale = new_morale.min(strength);
        self.finish_action();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn side(is_our: bool) -> Side {
        Side {
            is_our,
            ready: false,
            auto_play: false,
            nation: NationId::new(0),
            cursor: 0,
            units: Vec::new(),
            secondary: Vec::new(),
            projection_sums: ActionClassScores::default(),
            baseline_similarity: 0.0,
            composition_similarity: 0.0,
            max_range: 0,
            max_non_artillery_range: 0,
            field20: false,
            allow_broken_targets: false,
            has_artillery_or_engineers: false,
            field_f: false,
            last_stance: None,
            retreat_toward_north: false,
            cached_bombard_tile: -1,
        }
    }

    fn unit(tile: i32, side: BattleSide) -> TacUnit {
        TacUnit {
            source: MilitaryUnitId::from_serialized(0),
            unit_type: MilitaryUnitKind::Minutemen,
            tile,
            selected: false,
            state: TacticalUnitState::Ready,
            action_points: 10,
            ai_state: 0,
            strength: 100,
            morale: 100,
            quality: 0,
            sap_target: -1,
            flag3c: false,
            side,
            field24: 0,
            projection: ActionClassScores::default(),
            attack_target: None,
        }
    }

    fn battle() -> Battle {
        Battle {
            tiles: [Tile {
                terrain: TacticalTerrain::Class0,
                occupant: None,
                deploy_mark: DeployMark::Clear,
                mine_run: MineRun::None,
                trench_mask: 0,
            }; TACTICAL_TILE_COUNT],
            move_costs: [-1; TACTICAL_TILE_COUNT + 1],
            threat: [0; TACTICAL_TILE_COUNT],
            candidate_scores: [0; TACTICAL_TILE_COUNT],
            distance_field: [0; TACTICAL_TILE_COUNT],
            units: Vec::new(),
            sides: BattleSideTable::from_array([side(true), side(false)]),
            records: Vec::new(),
            current_side: BattleSide::Defender,
            selected: None,
            column_count: TACTICAL_STRIDE,
            outcome: BattleOutcome::InProgress,
            pending_end: false,
            fort_level: FortLevel::None,
            fort_strength: [0; 8],
            battle_site: ProvinceId::new(0),
            round: 0,
            composition_class: 0,
            live: false,
            events: Vec::new(),
        }
    }

    #[test]
    fn retail_second_flank_bug_blocks_reachability_from_the_east_slot() {
        let source = TACTICAL_STRIDE * 8 + 10;
        let direction = HexDirection::SouthWest;
        let neighbors = neighbor_list(source);
        let target = neighbors[direction];
        let east_blocker = neighbors[HexDirection::East];

        assert_ne!(
            retail_second_flank_direction(direction),
            direction.next_clockwise()
        );

        let mut battle = battle();
        battle.units.push(unit(source, BattleSide::Defender));
        battle.units.push(unit(east_blocker, BattleSide::Attacker));
        battle.tiles[source as usize].occupant = Some(0);
        battle.tiles[east_blocker as usize].occupant = Some(1);

        battle.compute_reachable(0);

        assert_eq!(battle.cost(target), -1);
    }

    fn seed_province(state: &mut GameState, province: u16, owner: u8, adjacency: &[u16]) {
        state.map.provinces[ProvinceId::new(province)] = ProvinceState::new(
            Some(NationId::new(owner)),
            Some(NationId::new(owner)),
            ProvinceDevelopmentStage::None,
            adjacency.iter().copied().map(ProvinceId::new).collect(),
            vec![TileId::new(0); adjacency.len()],
            Some(0),
            FortLevel::None,
            None,
            0,
            None,
            None,
            Vec::new(),
            ResourceTable::default(),
            MajorNationTable::default(),
            0,
            false,
            0,
            String::new(),
        );
    }

    fn push_unit(
        state: &mut GameState,
        nation: u8,
        province: u16,
        kind: MilitaryUnitKind,
        dest: Option<u16>,
    ) -> MilitaryUnitId {
        let id = state.unit_ids.next_military();
        let province = ProvinceId::new(province);
        let order = match dest {
            Some(dest) => MilitaryOrder::retail(
                MilitaryOrderCode::Redeploy,
                Some(ProvinceId::new(dest)),
                [Some(province); 3],
                [Some(province); 3],
            ),
            None => MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
        };
        state.military_units.insert(
            id,
            MilitaryUnitState::new(
                NationId::new(nation),
                kind,
                Some(province),
                order,
                NationId::new(nation),
                0,
                true,
                String::new(),
                400,
                kind.spawn_era(),
                0,
                0,
            ),
        );
        id
    }

    fn pending_regulars_vs_militia() -> (GameState, MilitaryUnitId, MilitaryUnitId) {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.turn.phase = crate::PhaseCode::COMBAT_MOVES;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        let attacker = push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        let defender = push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationships[NationId::new(1)][NationId::new(0)] =
            DiplomaticRelationship::War;
        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        (state, attacker, defender)
    }

    #[test]
    fn deploy_hover_classifies_deploy_invalid_undeploy_and_wait() {
        let mut state = game_state();
        state.turn.economic_turn = 3;
        state.turn.phase = crate::PhaseCode::COMBAT_MOVES;
        seed_province(&mut state, 1, 0, &[2]);
        seed_province(&mut state, 2, 1, &[1]);
        push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        push_unit(&mut state, 0, 1, MilitaryUnitKind::Regulars, Some(2));
        push_unit(&mut state, 1, 2, MilitaryUnitKind::Militia, None);
        state.diplomacy.relationships[NationId::new(0)][NationId::new(1)] =
            DiplomaticRelationship::War;
        state.diplomacy.relationships[NationId::new(1)][NationId::new(0)] =
            DiplomaticRelationship::War;
        assert_eq!(state.advance_turn(), crate::TurnStop::LandBattle);
        state.ensure_army_battle();
        let nation = state.turn.active_nation;
        let deploy = state
            .selected_army_unit_reachable_hexes()
            .into_iter()
            .next()
            .expect("deployment hex");
        {
            let battle = state.army_battle().expect("interactive battle");
            assert_eq!(battle.hover_action(deploy, nation), HoverAction::Deploy);
            let blocked = (0..TACTICAL_TILE_COUNT as i32)
                .filter_map(TacticalHex::from_index)
                .find(|&hex| battle.hover_action(hex, nation) == HoverAction::Invalid)
                .expect("blocked hex");
            assert_eq!(battle.hover_action(blocked, nation), HoverAction::Invalid);
            let other = if battle.nation(battle.active_side()) == NationId::new(0) {
                NationId::new(1)
            } else {
                NationId::new(0)
            };
            assert_eq!(battle.hover_action(deploy, other), HoverAction::Wait);
        }
        state.army_action_at(deploy).unwrap();
        let battle = state.army_battle().expect("battle remains after deploy");
        assert_eq!(battle.stage(), ArmyBattleStage::Deploying);
        assert_eq!(battle.hover_action(deploy, nation), HoverAction::Undeploy);
    }

    fn deploy_local_side(state: &mut GameState) {
        state.ensure_army_battle();
        while state.army_battle().unwrap().stage() == ArmyBattleStage::Deploying {
            let target = state
                .selected_army_unit_reachable_hexes()
                .into_iter()
                .next()
                .expect("local unit has a deployment tile");
            state.army_action_at(target).unwrap();
        }
    }

    #[test]
    fn live_hover_classifies_move_on_a_reachable_empty_hex() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let nation = state.turn.active_nation;
        let hex = state
            .selected_army_unit_reachable_hexes()
            .into_iter()
            .next()
            .expect("live unit has a reachable hex");
        let battle = state.army_battle().expect("live battle");
        assert_eq!(battle.stage(), ArmyBattleStage::Live);
        assert_eq!(battle.hover_action(hex, nation), HoverAction::Move);
    }

    #[test]
    fn live_army_battle_round_trip_preserves_semantic_state_and_continuation() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        {
            let battle = state.army_battle_mut().expect("live battle");
            let selected = battle.inner.selected.expect("selected source unit");
            battle.inner.units[selected].ai_state = 7;
            battle.inner.units[selected].field24 = 19;
            battle.inner.units[selected].morale -= 3;
            battle.inner.tiles[31].trench_mask = 0x81;
            battle.inner.fort_level = FortLevel::Two;
            battle.inner.fort_strength = [123; 8];
            battle.inner.composition_class = 3;
        }
        let expected_selected = state.selected_army_unit().unwrap().id.source();
        let encoded = serde_json::to_vec(&state).expect("serialize live battle");
        let mut restored: GameState =
            serde_json::from_slice(&encoded).expect("deserialize live battle");

        let restored_battle = restored.army_battle().expect("restored live battle");
        assert_eq!(restored_battle.stage(), ArmyBattleStage::Live);
        assert_eq!(
            restored_battle.active_side(),
            state.army_battle().unwrap().active_side()
        );
        assert_eq!(
            restored.selected_army_unit().unwrap().id.source(),
            expected_selected
        );
        assert_eq!(
            restored_battle.inner.units[restored_battle.inner.selected.unwrap()].ai_state,
            7
        );
        assert_eq!(
            restored_battle.inner.units[restored_battle.inner.selected.unwrap()].field24,
            19
        );
        assert_eq!(restored_battle.inner.tiles[31].trench_mask, 0x81);
        assert_eq!(restored_battle.inner.fort_level, FortLevel::Two);
        assert_eq!(restored_battle.inner.fort_strength, [123; 8]);
        assert_eq!(restored_battle.inner.composition_class, 3);
        assert_eq!(
            state.selected_army_unit_reachable_hexes(),
            restored.selected_army_unit_reachable_hexes()
        );

        let target = state
            .selected_army_unit_reachable_hexes()
            .into_iter()
            .next()
            .expect("restored selection remains actionable");
        assert_eq!(
            state.army_action_at(target),
            restored.army_action_at(target)
        );
        assert_eq!(
            state.army_battle_differential_snapshot(),
            restored.army_battle_differential_snapshot()
        );
        assert_eq!(state.rng, restored.rng);
    }

    #[test]
    fn interactive_battle_waits_for_local_deployment() {
        let (mut state, attacker, defender) = pending_regulars_vs_militia();
        let battle = state.ensure_army_battle();
        let units: Vec<_> = battle.units().collect();
        assert_eq!(units.len(), 2);
        let attacker_unit = units
            .iter()
            .find(|unit| unit.id.source() == attacker)
            .unwrap();
        let defender_unit = units
            .iter()
            .find(|unit| unit.id.source() == defender)
            .unwrap();
        assert_eq!(attacker_unit.side, BattleSide::Attacker);
        assert_eq!(defender_unit.side, BattleSide::Defender);
        assert_eq!(battle.stage(), ArmyBattleStage::Deploying);
        assert_eq!(battle.active_side(), BattleSide::Attacker);
        assert_eq!(attacker_unit.hex, None);
        let defender_hex = defender_unit.hex.expect("defender deploys");
        let columns = battle.column_count();
        assert!(
            defender_hex.column() <= columns - 3 && defender_hex.column() >= columns - 5,
            "defender column {} in zone for width {columns}",
            defender_hex.column()
        );
    }

    #[test]
    fn deployment_done_keeps_core_selection_on_an_undeployed_unit() {
        let (mut state, attacker, _) = pending_regulars_vs_militia();
        state.ensure_army_battle();

        assert_eq!(state.finish_selected_army_unit_action().unwrap().stop, None);
        let selected = state
            .selected_army_unit()
            .expect("deployment selection remains");
        assert_eq!(selected.id.source(), attacker);
        assert_eq!(selected.hex, None);
        assert_eq!(
            state.army_battle().unwrap().stage(),
            ArmyBattleStage::Deploying
        );
    }

    #[test]
    fn pre_live_retreat_hands_deployment_to_the_other_side() {
        let (mut state, _, defender) = pending_regulars_vs_militia();
        state.turn.active_nation = NationId::new(1);
        state.ensure_army_battle();
        assert_eq!(
            state.army_battle().unwrap().active_side(),
            BattleSide::Defender
        );

        assert_eq!(state.retreat_from_army_battle().unwrap().stop, None);

        let battle = state.army_battle().expect("deployment remains interactive");
        assert_eq!(battle.stage(), ArmyBattleStage::Deploying);
        assert_eq!(battle.active_side(), BattleSide::Defender);
        assert_eq!(
            battle.unit(ArmyUnitId(defender)).and_then(|unit| unit.hex),
            None
        );
        assert!(
            battle
                .units()
                .any(|unit| unit.side == BattleSide::Attacker && unit.hex.is_some()),
            "unwatched attacker auto-deploys during the handoff"
        );
    }

    #[test]
    fn reachable_hexes_include_a_legal_step_and_move_updates_the_unit_tile() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let selected = state
            .selected_army_unit()
            .expect("the active nation receives a selected unit");
        let origin = selected.hex.expect("selected unit is on the grid");
        let destinations = state.selected_army_unit_reachable_hexes();
        assert!(
            destinations.iter().any(|hex| hex.index() != origin.index()),
            "selected unit has at least one destination after auto-deploy"
        );
        let destination = destinations
            .iter()
            .copied()
            .find(|hex| hex.column() != origin.column() || hex.row() != origin.row())
            .expect("a distinct destination exists");
        let (action, stop) = state
            .army_action_at(destination)
            .expect("core accepts a reachable hex");
        let ArmyAction::Move(moved) = action else {
            panic!("reachable empty hex moves the selected unit");
        };
        assert_eq!(stop.stop, None);
        assert_eq!(moved.from, origin);
        let after = state
            .army_battle()
            .and_then(|battle| battle.unit(selected.id))
            .and_then(|unit| unit.hex)
            .expect("moved unit remains on the grid");
        assert_eq!(after, moved.to);
        assert_ne!(after, origin);
    }

    #[test]
    fn unreachable_hex_is_rejected_without_moving() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let selected = state.selected_army_unit().expect("selected unit");
        let origin = selected.hex.expect("selected unit is on the grid");
        let far = TacticalHex::from_row_column(1, 20).expect("grid contains column 20");
        assert_eq!(
            state.army_action_at(far),
            Err(ArmyActionRejection::InvalidTarget)
        );
        let after = state
            .army_battle()
            .and_then(|battle| battle.unit(selected.id))
            .and_then(|unit| unit.hex)
            .expect("unit stays deployed");
        assert_eq!(after, origin);
    }

    #[test]
    fn occupied_enemy_hex_does_not_change_the_core_selection() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let selected = state.selected_army_unit().expect("selected unit");
        let enemy_hex = state
            .army_battle()
            .expect("live battle")
            .units()
            .find(|unit| unit.side != selected.side)
            .and_then(|unit| unit.hex)
            .expect("enemy is deployed");

        assert_eq!(
            state.army_action_at(enemy_hex),
            Err(ArmyActionRejection::InvalidTarget)
        );
        assert_eq!(state.selected_army_unit(), Some(selected));
    }

    #[test]
    fn reachable_enemy_hex_attacks_with_the_core_selected_unit() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let (attacker, target) = {
            let battle = state.army_battle_mut().expect("live battle");
            let attacker = battle.inner.selected.expect("selected unit");
            let defender = battle.inner.sides[battle.inner.current_side.opponent()].units[0];
            let old_target = battle.inner.units[defender].tile;
            battle.inner.tiles[old_target as usize].occupant = None;
            let target = battle
                .inner
                .neighbors(battle.inner.units[attacker].tile)
                .values()
                .copied()
                .find(|&tile| {
                    tile >= 0
                        && battle.inner.tiles[tile as usize].occupant.is_none()
                        && !battle.inner.tiles[tile as usize].deploy_mark.is_fort_wall()
                })
                .expect("selected unit has an open adjacent tile");
            battle.inner.units[defender].tile = target;
            battle.inner.units[defender].strength = 500;
            battle.inner.units[defender].morale = 500;
            battle.inner.tiles[target as usize].occupant = Some(defender);
            (
                ArmyUnitId(battle.inner.units[attacker].source),
                TacticalHex::from_index(target).unwrap(),
            )
        };

        let (action, _) = state
            .army_action_at(target)
            .expect("adjacent enemy is a valid attack target");
        assert_eq!(action, ArmyAction::Attack { attacker, target });
    }

    #[test]
    fn active_nation_cannot_move_the_other_tactical_controller() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let selected = state.selected_army_unit().expect("selected unit");
        let destination = state
            .selected_army_unit_reachable_hexes()
            .iter()
            .copied()
            .find(|hex| Some(*hex) != selected.hex)
            .expect("selected unit has a destination");
        let selected_side = selected.side;
        let other_nation =
            state.army_battle().expect("live battle").inner.sides[selected_side.opponent()].nation;
        state.turn.active_nation = other_nation;

        assert_eq!(
            state.army_action_at(destination),
            Err(ArmyActionRejection::NotControlled)
        );
        assert!(state.selected_army_unit_reachable_hexes().is_empty());
    }

    #[test]
    fn movement_ending_an_action_advances_to_exactly_the_next_unit() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let active_nation = state.turn.active_nation;
        let (before, expected, destination) = {
            let battle = state.army_battle_mut().expect("live battle");
            let selected = battle.inner.selected.expect("selected unit");
            battle.inner.compute_reachable(selected);
            let destination = (0..TACTICAL_TILE_COUNT as i32)
                .filter(|&tile| battle.inner.cost(tile) > 0)
                .max_by_key(|&tile| battle.inner.cost(tile))
                .and_then(TacticalHex::from_index)
                .expect("selected unit has a destination");
            let move_cost = i32::from(battle.inner.cost(destination.index()));
            let mut probe = battle.inner.clone();
            let expected = probe
                .select_next_record_unit()
                .map(|unit| ArmyUnitId(probe.units[unit].source))
                .expect("another tactical unit follows");
            battle.inner.sides[BattleSide::Attacker].nation = active_nation;
            battle.inner.sides[BattleSide::Defender].nation = active_nation;
            battle.inner.sides[BattleSide::Attacker].auto_play = false;
            battle.inner.sides[BattleSide::Defender].auto_play = false;
            battle.inner.units[selected].action_points = move_cost;
            (
                ArmyUnitId(battle.inner.units[selected].source),
                expected,
                destination,
            )
        };

        let (_, stop) = state
            .army_action_at(destination)
            .expect("destination remains reachable at the exact action-point budget");
        assert_eq!(stop.stop, None);
        assert_ne!(before, expected);
        assert_eq!(
            state.selected_army_unit().map(|unit| unit.id),
            Some(expected)
        );
    }

    #[test]
    fn done_advances_to_exactly_the_next_unit() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let active_nation = state.turn.active_nation;
        let expected = {
            let battle = state.army_battle_mut().expect("live battle");
            battle.inner.sides[BattleSide::Attacker].nation = active_nation;
            battle.inner.sides[BattleSide::Defender].nation = active_nation;
            battle.inner.sides[BattleSide::Attacker].auto_play = false;
            battle.inner.sides[BattleSide::Defender].auto_play = false;
            let mut probe = battle.inner.clone();
            probe
                .select_next_record_unit()
                .map(|unit| ArmyUnitId(probe.units[unit].source))
                .expect("another tactical unit follows")
        };

        assert_eq!(state.finish_selected_army_unit_action().unwrap().stop, None);
        assert_eq!(
            state.selected_army_unit().map(|unit| unit.id),
            Some(expected)
        );
    }

    #[test]
    fn retreat_uses_the_tactical_players_retreat_stance() {
        let (mut state, _, _) = pending_regulars_vs_militia();
        deploy_local_side(&mut state);
        let active_nation = state.turn.active_nation;
        let reports_before = state.battle_reports().len();

        let stop = state
            .retreat_from_army_battle()
            .expect("active tactical player may retreat");

        assert!(
            stop.stop.is_some(),
            "retreat auto-runs until the battle ends"
        );
        assert_eq!(state.battle_reports().len(), reports_before + 1);
        let report = state.battle_reports().last().expect("battle was committed");
        assert_ne!(
            report.sides[report.participant.expect("battle report has a winner")].nation,
            active_nation
        );
        assert_eq!(
            state.retreat_from_army_battle(),
            Err(ArmyActionRejection::NoLiveBattle)
        );
        assert_eq!(state.battle_reports().len(), reports_before + 1);
    }

    #[test]
    fn interactive_initialization_then_auto_matches_direct_auto_and_rng() {
        let (state, _, _) = pending_regulars_vs_militia();
        let mut direct = state.clone();
        let direct_stop = direct.auto_resolve_land_battle();
        let mut interactive = state;
        interactive.ensure_army_battle();
        let interactive_stop = interactive.auto_resolve_land_battle();

        assert_eq!(interactive_stop, direct_stop);
        assert_eq!(interactive.rng(), direct.rng());
        assert_eq!(interactive, direct);
    }
}
