use crate::{GameSnapshotV1, SnapshotValidationError, TileSnapshot};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GameState {
    pub turn: TurnState,
    pub world: WorldState,
    pub rng: RngState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnState {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i32,
    pub phase_code: i32,
    pub mode: i32,
    pub difficulty: i32,
    pub active_nation: i32,
    pub selected_nation: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldState {
    pub width: u16,
    pub height: u16,
    pub wraps_horizontally: bool,
    pub tiles: Vec<TileState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TileState {
    pub terrain_kind: i64,
    pub owner_nation: i64,
    pub former_owner_nation: i64,
    pub city_or_province_index: i64,
    pub development_classes: i64,
    pub edge_resources: [i64; 2],
    pub rail_flags: i64,
    pub action_state: i64,
    pub active_flags: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RngState {
    pub crt_rand: u32,
    pub map_generation: u32,
    pub zone_status: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GameCommand {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GameEvent {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StepOutcome {
    pub events: Vec<GameEvent>,
}

impl TryFrom<GameSnapshotV1> for GameState {
    type Error = SnapshotValidationError;

    fn try_from(snapshot: GameSnapshotV1) -> Result<Self, Self::Error> {
        snapshot.verify_hashes()?;
        Ok(Self {
            turn: TurnState {
                scenario_map_index_plus_one: snapshot.metadata.scenario_map_index_plus_one,
                economic_turn: snapshot.metadata.economic_turn,
                phase_code: snapshot.metadata.turn_state,
                mode: snapshot.metadata.mode,
                difficulty: snapshot.metadata.difficulty,
                active_nation: snapshot.metadata.active_nation,
                selected_nation: snapshot.metadata.selected_nation,
            },
            world: WorldState {
                width: snapshot.world.width,
                height: snapshot.world.height,
                wraps_horizontally: snapshot.world.wrap != 0,
                tiles: snapshot
                    .world
                    .tiles
                    .into_iter()
                    .map(TileState::from)
                    .collect(),
            },
            rng: RngState {
                crt_rand: snapshot.rng.crt_rand_state,
                map_generation: snapshot.rng.map_generation_lcg,
                zone_status: snapshot.rng.zone_status_lcg,
            },
        })
    }
}

impl From<TileSnapshot> for TileState {
    fn from(snapshot: TileSnapshot) -> Self {
        let fields = snapshot.0;
        Self {
            terrain_kind: fields[0],
            owner_nation: fields[1],
            former_owner_nation: fields[2],
            city_or_province_index: fields[3],
            development_classes: fields[4],
            edge_resources: [fields[5], fields[6]],
            rail_flags: fields[7],
            action_state: fields[8],
            active_flags: fields[9],
        }
    }
}
