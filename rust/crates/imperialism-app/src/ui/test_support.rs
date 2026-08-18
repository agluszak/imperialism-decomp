use imperialism_core::{GameState, GameStateParts, TileId};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};

pub const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

pub fn beginning_context() -> LegacyGameStateContext {
    LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 0,
    }
}

pub fn beginning_of_game() -> GameState {
    beginning_of_game_with(beginning_context())
}

pub fn beginning_map_view_origin() -> TileId {
    LegacySaveV62::parse(BEGINNING_OF_GAME).map_view_origin()
}

pub fn beginning_of_game_parts() -> GameStateParts {
    beginning_of_game_parts_with(beginning_context())
}

pub fn beginning_of_game_with(context: LegacyGameStateContext) -> GameState {
    LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(context)
}

pub fn beginning_of_game_parts_with(context: LegacyGameStateContext) -> GameStateParts {
    LegacySaveV62::parse(BEGINNING_OF_GAME).game_state_parts(context)
}

/// Zone-status LCG and nation used by strategic-map presentation tests.
pub fn strategic_map_beginning_context() -> LegacyGameStateContext {
    LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 3_916_827_792,
    }
}
