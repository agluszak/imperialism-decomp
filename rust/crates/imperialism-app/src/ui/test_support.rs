use imperialism_core::{GameState, GameStateParts, NationId};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, peek_save_header};

pub const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

pub fn beginning_context() -> LegacyGameStateContext {
    fixture_context(BEGINNING_OF_GAME)
}

pub fn fixture_context(bytes: &[u8]) -> LegacyGameStateContext {
    let selected_nation = peek_save_header(bytes)
        .and_then(|header| NationId::try_new(header.active_nation))
        .unwrap_or(NationId::new(0));
    LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 0,
        selected_nation,
    }
}

pub fn beginning_of_game() -> GameState {
    beginning_of_game_with(beginning_context())
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
        selected_nation: NationId::new(6),
    }
}
