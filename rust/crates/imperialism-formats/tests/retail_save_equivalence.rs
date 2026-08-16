use imperialism_core::GameState;
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use imperialism_testkit::{assert_game_state_eq, run_runtime};

const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../fixtures/retail/beginning_of_game.imp");

#[test]
#[ignore = "requires the native runtime harness and Wine"]
fn beginning_save_projection_matches_cpp_loaded_state() -> anyhow::Result<()> {
    let runtime = run_runtime("load_saved_game")?;
    let expected: GameState = runtime.capture("game_state")?;

    let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
    let actual = save.game_state(LegacyGameStateContext {
        crt_rand_state: expected.rng().crt_rand.state(),
        map_generation_lcg: expected.rng().map_generation.state(),
        zone_status_lcg: expected.rng().zone_status.state(),
        selected_nation: expected.turn().selected_nation,
    });

    assert_game_state_eq(&expected, &actual)
}
