use imperialism_core::GameState;
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use imperialism_testkit::{assert_game_state_eq, run_retail_fixture_result};

const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../fixtures/retail/beginning_of_game.imp");

#[test]
#[ignore = "requires the native runtime harness and Wine"]
fn beginning_save_projection_matches_cpp_loaded_state() -> anyhow::Result<()> {
    let runtime = run_retail_fixture_result("load_saved_game", &["game_state"])?;
    let expected: GameState = runtime.capture("game_state")?;

    let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
    let mut actual = save.game_state(LegacyGameStateContext {
        crt_rand_state: expected.rng().crt_rand.state(),
        map_generation_lcg: expected.rng().map_generation.state(),
        zone_status_lcg: expected.rng().zone_status.state(),
        selected_nation: expected.turn().selected_nation,
    });

    // Map entry centers on the first idle civilian using the same retail viewport math.
    if let Some(tile) = actual.first_idle_civilian_tile(actual.turn().active_nation) {
        actual.center_map_on(tile);
    }
    assert_eq!(actual.map_view_origin(), expected.map_view_origin());

    assert_game_state_eq(&expected, &actual)
}
