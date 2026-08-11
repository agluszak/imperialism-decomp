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

    let save = LegacySaveV62::parse(BEGINNING_OF_GAME)?;
    let mut actual = save.game_state(LegacyGameStateContext {
        crt_rand_state: expected.rng().crt_rand.state(),
        map_generation_lcg: expected.rng().map_generation.state(),
        zone_status_lcg: expected.rng().zone_status.state(),
        selected_nation: expected.turn().selected_nation,
    })?;

    // The importer preserves the saved viewport. The production map-entry operation then
    // selects the first idle civilian and commits the same centered origin as retail.
    let persisted_view_origin = save.world_state()?.view_origin();
    assert_eq!(actual.world().view_origin(), persisted_view_origin);
    actual.enter_strategic_map_view();
    assert_eq!(actual.world().view_origin(), expected.world().view_origin());

    assert_game_state_eq(&expected, &actual)
}
